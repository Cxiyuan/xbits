#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 xbits HTTP 扩展解析（xbits-ext.zeek）：完整头/Cookie/Auth/Query/表单/JSON/XML/Body 片段。
用法：python3 app-id/tests/run_http_fields.py
前置：已运行 gen_pcaps.py（生成 pcaps/http_fields.pcap）。
"""
import os, sys, tempfile, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PCAP = os.path.join(HERE, "pcaps", "http_fields.pcap")
CLIENT = "10.8.0.1"


def ann(level, title, msg):
    print(f"::{level} title={title}::{' '.join(str(msg).split())}")


def parse_tsv(path):
    rows, fields = [], None
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if fields:
                rows.append(dict(zip(fields, line.split("\t"))))
    return rows


def main():
    if not os.path.exists(PCAP):
        ann("error", "no-pcap", "缺少 pcaps/http_fields.pcap，请先运行 gen_pcaps.py")
        return 2
    if shutil.which("zeek") is None:
        ann("error", "no-zeek", "zeek 不在 PATH")
        return 2

    work = tempfile.mkdtemp(prefix="zeek_httpf_")
    try:
        r = subprocess.run(["zeek", "-C", "-r", PCAP], cwd=work, capture_output=True, text=True)
        if r.returncode != 0:
            ann("error", "ZEEK-ERR", (r.stderr or r.stdout or "")[-1500:])
            print("RESULT: FAIL (zeek error)")
            return 1
        rows = [x for x in parse_tsv(os.path.join(work, "http.log"))
                if x.get("id.orig_h") == CLIENT]
        if not rows:
            ann("error", "NO-HTTP-LOG", "http.log 无 client 记录")
            print("RESULT: FAIL")
            return 1

        def row_with(sub):
            for x in rows:
                if sub in (x.get("uri", "") or ""):
                    return x
            return None

        checks = []
        login = row_with("/api/login")
        if login is None:
            checks.append(("login-row", False, "缺 /api/login 记录"))
        else:
            checks += [
                ("request_headers 含 COOKIE/AUTHORIZATION/X-FORWARDED-FOR",
                 all(k in (login.get("request_headers", "") or "") for k in ("COOKIE", "AUTHORIZATION", "X-FORWARDED-FOR")),
                 login.get("request_headers", "")),
                ("cookie 值", (login.get("cookie", "") or "") == "session=abc; uid=42", login.get("cookie", "")),
                ("authorization_scheme", (login.get("authorization_scheme", "") or "").lower() == "basic", login.get("authorization_scheme", "")),
                ("authorization_credentials 解码", "admin:s3cr3t" in (login.get("authorization_credentials", "") or ""), login.get("authorization_credentials", "")),
                ("query_params 含 user=admin", "user" in (login.get("query_params", "") or "") and "admin" in (login.get("query_params", "") or ""), login.get("query_params", "")),
                ("form_fields 含 username/password", "username" in (login.get("form_fields", "") or "") and "password" in (login.get("form_fields", "") or ""), login.get("form_fields", "")),
                ("req_body_excerpt", "username=admin" in (login.get("req_body_excerpt", "") or ""), login.get("req_body_excerpt", "")),
                ("resp_content_type json", "application/json" in (login.get("resp_content_type", "") or ""), login.get("resp_content_type", "")),
                ("resp_body_excerpt json", '"ok":true' in (login.get("resp_body_excerpt", "") or ""), login.get("resp_body_excerpt", "")),
                ("set_cookie 多值", "sid=xyz" in (login.get("set_cookie", "") or "") and "theme=dark" in (login.get("set_cookie", "") or ""), login.get("set_cookie", "")),
            ]

        j = row_with("/api/put")
        checks.append(("json_body", j is not None and '"a":1' in (j.get("json_body", "") or ""), (j or {}).get("json_body", "")))
        x = row_with("/xml")
        checks.append(("xml_body", x is not None and "<req>" in (x.get("xml_body", "") or ""), (x or {}).get("xml_body", "")))
        m = row_with("/upload")
        checks.append(("multipart form_fields 含 file", m is not None and "file" in (m.get("form_fields", "") or ""), (m or {}).get("form_fields", "")))
        checks.append(("multipart req_body_excerpt 含 HELLO", m is not None and "HELLO" in (m.get("req_body_excerpt", "") or ""), (m or {}).get("req_body_excerpt", "")))
        checks.append(("multipart_parts 含 file/HELLO", m is not None and "file" in (m.get("multipart_parts", "") or "") and "HELLO" in (m.get("multipart_parts", "") or ""), (m or {}).get("multipart_parts", "")))

        okall = True
        for name, ok, val in checks:
            print(("PASS " if ok else "FAIL ") + name + "  => " + str(val)[:200])
            if not ok:
                okall = False
                ann("error", "HTTP-FIELD", f"{name} 失败: {str(val)[:200]}")
        print("RESULT:", "PASS" if okall else "FAIL")
        ann("notice", "http-fields-summary", f"checks={len(checks)} ok={sum(1 for _,o,_ in checks if o)}")
        return 0 if okall else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
