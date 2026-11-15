#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 Zeek 9.0.1 下跑 app-id/扫描工具 检出率/误报率测试。
前置：先运行 gen_pcaps.py 生成 pcaps/manifest.json。
用法：python3 app-id/tests/run_tests.py
退出码：全部正样本检出且有 0 负样本误报 => 0；否则 1。
注：失败信息同时以 GitHub Actions 注解(::error::)输出，便于在 Actions 页面/API 查看。
"""
import os, sys, json, tempfile, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SCRIPTS = os.path.join(REPO, "app-id", "scripts", "__load__.zeek")
PCAPS = os.path.join(HERE, "pcaps")
MANIFEST = os.path.join(HERE, "manifest.json")


def ann(level, title, msg):
    msg = " ".join(str(msg).split())
    print(f"::{level} title={title}::{msg}")


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
    if not os.path.exists(MANIFEST):
        ann("error", "no-manifest", "manifest.json 不存在，请先运行 gen_pcaps.py")
        return 2
    if shutil.which("zeek") is None:
        ann("error", "no-zeek", "zeek 不在 PATH")
        return 2

    cases = json.load(open(MANIFEST, encoding="utf-8"))
    det = tot = fp = neg = 0
    fails = []
    passed = []
    missed = []
    broken = False

    for c in cases:
        work = tempfile.mkdtemp(prefix="zeek_")
        pcap = os.path.join(PCAPS, c["pcap"])
        try:
            r = subprocess.run(["zeek", "-C", "-r", pcap, SCRIPTS],
                               cwd=work, capture_output=True, text=True)
            if r.returncode != 0:
                detail = (r.stderr or r.stdout or "").strip()
                fails.append(f"[ZEEK-ERR] {c['pcap']} rc={r.returncode}\n{detail[-1600:]}")
                ann("error", f"ZEEK-ERR {c['pcap']}", detail[-1600:] or "zeek non-zero exit")
                broken = True
                break
            rows = parse_tsv(os.path.join(work, "scan_report.log"))
            sigrows = parse_tsv(os.path.join(work, "signatures.log"))
            sig_ids = sorted({x.get("sig_id", "") for x in sigrows if x.get("sig_id")})
            found = [x for x in rows if x.get("src") == c["client"]]
            if c["expect"] == "negative":
                neg += 1
                if found:
                    fp += 1
                    fails.append(f"[FP] {c['pcap']} 被判为 {found}")
                    ann("error", f"FP {c['pcap']}", f"negative 被判为 {found}")
            else:
                tot += 1
                ok = False
                if found:
                    if c["expect"] == "unknown":
                        ok = True
                    else:
                        ok = any(x.get("tool") == c["tool"] for x in found)
                if ok:
                    det += 1
                    passed.append(c["pcap"])
                else:
                    missed.append(c["pcap"])
                    fails.append(f"[MISS] {c['pcap']} 期望 {c['expect']}/{c.get('tool')}，实得 {found} sigs={sig_ids}")
                    ann("error", f"MISS {c['pcap']}",
                        f"期望 {c['expect']}/{c.get('tool')}，实得 {found} sigs={sig_ids}")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    print("=" * 64)
    print(f"正样本检出率: {det}/{tot} = {(det/tot*100 if tot else 0):.1f}%")
    print(f"负样本误报率: {fp}/{neg} = {(fp/neg*100 if neg else 0):.1f}%")
    print("=" * 64)
    for f in fails:
        print(f)
    ann("notice", "scan-summary", f"DET={det}/{tot} FPR={fp}/{neg} broken={broken}")
    ann("notice", "pass-list", "PASS=[" + ", ".join(passed) + "]")
    if missed:
        ann("notice", "miss-list", "MISS=[" + ", ".join(missed) + "]")

    if (not broken) and det == tot and fp == 0 and tot > 0:
        print("RESULT: PASS (检出全中，零误报)")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
