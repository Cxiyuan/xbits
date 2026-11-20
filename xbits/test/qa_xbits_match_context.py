#!/usr/bin/env python3
"""xbits match_context + suppression tests (root-cause, no fallback).

Covers:
  * match_context buffer + FP validator -> key whitelisted -> identical later alert suppressed
  * missing match_context for a match_context-only SID -> no key built, never suppressed
  * different tuple -> different key -> not suppressed
  * lua/http.header/file.data style SIDs only accept exported match_context (no EVE approximation)
  * match_context event itself does not produce an EngineAlert
  * SID without match_buffers metadata -> no suppression key built
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def wait_socket(path: Path, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"socket not created: {path}")


def send_events(sock_path: Path, events: list[dict]) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(sock_path))
    for event in events:
        s.sendall((json.dumps(event, ensure_ascii=False) + "\n").encode())
    s.close()


def read_alerts(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if raw:
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
    return out


BASE_ALERT = {
    "timestamp": "2026-11-08T00:00:00.000000+0000",
    "source": "suricata",
    "kind": "alert",
    "event_type": "alert",
    "community_id": "1:testCID=",
    "src_ip": "203.0.113.9",
    "src_port": 40001,
    "dest_ip": "10.0.0.80",
    "dest_port": 80,
    "proto": "TCP",
    "flow_id": 123456789,
    "uid": "C123456789",
    "alert": {"signature_id": 9103001, "signature": "[Web漏洞利用] SQL 注入"},
}

MATCH_CTX_URI = {
    "timestamp": "2026-11-08T00:00:00.100000+0000",
    "source": "suricata",
    "kind": "match_context",
    "sid": 9103001,
    "src": "203.0.113.9",
    "sport": 40001,
    "dst": "10.0.0.80",
    "dport": 80,
    "proto": "TCP",
    "tx_id": 1,
    # Suricata 核心补丁导出的是内部 buffer 名（http_uri），xbits 侧归一为 http.uri
    "buffer": "http_uri",
    "buffer_len": 19,
    "buffer_b64": "L2FwaS9sb2dpbg==",  # /api/login
}

ALERT_OTHER_TUPLE = dict(
    BASE_ALERT,
    src_port=40002,
    flow_id=111111111,
    uid="C111111111",
)

# SID 9103003: payload 规则（由 content/pcre 默认匹配 payload），
# 精确 payload 直接来自 EVE payload 字段——不需要 context 导出即可抑制。
PAYLOAD_BYTES = "R0VUIC9pbmRleC5waHA/Y21kPWNhdCUyMGV0Yy9wYXNzd2QgSFRUUC8xLjE="
ALERT_PAYLOAD = dict(
    BASE_ALERT,
    src_port=40009,
    flow_id=333333333,
    uid="C333333333",
    payload=PAYLOAD_BYTES,
    alert={"signature_id": 9103003, "signature": "[Web漏洞利用] payload check"},
)

ALERT_HEADER = dict(
    BASE_ALERT,
    src_port=40003,
    flow_id=987654321,
    uid="C987654321",
    alert={"signature_id": 9103002, "signature": "[Web漏洞利用] Header check"},
)

MATCH_CTX_HEADER = {
    "timestamp": "2026-11-08T00:00:00.200000+0000",
    "source": "suricata",
    "kind": "match_context",
    "sid": 9103002,
    "src": "203.0.113.9",
    "sport": 40003,
    "dst": "10.0.0.80",
    "dport": 80,
    "proto": "TCP",
    "tx_id": 2,
    # Suricata 导出 http_header，xbits 归一为 http.header
    "buffer": "http_header",
    "buffer_len": 13,
    "buffer_b64": "dXNlci1hZ2VudA==",  # user-agent
}

# SID 9103004 declares [file.data] only
ALERT_FILEDATA = dict(
    BASE_ALERT,
    src_port=40005,
    flow_id=333333333,
    uid="C333333333",
    alert={"signature_id": 9103004, "signature": "[WebShell] file.data check"},
)

MATCH_CTX_FILEDATA = {
    "timestamp": "2026-11-08T00:00:00.300000+0000",
    "source": "suricata",
    "kind": "match_context",
    "sid": 9103004,
    "src": "203.0.113.9",
    "sport": 40005,
    "dst": "10.0.0.80",
    "dport": 80,
    "proto": "TCP",
    "tx_id": 3,
    # Suricata 导出 file_data，xbits 归一为 file.data
    "buffer": "file_data",
    "buffer_len": 12,
    "buffer_b64": "PD9waHAgZXZhbA==",  # <?php eval
}

# SID 9103005 declares [http.uri.raw] only
ALERT_URIRAW = dict(
    BASE_ALERT,
    src_port=40006,
    flow_id=444444444,
    uid="C444444444",
    alert={"signature_id": 9103005, "signature": "[Web漏洞利用] raw uri check"},
)

MATCH_CTX_URIRAW = {
    "timestamp": "2026-11-08T00:00:00.400000+0000",
    "source": "suricata",
    "kind": "match_context",
    "sid": 9103005,
    "src": "203.0.113.9",
    "sport": 40006,
    "dst": "10.0.0.80",
    "dport": 80,
    "proto": "TCP",
    "tx_id": 4,
    # Suricata 导出 http_raw_uri，xbits 归一为 http.uri.raw
    "buffer": "http_raw_uri",
    "buffer_len": 23,
    "buffer_b64": "L2FwaS8uLi8uLi9ldmMvcGFzc3dk",  # /api/../../etc/passwd
}

ALERT_NO_META = dict(
    BASE_ALERT,
    src_port=40004,
    flow_id=222222222,
    uid="C222222222",
    alert={"signature_id": 9999999, "signature": "no metadata rule"},
)

# SID 9103006: validator 返回 false_positive 但 confidence=40 < fp_confidence(90)
ALERT_LOW_FP = dict(
    BASE_ALERT,
    src_port=40007,
    flow_id=555555555,
    uid="C555555555",
    alert={"signature_id": 9103006, "signature": "[Web漏洞利用] low-confidence fp"},
)

MATCH_CTX_LOW_FP = {
    "timestamp": "2026-11-08T00:00:00.500000+0000",
    "source": "suricata",
    "kind": "match_context",
    "sid": 9103006,
    "src": "203.0.113.9",
    "sport": 40007,
    "dst": "10.0.0.80",
    "dport": 80,
    "proto": "TCP",
    "tx_id": 5,
    "buffer": "http_uri",
    "buffer_len": 19,
    "buffer_b64": "L2FwaS9sb2dpbg==",
}


def run_case(xbits, validator, rules, match_buffers, name, match_contexts, alerts,
             want_suppressed, want_emitted, defer_contexts=0.0,
             expect_suppression_evidence=None):
    work = Path(tempfile.mkdtemp(prefix="xbits-match-context-"))
    out = work / "out.jsonl"
    engine = None
    try:
        engine = subprocess.Popen(
            [str(xbits),
             "--hook-socket", str(work / "xbits.sock"),
             "--rules", str(rules),
             "--match-buffers", str(match_buffers),
             "--validator-cmd", str(validator),
             "--suppression-ttl-sec", "300",
             "--pending-context-ms", "800",
             "--analysis-file", str(out)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        wait_socket(work / "xbits.sock")
        if defer_contexts > 0:
            # 顺序问题回归：先发告警，再发 match_context（模拟 socket 乱序）。
            send_events(work / "xbits.sock", alerts)
            time.sleep(defer_contexts)
            send_events(work / "xbits.sock", match_contexts)
        else:
            send_events(work / "xbits.sock", match_contexts + alerts)
        time.sleep(1.2)
        engine.terminate()
        engine.wait(timeout=5)
    except BaseException:
        if engine is not None:
            engine.kill()
        raise

    rows = read_alerts(out)
    suppressed = [r for r in rows if r.get("xbits", {}).get("verdict") == "suppressed"]
    emitted = [r for r in rows if r.get("xbits", {}).get("verdict") != "suppressed"]
    ok = (len(suppressed) == want_suppressed and len(emitted) == want_emitted)
    if ok and expect_suppression_evidence is not None and suppressed:
        # V-12：raw 规则的抑制 key 必须来自 context 导出的精确值（evidence key= 里有
        # http.uri.raw=<导出值>），而不是 EVE 归一化兜底。
        want = f"http.uri.raw={expect_suppression_evidence}"
        key_lines = [
            e for r in suppressed for e in r.get("xbits", {}).get("evidence", [])
            if e.startswith("key=")
        ]
        if not any(want in k for k in key_lines):
            ok = False
            detail_extra = f"; MISSING {want!r} in keys {key_lines}"
        else:
            detail_extra = "; raw key verified"
    else:
        detail_extra = ""
    detail = (f"{name}: suppressed={len(suppressed)} want={want_suppressed} "
              f"emitted={len(emitted)} want={want_emitted}{detail_extra}; rows={rows}")
    try:
        shutil.rmtree(work)
    except OSError:
        pass
    return ok, detail


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xbits", required=True)
    parser.add_argument("--validator", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--match-buffers", required=True)
    parser.add_argument("--production-meta", default=None,
                        help="生产 match_buffers.json（规则检测/xbits/规则库元数据/）；"
                             "提供时追加真实 SID 的 V-12 回归用例")
    args = parser.parse_args()

    cases = [
        (
            "uri-context-fp-then-suppressed",
            [MATCH_CTX_URI],
            [dict(BASE_ALERT), dict(BASE_ALERT)],
            1,
            1,
        ),
        (
            "uri-context-missing-for-second-tuple",
            [MATCH_CTX_URI],
            [dict(BASE_ALERT), dict(ALERT_OTHER_TUPLE)],
            0,
            2,
        ),
        (
            "header-context-fp-then-suppressed",
            [MATCH_CTX_HEADER],
            [ALERT_HEADER, ALERT_HEADER],
            1,
            1,
        ),
        (
            "header-alert-without-context-not-suppressed",
            [],
            [ALERT_HEADER, ALERT_HEADER],
            0,
            2,
        ),
        (
            "filedata-context-fp-then-suppressed",
            [MATCH_CTX_FILEDATA],
            [ALERT_FILEDATA, ALERT_FILEDATA],
            1,
            1,
        ),
        (
            "filedata-alert-without-context-not-suppressed",
            [],
            [ALERT_FILEDATA, ALERT_FILEDATA],
            0,
            2,
        ),
        (
            "uriraw-context-fp-then-suppressed",
            [MATCH_CTX_URIRAW],
            [ALERT_URIRAW, ALERT_URIRAW],
            1,
            1,
        ),
        (
            "uriraw-alert-without-context-not-suppressed",
            [],
            [ALERT_URIRAW, ALERT_URIRAW],
            0,
            2,
        ),
        (
            "low-confidence-fp-not-whitelisted",
            [MATCH_CTX_LOW_FP],
            [ALERT_LOW_FP, ALERT_LOW_FP],
            0,
            2,
        ),
        (
            "no-metadata-sid-not-suppressed",
            [],
            [ALERT_NO_META, ALERT_NO_META],
            0,
            2,
        ),
        (
            "match-context-event-no-alert",
            [MATCH_CTX_URI],
            [],
            0,
            0,
        ),
        (
            "reverse-order-alert-before-context",
            [MATCH_CTX_HEADER],
            [ALERT_HEADER, ALERT_HEADER],
            1,
            1,
            0.25,  # 先发告警，0.25s 后补 match_context（context-only buffer 才走 defer）
        ),
        (
            # 分类修复回归：payload 规则用 EVE payload 精确值即可抑制，
            # 不再被误标为 app-tx lua 而不可抑制。
            "payload-rule-fp-then-suppressed",
            [],
            [dict(ALERT_PAYLOAD), dict(ALERT_PAYLOAD)],
            1,
            1,
        ),
    ]

    failures = []
    for case in cases:
        name, ctxs, alerts, want_sup, want_emit = case[:5]
        defer = case[5] if len(case) > 5 else 0.0
        evidence = case[6] if len(case) > 6 else None
        ok, detail = run_case(
            Path(args.xbits), Path(args.validator), Path(args.rules),
            Path(args.match_buffers), name, ctxs, alerts, want_sup, want_emit,
            defer_contexts=defer,
            expect_suppression_evidence=evidence,
        )
        print(("OK " if ok else "FAIL ") + detail)
        if not ok:
            failures.append(detail)

    # ---- V-12：生产元数据回归（真实 SID）----
    # 用 规则检测/xbits/规则库元数据/match_buffers.json（19k 条真实规则元数据）跑
    # 至少 3 个真实 SID（含 http.uri.raw 规则），断言 primary=raw 时抑制 key 里的
    # http.uri.raw=<值> 来自 match_context 导出，而不是 EVE 归一化兜底。
    # xbits 规则文件用 testdata 的 sid_in 语义不通（真实 SID 不在 testdata 规则里），
    # 因此这里动态生成一个只含这 3 条 SID 的规则文件（与生产 gen_xbits_analysis 同构）。
    prod_meta = Path(args.production_meta) if args.production_meta else None
    if prod_meta is not None and prod_meta.exists():
        PROD_SIDS = [9103001, 9104001, 11020687]  # raw / raw / uri+raw 混合
        prod_rules = [
            {
                "id": f"xb-prod-{sid}",
                "name": f"prod sid {sid}",
                "source": "suricata",
                "kind": "alert",
                "group_by": "src",
                "score": 20,
                "threshold": 20,
                "reason": f"prod-{sid}",
                "sid_in": [sid],
            }
            for sid in PROD_SIDS
        ]
        work = Path(tempfile.mkdtemp(prefix="xbits-prod-meta-"))
        try:
            rules_file = work / "prod_rules.json"
            rules_file.write_text(json.dumps(prod_rules, ensure_ascii=False), encoding="utf-8")

            def real_alert(sid: int, sport: int) -> dict:
                return dict(
                    BASE_ALERT,
                    src_port=sport,
                    flow_id=sport,
                    uid=f"CPROD{sid}",
                    alert={"signature_id": sid, "signature": f"[Web漏洞利用] prod {sid}"},
                )

            def real_ctx(sid: int, sport: int, raw: bool) -> dict:
                # Suricata 导出内部名：http_raw_uri（raw）/ http_uri（归一化）
                return {
                    "timestamp": "2026-11-08T00:00:01.000000+0000",
                    "source": "suricata",
                    "kind": "match_context",
                    "sid": sid,
                    "src": "203.0.113.9",
                    "sport": sport,
                    "dst": "10.0.0.80",
                    "dport": 80,
                    "proto": "TCP",
                    "tx_id": 1,
                    "buffer": "http_raw_uri" if raw else "http_uri",
                    "buffer_len": 23,
                    # /api/../../etc/passwd —— raw URI 的精确导出值
                    "buffer_b64": "L2FwaS8uLi8uLi9ldmMvcGFzc3dk",
                }

            prod_cases = [
                (
                    "prod-9103001-raw-uri-fp-then-suppressed",
                    [real_ctx(9103001, 40001, raw=True)],
                    [real_alert(9103001, 40001), real_alert(9103001, 40001)],
                    1,
                    1,
                    0.0,
                    "L2FwaS8uLi8uLi9ldmMvcGFzc3dk",  # key 里必须是导出的 raw 值
                ),
                (
                    "prod-9104001-raw-uri-fp-then-suppressed",
                    [real_ctx(9104001, 40002, raw=True)],
                    [real_alert(9104001, 40002), real_alert(9104001, 40002)],
                    1,
                    1,
                    0.0,
                    "L2FwaS8uLi8uLi9ldmMvcGFzc3dk",
                ),
                (
                    "prod-11020687-uri-plus-raw-needs-both",
                    [real_ctx(11020687, 40003, raw=True)],
                    [real_alert(11020687, 40003), real_alert(11020687, 40003)],
                    # 元数据 buffers=[http.uri, http.uri.raw]：缺 http.uri（归一化）
                    # 导出时必须 fail-closed 不建 key（无近似兜底），两次都 emitted。
                    0,
                    2,
                    0.0,
                    None,
                ),
                (
                    "prod-11020687-both-contexts-suppressed",
                    [
                        real_ctx(11020687, 40004, raw=True),
                        {**real_ctx(11020687, 40004, raw=False),
                         "buffer": "http_uri",
                         "buffer_b64": "L2FwaS9sb2dpbg=="},  # /api/login
                    ],
                    [real_alert(11020687, 40004), real_alert(11020687, 40004)],
                    1,
                    1,
                    0.0,
                    None,
                ),
            ]
            for case in prod_cases:
                name, ctxs, alerts, want_sup, want_emit, defer, evidence = case
                ok, detail = run_case(
                    Path(args.xbits), Path(args.validator), Path(rules_file),
                    prod_meta, name, ctxs, alerts, want_sup, want_emit,
                    defer_contexts=defer,
                    expect_suppression_evidence=evidence,
                )
                print(("OK " if ok else "FAIL ") + detail)
                if not ok:
                    failures.append(detail)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    print(f"\n{len(cases) - len(failures)}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
