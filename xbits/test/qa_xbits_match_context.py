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
    "buffer": "http.uri",
    "buffer_len": 19,
    "buffer_b64": "L2FwaS9sb2dpbg==",  # /api/login
}

ALERT_OTHER_TUPLE = dict(
    BASE_ALERT,
    src_port=40002,
    flow_id=111111111,
    uid="C111111111",
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
    "buffer": "http.header",
    "buffer_len": 13,
    "buffer_b64": "dXNlci1hZ2VudA==",  # user-agent
}

ALERT_NO_META = dict(
    BASE_ALERT,
    src_port=40004,
    flow_id=222222222,
    uid="C222222222",
    alert={"signature_id": 9999999, "signature": "no metadata rule"},
)


def run_case(xbits, validator, rules, match_buffers, name, match_contexts, alerts,
             want_suppressed, want_emitted):
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
             "--analysis-file", str(out)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        wait_socket(work / "xbits.sock")
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
    detail = (f"{name}: suppressed={len(suppressed)} want={want_suppressed} "
              f"emitted={len(emitted)} want={want_emitted}; rows={rows}")
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
    ]

    failures = []
    for name, ctxs, alerts, want_sup, want_emit in cases:
        ok, detail = run_case(
            Path(args.xbits), Path(args.validator), Path(args.rules),
            Path(args.match_buffers), name, ctxs, alerts, want_sup, want_emit,
        )
        print(("OK " if ok else "FAIL ") + detail)
        if not ok:
            failures.append(detail)

    print(f"\n{len(cases) - len(failures)}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
