#!/usr/bin/env python3
"""Central analysis plane correlation tests.

Covers four required behaviours without requiring Docker:
  * positive: Zeek context + Suricata alert -> high-confidence alert
  * missing-context: Suricata alert alone -> no high-confidence alert
  * benign-context: normal URI context -> alert suppressed
  * reverse-order: Suricata alert first, Zeek context later -> still correlated
  * app-id alert: XbitsAlert::alert reaches xbits through normalization
"""
from __future__ import annotations

import argparse
import json
import os
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


def run_case(xbits: Path, rules: Path, name: str, events: list[dict]) -> tuple[bool, str]:
    work = Path(tempfile.mkdtemp(prefix="xbits-context-"))
    engine = None
    try:
        sock = work / "hook.sock"
        alerts = work / "alerts.jsonl"
        stdout = open(work / "stdout.log", "w", encoding="utf-8")
        stderr = open(work / "stderr.log", "w", encoding="utf-8")
        engine = subprocess.Popen(
            [str(xbits), "--hook-socket", str(sock), "--rules", str(rules), "--alert-file", str(alerts)],
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
        wait_socket(sock)
        send_events(sock, events)
        time.sleep(0.25)
        got = read_alerts(alerts)
        return True, json.dumps(got, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return False, f"{name}: {exc}"
    finally:
        if engine is not None:
            engine.terminate()
            try:
                engine.wait(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--rules", default=str(ROOT / "xbits" / "rules" / "analysis.json"))
    args = parser.parse_args()
    xbits = Path(args.xbits)
    rules = Path(args.rules)

    zeek_http = {
        "source": "zeek", "kind": "event", "event": "http_request",
        "uid": "C-positive", "src": "203.0.113.9", "dst": "10.0.0.80",
        "sport": 40001, "dport": 80, "proto": "tcp",
        "host": "app.example.test", "method": "GET",
        "uri": "/search?q=1%27%20UNION%20SELECT",
        "status": 200,
    }
    suricata_alert = {
        "source": "suricata", "kind": "alert", "sid": 9103001,
        "signature": "[Web漏洞利用] SQL 注入",
        "src": "203.0.113.9", "dst": "10.0.0.80",
        "sport": 40001, "dport": 80, "proto": "TCP",
    }
    appid_alert = {
        "source": "zeek", "kind": "alert", "event": "XbitsAlert::alert",
        "alert_kind": "scanner", "alert_name": "gobuster", "severity": "high",
        "src": "10.1.0.11", "desc": "dir_brute",
    }

    cases = [
        ("positive-context", [zeek_http, suricata_alert], lambda got: len(got) == 1 and got[0].get("confidence", 0) >= 80),
        ("missing-context", [suricata_alert], lambda got: len(got) == 0),
        ("benign-context", [{**zeek_http, "uri": "/healthz"}, suricata_alert], lambda got: len(got) == 0),
        ("reverse-order", [suricata_alert, zeek_http], lambda got: len(got) == 1 and got[0].get("confidence", 0) >= 80),
        ("appid-alert", [appid_alert], lambda got: len(got) == 1 and got[0].get("alert_kind") == "scanner"),
    ]
    failed = []
    for name, events, assertion in cases:
        ok, detail = run_case(xbits, rules, name, events)
        if not ok:
            failed.append(detail)
            print(f"{name}: FAIL {detail}", file=sys.stderr)
            continue
        got = json.loads(detail)
        if not assertion(got):
            failed.append(f"{name}: unexpected output {got}")
            print(f"{name}: FAIL {got}", file=sys.stderr)
        else:
            print(f"{name}: OK {got}")
    if failed:
        print("XBITS CONTEXT: FAIL", file=sys.stderr)
        for f in failed:
            print(" -", f, file=sys.stderr)
        return 1
    print("XBITS CONTEXT: PASS (positive/negative/missing/reverse/app-id)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
