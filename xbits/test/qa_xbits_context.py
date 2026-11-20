#!/usr/bin/env python3
"""Central analysis plane correlation tests.

Covers the required behaviours without requiring Docker:
  * positive: Zeek context + Suricata alert -> high-confidence alert
  * missing-context: Suricata alert alone -> NO real correlation alert
  * benign-context: normal URI context -> NO real correlation alert
  * reverse-order: Suricata alert first, Zeek context later -> still correlated
  * app-id alert: XbitsAlert::alert reaches xbits through normalization

两点修复（qa/QA_REPORT.md V-18 / TS-08）：

1. 负例旁必须有"必须产出"的对照：missing/benign 两个负例都会同时投递一条
   一定命中的 app-id 告警（xb-zeek-appid-scanner）。断言是"输出恰好等于这条对照
   告警，且没有真实的 SQLi 关联告警"，而不是"len(got) == 0" —— 后者与"引擎崩了/
   规则没加载"同形，无法区分。
2. 固定 `time.sleep(0.25)` 换成"轮询到期望条数或超时"：不再靠墙钟猜异步写盘。
   （require_context 规则等不到上下文时会在 60s TTL 后产出 degraded=context-missing
   的 fail-closed 告警；本测试窗口远小于 60s，因此这里断言的是"没有真实关联告警"，
   若出现任何输出都只能是那条对照告警。）
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

CONTROL_RULE = "xb-zeek-appid-scanner"
REAL_RULE = "xb-suricata-web-sqli"


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


def wait_alerts(path: Path, expect_count: int, timeout: float = 8.0) -> list[dict]:
    """轮询到条数达到期望（用于"必须产出"的对照），超时返回当前结果由调用方判定。"""
    deadline = time.time() + timeout
    got: list[dict] = []
    while time.time() < deadline:
        got = read_alerts(path)
        if len(got) >= expect_count:
            return got
        time.sleep(0.05)
    return got


def run_case(xbits: Path, rules: Path, name: str, events: list[dict], expect_count: int) -> tuple[bool, str]:
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
        got = wait_alerts(alerts, expect_count)
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


def rule_ids(got: list[dict]) -> list[str]:
    return [row.get("rule_id") for row in got]


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
    # 对照告警：不依赖任何上下文，必定产出一条输出（证明引擎活着、规则已加载）
    appid_alert = {
        "source": "zeek", "kind": "alert", "event": "XbitsAlert::alert",
        "alert_kind": "scanner", "alert_name": "gobuster", "severity": "high",
        "src": "10.1.0.11", "desc": "dir_brute",
    }

    def no_real_alert(got: list[dict]) -> bool:
        return REAL_RULE not in rule_ids(got)

    def only_control(got: list[dict]) -> bool:
        return len(got) == 1 and got[0].get("rule_id") == CONTROL_RULE

    cases = [
        # name, events, expect_count (用于轮询), assertion
        ("positive-context", [zeek_http, suricata_alert], 1,
         lambda got: len(got) == 1 and got[0].get("rule_id") == REAL_RULE and got[0].get("confidence", 0) >= 80),
        ("missing-context", [suricata_alert, appid_alert], 1,
         lambda got: only_control(got) and no_real_alert(got)),
        ("benign-context", [{**zeek_http, "uri": "/healthz"}, appid_alert, suricata_alert], 1,
         lambda got: only_control(got) and no_real_alert(got)),
        ("reverse-order", [suricata_alert, zeek_http], 1,
         lambda got: len(got) == 1 and got[0].get("rule_id") == REAL_RULE and got[0].get("confidence", 0) >= 80),
        ("appid-alert", [appid_alert], 1,
         lambda got: len(got) == 1 and got[0].get("rule_id") == CONTROL_RULE and got[0].get("confidence", 0) >= 30),
    ]
    failed = []
    for name, events, expect_count, assertion in cases:
        ok, detail = run_case(xbits, rules, name, events, expect_count)
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
    print("XBITS CONTEXT: PASS (positive/missing/benign/reverse/app-id; negatives carry a must-fire control)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
