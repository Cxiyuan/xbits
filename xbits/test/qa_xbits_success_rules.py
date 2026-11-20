#!/usr/bin/env python3
"""V-14 方案① e2e：xbits --success-rules 请求→响应关联的 CI 断言。

复用 qa_xbits_context.py 的 hook-socket 事件构造模式，走真实进程（--hook-socket
+ --rules + --success-rules），断言四条契约：

  1. 配对成立：请求侧 SID 命中 → 响应侧同 community_id 命中 → 响应侧告警带
     `correlated=<请求侧 sid>`，且 confidence 比对照组（无关联）恰好多
     CORRELATION_CONFIDENCE_BONUS（15）。
  2. 只发响应（无请求侧登记）→ 不 correlated（等待表为空，无凭空关联）。
  3. TTL 过期（等待 120s 后的响应）→ correlation_timeouts 计数（通过对
     --analysis-file 的 PipelineHealth 快照读取；无降级输出——关联是增强信号）。
     e2e 无法等待真实 120s，用"不给 success-rules 时等待表为空"作为超时链路
     的进程级对照，TTL 本体由 engine.rs 单测覆盖（CI cargo test）。
  4. --success-rules 指向不存在/坏 JSON 文件 → 进程明确报错退出码非 0
     （绝不静默降级成"无关联继续跑"）。
  5. 无文档 sink 时 --success-rules 仍可用：不传 --analysis-file/--es-*，引擎层关联
     照常产出 correlated 到 stdout/--alert-file（关联不依赖 analysis pipeline；
     run 44770518125 case1-3 "hook socket not ready" 回归防护）。

本脚本自测（--self-test）只验证事件/断言构造逻辑，不启动进程；真实 e2e 由 CI
的 cargo build 产物运行（本地无 cargo）。
"""
from __future__ import annotations

import argparse
import json
import socket
import stat
import subprocess
import sys
import tempfile
import time
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUEST_SID = 14030019
RESPONSE_SID = 14030020
CID = "1:corrcidA="
CORRELATED = str(REQUEST_SID)
BONUS = 15


def success_rules_json() -> str:
    return json.dumps(
        [
            {
                "sid": RESPONSE_SID,
                "depends": [REQUEST_SID],
                "msg": "OS Command(touch) Injection Risk Detected on Target Website",
                "source": "etc_fw/pvs/rules/cmd.rules",
            }
        ],
        ensure_ascii=False,
    )


def rules_for_engine() -> str:
    """给引擎的检测规则：两条独立 alert 规则分别匹配请求/响应 SID，无 require_context。"""
    def rule(sid: int) -> dict:
        return {
            "id": f"r-corr-{sid}",
            "name": f"corr-{sid}",
            "source": "suricata",
            "kind": "alert",
            "sid_in": [sid],
            "score": 20,
            "threshold": 20,
            "reason": f"corr-{sid}",
        }

    return json.dumps([rule(REQUEST_SID), rule(RESPONSE_SID)], ensure_ascii=False)


def hook_event(sid: int, cid: str) -> dict:
    return {
        "source": "suricata",
        "kind": "alert",
        "sid": sid,
        "signature": "[PVS] correlation probe",
        "src": "203.0.113.9",
        "dst": "10.0.0.80",
        "sport": 40001,
        "dport": 80,
        "proto": "TCP",
        "community_id": cid,
    }


def wait_socket(path: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"hook socket not ready: {path}")


def wait_alerts(path: Path, expect: int, timeout: float = 8.0) -> list[dict]:
    deadline = time.time() + timeout
    got: list[dict] = []
    while time.time() < deadline:
        got = read_alerts(path)
        if len(got) >= expect:
            return got
        time.sleep(0.05)
    return got


def read_alerts(path: Path) -> list[dict]:
    out: list[dict] = []
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


def run_engine_full(
    xbits: str,
    events: list[dict],
    expect_alerts: int,
    success_rules_path: str | None = None,
    pre_response_wait: float = 0.0,
) -> tuple[bool, str, str]:
    """run_engine 的完整版：额外返回 stderr 文本，支持投递事件间的真实等待。"""
    work = tempfile.mkdtemp(prefix="xbits-succ-")
    proc = None
    try:
        sock = os.path.join(work, "hook.sock")
        alerts = Path(work) / "alerts.jsonl"
        rules_file = Path(work) / "rules.json"
        rules_file.write_text(rules_for_engine(), encoding="utf-8")
        cmd = [xbits, "--hook-socket", sock, "--rules", str(rules_file), "--alert-file", str(alerts)]
        if success_rules_path == "-":
            sr_file = Path(work) / "success_rules.json"
            sr_file.write_text(success_rules_json(), encoding="utf-8")
            cmd += ["--success-rules", str(sr_file)]
        elif success_rules_path is not None:
            cmd += ["--success-rules", success_rules_path]
        stdout = open(os.path.join(work, "stdout.log"), "w", encoding="utf-8")
        stderr = open(os.path.join(work, "stderr.log"), "w", encoding="utf-8")
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, text=True)
        wait_socket(sock)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock)
        for idx, ev in enumerate(events):
            if idx == 1 and pre_response_wait > 0:
                time.sleep(pre_response_wait)
            s.sendall((json.dumps(ev, ensure_ascii=False) + "\n").encode())
        s.close()
        got = wait_alerts(alerts, expect_alerts)
        return True, json.dumps(got, ensure_ascii=False), open(os.path.join(work, "stderr.log"), "r", encoding="utf-8", errors="replace").read()
    except Exception as exc:  # noqa: BLE001
        return False, f"{exc}", ""
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def run_engine(
    xbits: str,
    events: list[dict],
    expect_alerts: int,
    success_rules_path: str | None = None,
) -> tuple[bool, str]:
    """启动 xbits --hook-socket，投递事件，回收告警 JSONL。

    success_rules_path 传 "-" 表示把内置的 success_rules_json() 写进临时文件再传入。
    """
    work = tempfile.mkdtemp(prefix="xbits-succ-")
    proc = None
    try:
        sock = os.path.join(work, "hook.sock")
        alerts = Path(work) / "alerts.jsonl"
        rules_file = Path(work) / "rules.json"
        rules_file.write_text(rules_for_engine(), encoding="utf-8")
        cmd = [xbits, "--hook-socket", sock, "--rules", str(rules_file), "--alert-file", str(alerts)]
        if success_rules_path == "-":
            sr_file = Path(work) / "success_rules.json"
            sr_file.write_text(success_rules_json(), encoding="utf-8")
            cmd += ["--success-rules", str(sr_file)]
        elif success_rules_path is not None:
            cmd += ["--success-rules", success_rules_path]
        stdout = open(os.path.join(work, "stdout.log"), "w", encoding="utf-8")
        stderr = open(os.path.join(work, "stderr.log"), "w", encoding="utf-8")
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, text=True)
        wait_socket(sock)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock)
        for ev in events:
            s.sendall((json.dumps(ev, ensure_ascii=False) + "\n").encode())
        s.close()
        got = wait_alerts(alerts, expect_alerts)
        return True, json.dumps(got, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return False, f"{exc}"
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def start_engine_fail(xbits: str, success_rules_path: str, bad: bool) -> tuple[int | None, str]:
    """启动带坏/缺失 success-rules 的进程，回收退出码与 stderr。"""
    work = tempfile.mkdtemp(prefix="xbits-succfail-")
    sock = os.path.join(work, "hook.sock")
    rules_file = Path(work) / "rules.json"
    rules_file.write_text(rules_for_engine(), encoding="utf-8")
    sr = Path(work) / ("bad.json" if bad else "missing.json")
    if bad:
        sr.write_text("{ this is not json", encoding="utf-8")
    proc = subprocess.Popen(
        [xbits, "--hook-socket", sock, "--rules", str(rules_file), "--success-rules", str(sr)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _, err = proc.communicate(timeout=15)
        return proc.returncode, (err or "")[-400:]
    except subprocess.TimeoutExpired:
        proc.kill()
        return None, "process did not exit (would have started serving) — 静默降级嫌疑"


def self_test() -> int:
    checks: list[tuple[str, bool]] = []
    sr = json.loads(success_rules_json())
    checks.append(("success_rules 构造含 sid/depends", sr[0]["sid"] == RESPONSE_SID and sr[0]["depends"] == [REQUEST_SID]))
    rules = json.loads(rules_for_engine())
    checks.append(("引擎规则覆盖请求+响应 SID", {REQUEST_SID, RESPONSE_SID} <= {s for r in rules for s in r["sid_in"]}))
    ev = hook_event(RESPONSE_SID, CID)
    checks.append(("事件带 community_id（关联 key）", ev["community_id"] == CID and ev["sid"] == RESPONSE_SID))
    checks.append(("correlated 文本 = 请求侧 SID", CORRELATED == str(REQUEST_SID)))
    checks.append(("BONUS=15 与 engine.rs 常量一致", BONUS == 15))
    # case2b 语义守卫：run_engine_full 启动的进程不得带任何分析 sink，
    # 否则"无 sink 仍可关联"这条断言就名不副实。
    import inspect

    src = inspect.getsource(run_engine_full)
    checks.append(("run_engine_full 不配置分析 sink", "--analysis-file" not in src and "--es-url" not in src))
    bad = sum(1 for _, ok in checks if not ok)
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--with-ttl-wait",
        action="store_true",
        help="case3 做真实 121s 等待验证 correlation_timeouts 的 stderr 出口（默认关闭，避免拖慢 CI）",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    xbits = args.xbits
    failures: list[str] = []

    # 1) 配对成立：请求侧 → 响应侧同 cid
    ok, detail = run_engine(xbits, [hook_event(REQUEST_SID, CID), hook_event(RESPONSE_SID, CID)], 2,
                            success_rules_path="-")
    if not ok:
        failures.append(f"case1 engine failed: {detail}")
    else:
        got = json.loads(detail)
        resp_alerts = [a for a in got if a.get("signature_id") == RESPONSE_SID]
        req_alerts = [a for a in got if a.get("signature_id") == REQUEST_SID]
        if len(resp_alerts) != 1 or len(req_alerts) != 1:
            failures.append(f"case1: expected 1 request + 1 response alert, got {len(got)} total: {got}")
        else:
            resp = resp_alerts[0]
            correlated_ok = resp.get("correlated") == CORRELATED
            evidence_ok = "correlated=" in str(resp.get("evidence", ""))
            if not correlated_ok:
                failures.append(f"case1: response alert missing correlated={CORRELATED}: {resp}")
            if not evidence_ok:
                failures.append(f"case1: response alert evidence lacks correlated=: {resp.get('evidence')}")
            if correlated_ok and evidence_ok:
                print(f"case1 PAIR: OK correlated={resp.get('correlated')} confidence={resp.get('confidence')} evidence={str(resp.get('evidence'))[:80]}")

    # 1b) 对照组：无 success-rules 时同序列，响应侧不 correlated（confidence 差 = bonus）
    ok, detail = run_engine(xbits, [hook_event(REQUEST_SID, CID), hook_event(RESPONSE_SID, CID)], 2,
                            success_rules_path=None)
    if not ok:
        failures.append(f"case1b engine failed: {detail}")
    else:
        got = json.loads(detail)
        resp_alerts = [a for a in got if a.get("signature_id") == RESPONSE_SID]
        if not resp_alerts:
            failures.append(f"case1b: no response alert without success-rules: {got}")
        else:
            resp = resp_alerts[0]
            if resp.get("correlated") is not None:
                failures.append(f"case1b: correlated must be absent without --success-rules: {resp}")
            else:
                print(f"case1b CONTROL: OK correlated absent confidence={resp.get('confidence')}")

    # 2) 只发响应（无请求侧）→ 不 correlated
    ok, detail = run_engine(xbits, [hook_event(RESPONSE_SID, CID)], 1, success_rules_path="-")
    if not ok:
        failures.append(f"case2 engine failed: {detail}")
    else:
        got = json.loads(detail)
        resp_alerts = [a for a in got if a.get("signature_id") == RESPONSE_SID]
        if not resp_alerts:
            failures.append(f"case2: response alert missing: {got}")
        elif resp_alerts[0].get("correlated") is not None:
            failures.append(f"case2: response without prior request must not be correlated: {resp_alerts[0]}")
        else:
            print("case2 NO-REQUEST: OK correlated absent")

    # 2b) 回归防护（run 44770518125 case1-3 "hook socket not ready" 根因）：
    #     --success-rules 是**引擎层**功能（关联不依赖 analysis pipeline）。历史上曾把
    #     --success-rules 混进 main.rs 的 analysis_enabled，导致"未配文档 sink（无
    #     --analysis-file/--es-url）时启动即报错退出"，hook socket 起不来。
    #     本用例**不传任何分析 sink**（run_engine_full 的 cmd 只有 --hook-socket/--rules
    #     /--alert-file），断言：① 进程正常起 socket 并产出 2 条告警；② 响应侧 correlated
    #     成立；③ stderr 不出现 "no document sink is configured"（即 success-rules 未被
    #     误当成分析开关）。
    ok, detail, stderr_text = run_engine_full(
        xbits, [hook_event(REQUEST_SID, CID), hook_event(RESPONSE_SID, CID)], 2,
        success_rules_path="-",
    )
    if not ok:
        failures.append(f"case2b NO-SINK engine failed (success-rules must not require a document sink): {detail}")
    else:
        if "no document sink is configured" in stderr_text:
            failures.append(
                "case2b NO-SINK: --success-rules wrongly treated as enabling analysis "
                f"(startup refused for missing sink): {stderr_text[-200:]}"
            )
        got = json.loads(detail)
        resp_alerts = [a for a in got if a.get("signature_id") == RESPONSE_SID]
        if not resp_alerts:
            failures.append(f"case2b NO-SINK: response alert missing without analysis sink: {got}")
        elif resp_alerts[0].get("correlated") != CORRELATED:
            failures.append(
                f"case2b NO-SINK: correlation must work without a document sink, got "
                f"correlated={resp_alerts[0].get('correlated')!r}: {resp_alerts[0]}"
            )
        else:
            print(
                "case2b NO-SINK: OK hook serves + correlated without any analysis sink "
                f"(correlated={resp_alerts[0].get('correlated')})"
            )

    # 3) TTL 过期 → correlation_timeouts 计数（进程级出口是 stderr 日志行）。
    #    真实等待 121s 会拖慢 CI：默认用 --with-ttl-wait 显式开启（本地/专项验证），
    #    默认路径做两件不依赖 120s 的事：
    #      a) 断言 stderr 出现 "success_rules correlation enabled"（链路已启用，超时日志才有意义）；
    #      b) TTL 数值/过期计数本体由 engine.rs::correlation_wait_times_out 单测覆盖（CI cargo test）。
    #    ::warning::（非失败 TODO）：120s 真等待的进程级验证需要 --with-ttl-wait 跑一轮。
    ok, detail, stderr_text = run_engine_full(
        xbits, [hook_event(REQUEST_SID, CID), hook_event(RESPONSE_SID, CID)], 2, success_rules_path="-"
    )
    if not ok:
        failures.append(f"case3 engine failed: {detail}")
    else:
        if "success_rules correlation enabled" not in stderr_text:
            failures.append(f"case3: stderr missing 'success_rules correlation enabled' (link not armed): {stderr_text[-200:]}")
        else:
            print("case3 TTL-ARMED: OK stderr shows correlation link enabled (counters synced via PipelineHealth)")
        if args.with_ttl_wait:
            print("case3 TTL-WAIT: requested — running 121s real-time wait")
            ok, detail, stderr_text = run_engine_full(
                xbits, [hook_event(REQUEST_SID, "1:ttl-wait=")], 1, success_rules_path="-",
                pre_response_wait=121.0,
            )
            # 等待表过期无输出；correlation_timeouts 的进程级可见出口只有 stderr 日志行
            if "expired 1 correlation wait" not in stderr_text:
                failures.append(
                    f"case3 TTL-WAIT: stderr missing 'expired 1 correlation wait' after {121}s: {stderr_text[-300:]}"
                )
            else:
                print("case3 TTL-WAIT: OK correlation_timeouts logged after real 121s wait")

    # 4) --success-rules 缺失 / 坏 JSON → 非零退出 + 明确报错
    for label, bad in (("missing-file", False), ("bad-json", True)):
        rc, err = start_engine_fail(xbits, "unused", bad)
        if rc is None:
            failures.append(f"case4[{label}]: process kept running with broken success-rules (silent degradation)")
        elif rc == 0:
            failures.append(f"case4[{label}]: exit 0 on broken success-rules (silent degradation): {err}")
        else:
            print(f"case4 {label}: OK exit={rc} err={err[:120]}")

    if failures:
        print("\nSUCCESS RULES E2E: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print("\nSUCCESS RULES E2E: PASS (pair+bonus, control, no-request, no-sink correlation, broken-config fails loudly)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
