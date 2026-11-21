#!/usr/bin/env python3
"""Assert xbits central-engine hook output (EngineAlert JSONL), polling instead of sleeping.

Purpose: replace the old CI pattern

    sleep 1
    grep -q '"rule_id":"xb-zeek-http-request"' /tmp/xbits-hook.out
    kill $(cat pid) || true

which passes even when the alert lacks src/dst/community_id, or when 10 alerts
were produced but only 1 survived, and which never fails if the socket never
came up. Here we:

  * poll the file until `--min-events` matching lines exist or `--timeout` (fail);
  * validate required fields are present and non-empty on every matching line;
  * optionally require a specific signature_id / reason / rule_id set;
  * print the matched lines for the CI log.

R8-6: JSON lines that fail to parse are **counted, not silently skipped**.
The summary always reports `bad-json-lines: N`; when the expected number of
matching events is not reached and N > 0, the failure names the corrupt lines
(dropped/truncated hook output) instead of only saying "0 matched". A bad line
that does not prevent the assertion is surfaced as a warning (stderr), not a
failure — the hook stream may legitimately contain partial writes while polling.

Exit codes: 0 ok, 1 assertion/timeout failure.
Self-test: `python3 xbits/test/assert_hook_output.py --self-test` (no engine needed).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Sequence, Set, Tuple


def is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def load(path: str) -> Tuple[List[dict], List[str]]:
    """Read the JSONL hook output.

    Returns (events, bad_lines): bad_lines holds a short preview of every
    non-empty line that is not valid JSON (R8-6: never dropped silently).
    """
    events: List[dict] = []
    bad_lines: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip().lstrip("\ufeff")  # tolerate a UTF-8 BOM on the first line
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    bad_lines.append(line[:160])
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
    except FileNotFoundError:
        return [], []
    return events, bad_lines


def select(
    events: List[dict],
    rule_ids: Optional[Set[str]],
    signature_id: Optional[int],
    reason: Optional[str],
) -> List[dict]:
    """Filter parsed events by rule_id set / signature_id / reason (pure)."""
    matched: List[dict] = []
    for ev in events:
        if rule_ids is not None and ev.get("rule_id") not in rule_ids:
            continue
        if signature_id is not None and ev.get("signature_id") != signature_id:
            continue
        if reason is not None and ev.get("reason") != reason:
            continue
        matched.append(ev)
    return matched


def evaluate(
    matched: Sequence[dict],
    bad_lines: Sequence[str],
    parsed: int,
    source: str,
    *,
    min_events: int,
    timeout: float,
    required: Sequence[str],
    allow_zero_signature_id: bool,
) -> Tuple[List[str], List[str]]:
    """Pure assertion core: returns (failures, warnings).

    R8-6: when too few matching events were found and some lines failed to
    parse, the failure names `bad-json-lines: N` plus a preview, so a truncated
    alert line reads as "corrupt line", not as "0 matched".
    """
    failures: List[str] = []
    warnings: List[str] = []

    if len(matched) < min_events:
        message = (
            "expected >=%d matching hook events, got %d after %.1fs "
            "(parsed %d lines from %s)" % (min_events, len(matched), timeout, parsed, source)
        )
        if bad_lines:
            message += (
                "; bad-json-lines: %d — %d line(s) failed JSON parse and were skipped, "
                "hook output may be truncated/dropped (first: %s)"
                % (len(bad_lines), len(bad_lines), bad_lines[0])
            )
        failures.append(message)
    elif bad_lines:
        warnings.append(
            "bad-json-lines: %d — corrupt line(s) skipped (assertion still satisfied; "
            "first: %s)" % (len(bad_lines), bad_lines[0])
        )

    for ev in matched:
        for key in required:
            if is_blank(ev.get(key)):
                failures.append("event missing %s: %s" % (key, json.dumps(ev, ensure_ascii=False)[:300]))
                break
        sid = ev.get("signature_id")
        if not isinstance(sid, int):
            failures.append("signature_id must be int: %r" % sid)
        elif sid == 0 and not allow_zero_signature_id:
            failures.append("signature_id is 0 (add --allow-zero-signature-id only for zeek events)")
    return failures, warnings


def run(args: argparse.Namespace) -> int:
    required = tuple(f.strip() for f in args.require_fields.split(",") if f.strip())
    rule_ids = set(args.rule_id) if args.rule_id else None

    deadline = time.time() + max(args.timeout, 0.0)
    matched: List[dict] = []
    bad_lines: List[str] = []
    parsed = 0
    while True:
        events, bad_lines = load(args.file)
        parsed = len(events)
        matched = select(events, rule_ids, args.signature_id, args.reason)
        if len(matched) >= args.min_events or time.time() >= deadline:
            break
        time.sleep(0.1)

    print(
        "hook output %s: parsed=%d matched=%d bad-json-lines=%d "
        "(filters rule_id=%s signature_id=%s reason=%s)"
        % (
            args.file,
            parsed,
            len(matched),
            len(bad_lines),
            sorted(rule_ids) if rule_ids else None,
            args.signature_id,
            args.reason,
        )
    )
    for ev in matched:
        print("  OK " + json.dumps(ev, ensure_ascii=False)[:400])

    failures, warnings = evaluate(
        matched,
        bad_lines,
        parsed,
        args.file,
        min_events=args.min_events,
        timeout=args.timeout,
        required=required,
        allow_zero_signature_id=args.allow_zero_signature_id,
    )
    for warning in warnings:
        print("WARN: %s" % warning, file=sys.stderr)

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("hook assertions passed (%d events, bad-json-lines=%d)" % (len(matched), len(bad_lines)))
    return 0


def _run_cli(file_path: str, min_events: int, timeout: float = 0.3) -> Tuple[int, str, str]:
    """Run this script in a child process (self-test only) and capture rc/stdout/stderr."""
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        "--file",
        file_path,
        "--min-events",
        str(min_events),
        "--timeout",
        str(timeout),
    ]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
        timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def self_test() -> int:
    """R8-6 negative case: one corrupt line + one valid line must FAIL by name."""
    checks: List[Tuple[str, bool]] = []
    good = json.dumps({"rule_id": "xb-demo", "reason": "demo", "src": "1.1.1.1",
                       "dst": "2.2.2.2", "proto": "TCP", "signature_id": 9103001})
    with tempfile.TemporaryDirectory(prefix="xbits-hook-out-") as tmp:
        clean = os.path.join(tmp, "clean.out")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write(good + "\n")
        rc, out, err = _run_cli(clean, min_events=1)
        checks.append(("全部行可解析 → PASS", rc == 0 and "bad-json-lines=0" in out and not err))

        mixed = os.path.join(tmp, "mixed.out")
        with open(mixed, "w", encoding="utf-8") as fh:
            fh.write(good + "\n")
            fh.write('{"rule_id":"xb-trunc", "reason":"demo", "src":"1.1.1.1"\n')  # 坏行
        rc, out, err = _run_cli(mixed, min_events=1)
        checks.append(
            ("坏行+正常行且匹配数够 → 仍 PASS，但报 bad-json-lines=1 + WARN",
             rc == 0 and "bad-json-lines=1" in out and "WARN: bad-json-lines: 1" in err)
        )

        rc, out, err = _run_cli(mixed, min_events=2)
        checks.append(
            ("坏行+正常行且因此未匹配 → FAIL 并点名 bad-json-lines",
             rc == 1 and "bad-json-lines: 1" in err and "expected >=2" in err)
        )

        only_bad = os.path.join(tmp, "only_bad.out")
        with open(only_bad, "w", encoding="utf-8") as fh:
            fh.write("{not json at all\n")
        rc, out, err = _run_cli(only_bad, min_events=1)
        checks.append(
            ("只有坏行 → FAIL 并点名为行损坏（不再只是 0 matched）",
             rc == 1 and "bad-json-lines: 1" in err and "failed JSON parse" in err)
        )

        rc, out, err = _run_cli(os.path.join(tmp, "missing.out"), min_events=1)
        checks.append(("文件缺失 → FAIL", rc == 1 and "expected >=1" in err))

    bad = sum(1 for _, ok in checks if not ok)
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=False)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--rule-id", action="append", default=None, help="required rule_id (repeatable)")
    parser.add_argument("--signature-id", type=int, default=None)
    parser.add_argument("--reason", default=None)
    parser.add_argument(
        "--require-fields",
        default="rule_id,reason,src,dst,proto",
        help="comma separated fields that must be present and non-empty",
    )
    parser.add_argument(
        "--allow-zero-signature-id",
        action="store_true",
        help="zeek-originated events may carry signature_id=0 (no Suricata SID)",
    )
    parser.add_argument("--self-test", action="store_true", help="本地验证坏行/匹配语义，不需要 engine")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.file:
        parser.error("--file is required unless --self-test")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
