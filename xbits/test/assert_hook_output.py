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

Exit codes: 0 ok, 1 assertion/timeout failure.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List


def is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def load(path: str) -> List[dict]:
    events: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
    except FileNotFoundError:
        return []
    return events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
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
    args = parser.parse_args()

    required = tuple(f.strip() for f in args.require_fields.split(",") if f.strip())
    rule_ids = set(args.rule_id) if args.rule_id else None

    deadline = time.time() + max(args.timeout, 0.0)
    matched: List[dict] = []
    total = 0
    while True:
        events = load(args.file)
        total = len(events)
        matched = []
        for ev in events:
            if rule_ids is not None and ev.get("rule_id") not in rule_ids:
                continue
            if args.signature_id is not None and ev.get("signature_id") != args.signature_id:
                continue
            if args.reason is not None and ev.get("reason") != args.reason:
                continue
            matched.append(ev)
        if len(matched) >= args.min_events or time.time() >= deadline:
            break
        time.sleep(0.1)

    print(
        "hook output %s: parsed=%d matched=%d (filters rule_id=%s signature_id=%s reason=%s)"
        % (args.file, total, len(matched), sorted(rule_ids) if rule_ids else None, args.signature_id, args.reason)
    )
    for ev in matched:
        print("  OK " + json.dumps(ev, ensure_ascii=False)[:400])

    failures: List[str] = []
    if len(matched) < args.min_events:
        failures.append(
            "expected >=%d matching hook events, got %d after %.1fs "
            "(parsed %d lines from %s)" % (args.min_events, len(matched), args.timeout, total, args.file)
        )
    for ev in matched:
        for key in required:
            if is_blank(ev.get(key)):
                failures.append("event missing %s: %s" % (key, json.dumps(ev, ensure_ascii=False)[:300]))
                break
        sid = ev.get("signature_id")
        if not isinstance(sid, int):
            failures.append("signature_id must be int: %r" % sid)
        elif sid == 0 and not args.allow_zero_signature_id:
            failures.append("signature_id is 0 (add --allow-zero-signature-id only for zeek events)")

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("hook assertions passed (%d events)" % len(matched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
