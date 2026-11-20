#!/usr/bin/env python3
"""Assert xbits events (correlation log or EVE->alert bridge JSON) with field-level checks.

两种输入源：
  * `--source correlation`（默认）：Zeek/跨引擎相关日志（xbits_correlation.log），
    行里有 scenario/signature_id/reason/community_id/related_sids 等字段。
  * `--source alert-json`：`xbits --stdin`（EVE alert -> xbits alert）输出，
    字段为 timestamp/signature_id/signature/community_id/src/dst/sport/dport/proto/flow_id。

替代原来的 `grep -q '"signature_id":9103001'`（输入第 1 行本身就含该串，等于回声测试）：
这里解析 JSON，断言**精确条数**与**必填字段非空**，缺字段/条数不对/超时都失败。

This is a test helper only; it is not part of detection logic.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List

DEFAULT_FIELDS = {
    "correlation": ("community_id", "src", "dst", "reason", "related_sids"),
    "alert-json": ("signature_id", "signature", "src", "dst", "proto"),
}


def load_rows(path: str) -> List[dict]:
    rows: List[dict] = []
    if path == "-":
        fp = sys.stdin
        close = False
    else:
        fp = open(path, "r", encoding="utf-8", errors="replace")
        close = True
    try:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    finally:
        if close:
            fp.close()
    return rows


def is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="path to JSONL log, or '-' for stdin")
    parser.add_argument("--source", choices=sorted(DEFAULT_FIELDS), default="correlation")
    parser.add_argument("--signature-id", type=int, default=None)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--expect-count", type=int, default=None, help="matched rows must equal this exactly")
    parser.add_argument("--require-uid", action="store_true")
    parser.add_argument(
        "--require-fields",
        default=None,
        help="comma separated field names that must be present and non-empty",
    )
    parser.add_argument("--scenario", default="xbits-cross-engine")
    parser.add_argument("--reason", default="suricata_alert")
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=0.0,
        help="poll the file until enough rows appear (seconds); 0 = read once",
    )
    args = parser.parse_args()

    required = (
        tuple(f.strip() for f in args.require_fields.split(",") if f.strip())
        if args.require_fields
        else DEFAULT_FIELDS[args.source]
    )

    rows: List[dict] = []
    deadline = time.time() + max(args.wait_timeout, 0.0)
    wanted = args.expect_count if args.expect_count is not None else args.min_events
    while True:
        try:
            rows = load_rows(args.log)
        except OSError as err:
            print("missing xbits log: %s" % err, file=sys.stderr)
            return 1

        matched = []
        for row in rows:
            if args.source == "correlation":
                if row.get("scenario") != args.scenario:
                    continue
                if args.signature_id is not None and row.get("signature_id") != args.signature_id:
                    continue
                if row.get("reason") != args.reason:
                    continue
            else:
                if args.signature_id is not None and row.get("signature_id") != args.signature_id:
                    continue
            matched.append(row)
        rows = matched

        if len(rows) >= wanted or time.time() >= deadline:
            break
        time.sleep(0.1)

    failures: List[str] = []
    if len(rows) < args.min_events:
        failures.append(
            "expected >=%d events, got %d (source=%s, waited %.1fs)"
            % (args.min_events, len(rows), args.source, args.wait_timeout)
        )
    if args.expect_count is not None and len(rows) != args.expect_count:
        failures.append("expected exactly %d events, got %d" % (args.expect_count, len(rows)))

    for row in rows:
        for key in required:
            if is_blank(row.get(key)):
                failures.append("event missing %s: %r" % (key, row))
                break
        if args.source == "correlation":
            related = row.get("related_sids")
            if isinstance(related, list) and args.signature_id is not None:
                if args.signature_id not in related:
                    failures.append("related_sids does not contain signature: %r" % related)
            if args.require_uid and is_blank(row.get("uid")):
                failures.append("event missing uid: %r" % row)
        else:
            sid = row.get("signature_id")
            if not isinstance(sid, int):
                failures.append("signature_id must be int: %r" % row.get("signature_id"))

    for row in rows:
        print(
            "OK %s"
            % " ".join("%s=%s" % (k, row.get(k)) for k in ("signature_id", "rule_id", "community_id", "uid", "reason", "score"))
        )

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("xbits assertions passed (%d events, fields=%s)" % (len(rows), ",".join(required)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
