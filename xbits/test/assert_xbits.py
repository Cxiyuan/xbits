#!/usr/bin/env python3
"""Assert xbits correlation events produced by Zeek 9.0.1.

This is a test helper only; it is not part of detection logic.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List


def load_rows(path: str) -> List[dict]:
    rows: List[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
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
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--signature-id", type=int, default=9103001)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--require-uid", action="store_true")
    args = parser.parse_args()

    try:
        rows = load_rows(args.log)
    except OSError as err:
        print("missing xbits log: %s" % err, file=sys.stderr)
        return 1

    rows = [
        row
        for row in rows
        if row.get("scenario") == "xbits-cross-engine"
        and row.get("signature_id") == args.signature_id
        and row.get("reason") == "suricata_alert"
    ]
    failures: List[str] = []
    if len(rows) < args.min_events:
        failures.append(
            "expected >=%d xbits events with signature_id=%d, got %d"
            % (args.min_events, args.signature_id, len(rows))
        )

    for row in rows:
        for key in ("community_id", "src", "dst", "reason", "related_sids"):
            if not row.get(key):
                failures.append("event missing %s: %r" % (key, row))
                break
        if row.get("reason") != "suricata_alert":
            failures.append("unexpected reason: %r" % row.get("reason"))
        related = row.get("related_sids")
        if isinstance(related, list) and args.signature_id not in related:
            failures.append("related_sids does not contain signature: %r" % related)
        if args.require_uid and not row.get("uid"):
            failures.append("event missing uid: %r" % row)

    for row in rows:
        print(
            "OK signature_id=%s community_id=%s uid=%s reason=%s score=%s"
            % (
                row.get("signature_id"),
                row.get("community_id"),
                row.get("uid"),
                row.get("reason"),
                row.get("score"),
            )
        )

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("xbits assertions passed (%d events)" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
