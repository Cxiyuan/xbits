#!/usr/bin/env python3
"""Assert Zeek correlation logs and optional Suricata community-id linkage."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Set


def load_json_lines(path: str) -> List[dict]:
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


def suricata_community_ids(eve_path: str) -> Set[str]:
    ids: Set[str] = set()
    if not os.path.isfile(eve_path):
        return ids
    for row in load_json_lines(eve_path):
        if row.get("event_type") != "alert":
            continue
        cid = row.get("community_id")
        if isinstance(cid, str) and cid:
            ids.add(cid)
    return ids


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--eve-root")
    parser.add_argument("--case")
    args = parser.parse_args()

    if not os.path.isfile(args.log):
        print("missing Zeek log: %s" % args.log, file=sys.stderr)
        return 1

    rows = [
        row
        for row in load_json_lines(args.log)
        if row.get("scenario") == args.scenario
    ]
    failures = []
    if len(rows) < args.min_events:
        failures.append("expected >=%d %s events, got %d" % (
            args.min_events, args.scenario, len(rows)))

    for row in rows:
        for key in ("reason", "related_sids", "community_id", "uid"):
            if not row.get(key):
                failures.append("event missing %s: %r" % (key, row))
                break

    if not failures and args.eve_root and args.case:
        eve = os.path.join(args.eve_root, args.case, "eve.json")
        suricata_ids = suricata_community_ids(eve)
        zeek_ids = {row.get("community_id") for row in rows if row.get("community_id")}
        if not suricata_ids:
            failures.append("no Suricata alert community_id in %s" % eve)
        if not zeek_ids:
            failures.append("no Zeek community_id in %s" % args.log)
        if suricata_ids and zeek_ids and not (suricata_ids & zeek_ids):
            failures.append(
                "community_id mismatch: suricata=%s zeek=%s"
                % (sorted(suricata_ids), sorted(zeek_ids))
            )

    for row in rows:
        print(
            "OK scenario=%s reason=%s community_id=%s related_sids=%s"
            % (
                row.get("scenario"),
                row.get("reason"),
                row.get("community_id"),
                row.get("related_sids"),
            )
        )

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("Zeek correlation assertions passed (%d events)" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
