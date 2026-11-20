#!/usr/bin/env python3
"""Assert Zeek correlation logs and optional Suricata community-id linkage."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List


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


def suricata_alerts(eve_path: str) -> List[dict]:
    alerts: List[dict] = []
    if not os.path.isfile(eve_path):
        return alerts
    for row in load_json_lines(eve_path):
        if row.get("event_type") == "alert":
            alerts.append(row)
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--eve-root")
    parser.add_argument("--case")
    parser.add_argument(
        "--link-scope",
        choices=("single", "multi"),
        default="single",
        help=(
            "single: 该用例的告警只发生在一条流上，要求两侧 community_id 有交集；"
            "multi: 用例是多次独立连接组成的突发（如扫描/爆破），"
            "community_id 天然分属不同流，改为断言告警与关联事件端点一致。"
        ),
    )
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
        alerts = suricata_alerts(eve)
        suricata_ids = {a.get("community_id") for a in alerts if a.get("community_id")}
        zeek_ids = {row.get("community_id") for row in rows if row.get("community_id")}
        if not suricata_ids:
            failures.append("no Suricata alert community_id in %s" % eve)
        if not zeek_ids:
            failures.append("no Zeek community_id in %s" % args.log)
        if args.link_scope == "single":
            if suricata_ids and zeek_ids and not (suricata_ids & zeek_ids):
                failures.append(
                    "community_id mismatch: suricata=%s zeek=%s"
                    % (sorted(suricata_ids), sorted(zeek_ids))
                )
        else:
            # 多流突发：cid 必不相同，断言两侧描述的是同一对端点。
            # 端点方向不固定：Suricata 可能把告警挂在响应方向，故按无序对比较。
            eve_pairs = {
                frozenset((a.get("src_ip"), a.get("dest_ip")))
                for a in alerts
                if a.get("src_ip")
            }
            zeek_pairs = {frozenset((row.get("src"), row.get("dst"))) for row in rows}
            if not (eve_pairs & zeek_pairs):
                failures.append(
                    "endpoint mismatch: suricata=%s zeek=%s"
                    % (sorted(map(sorted, eve_pairs)), sorted(map(sorted, zeek_pairs)))
                )
            else:
                print(
                    "NOTE link-scope=multi: community_id 分属不同流（扫描/爆破形态），"
                    "只断言端点一致：%s"
                    % sorted(map(sorted, eve_pairs & zeek_pairs))
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
