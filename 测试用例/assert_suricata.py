#!/usr/bin/env python3
"""Assert Suricata EVE alerts for the generated PCAP corpus.

每个用例必须是"有态度"的断言：
  * require 非空 → 这些 SID 必须出现；
  * forbid 非空 → 这些 SID 不得出现；
  * require 与 forbid **都为空 → 直接失败并点名用例**（既不断言命中也不断言不命中，
    等于恒真。qa/QA_REPORT.md V-18：18 个用例里 c2_periodic 曾是这样）。

用例可带 `note` 说明"为什么这个空 require 是对的"（如 C2 周期性信标由 Zeek 行为
脚本断言，Suricata 侧只做误报防护），note 会被打印，便于 review 时看到设计意图。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Set


def read_alerts(eve_path: str) -> Set[int]:
    sids: Set[int] = set()
    with open(eve_path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            sid = event.get("alert", {}).get("signature_id")
            if isinstance(sid, int):
                sids.add(sid)
    return sids


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve-root", required=True)
    parser.add_argument("--cases", required=True)
    args = parser.parse_args()

    with open(args.cases, "r", encoding="utf-8-sig") as fp:
        cases: Dict[str, dict] = json.load(fp)

    failures = []
    asserted = 0
    for name, spec in sorted(cases.items()):
        require = {int(sid) for sid in spec.get("require", [])}
        forbid = {int(sid) for sid in spec.get("forbid", [])}
        note = str(spec.get("note") or "").strip()
        if not require and not forbid:
            failures.append(
                "%s: 空断言（require 与 forbid 均为空）—— 既不断言命中也不断言不命中，恒真；"
                "请补 require/forbid 或用例级 note+require 说明" % name
            )
            print("%-28s %-4s reason=%s" % (name, "FAIL", "empty require/forbid"))
            continue

        eve_path = os.path.join(args.eve_root, name, "eve.json")
        if not os.path.isfile(eve_path):
            failures.append("%s: missing %s" % (name, eve_path))
            print("%-28s %-4s reason=%s" % (name, "FAIL", "missing eve.json"))
            continue

        actual = read_alerts(eve_path)
        asserted += 1
        missing = sorted(require - actual)
        unexpected = sorted(forbid & actual)
        status = "OK"
        if missing or unexpected:
            status = "FAIL"
            failures.append(name)
        print(
            "%-28s %-4s alerts=%s missing=%s forbidden=%s%s"
            % (
                name,
                status,
                sorted(actual),
                missing,
                unexpected,
                (" note=" + note) if note else "",
            )
        )

    if failures:
        print("\nFAILED cases: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print(
        "\nall %d Suricata cases passed (%d cases carry require/forbid assertions)"
        % (len(cases), asserted)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
