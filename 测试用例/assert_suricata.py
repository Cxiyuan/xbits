#!/usr/bin/env python3
"""Assert Suricata EVE alerts for the generated PCAP corpus."""

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

    with open(args.cases, "r", encoding="utf-8") as fp:
        cases: Dict[str, dict] = json.load(fp)

    failures = []
    for name, spec in sorted(cases.items()):
        eve_path = os.path.join(args.eve_root, name, "eve.json")
        if not os.path.isfile(eve_path):
            failures.append("%s: missing %s" % (name, eve_path))
            continue

        actual = read_alerts(eve_path)
        require = {int(sid) for sid in spec.get("require", [])}
        forbid = {int(sid) for sid in spec.get("forbid", [])}
        missing = sorted(require - actual)
        unexpected = sorted(forbid & actual)
        status = "OK"
        if missing or unexpected:
            status = "FAIL"
            failures.append(name)
        print(
            "%-28s %-4s alerts=%s missing=%s forbidden=%s"
            % (name, status, sorted(actual), missing, unexpected)
        )

    if failures:
        print("\nFAILED cases: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print("\nall %d Suricata cases passed" % len(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
