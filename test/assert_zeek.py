#!/usr/bin/env python3
"""Assert Zeek notice.log entries for the generated PCAP corpus."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Set


def read_notices(path: str) -> Set[str]:
    notes: Set[str] = set()
    if not os.path.isfile(path):
        return notes
    fields = []
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#"):
                continue
            values = line.split("\t")
            if not fields or len(values) != len(fields):
                continue
            row = dict(zip(fields, values))
            note = row.get("note", "")
            if note and note != "-":
                notes.add(note)
    return notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-root", required=True)
    parser.add_argument("--cases", required=True)
    args = parser.parse_args()

    with open(args.cases, "r", encoding="utf-8") as fp:
        cases: Dict[str, dict] = json.load(fp)

    failures = []
    for name, spec in sorted(cases.items()):
        log_dir = os.path.join(args.log_root, name)
        notices = read_notices(os.path.join(log_dir, "notice.log"))
        require = spec.get("require", [])
        forbid = spec.get("forbid", [])
        missing = [n for n in require if not any(n in note for note in notices)]
        unexpected = [n for n in forbid if any(n in note for note in notices)]
        status = "OK"
        if missing or unexpected:
            status = "FAIL"
            failures.append(name)
        print(
            "%-28s %-4s notices=%s missing=%s forbidden=%s"
            % (name, status, sorted(notices), missing, unexpected)
        )

    if failures:
        print("\nFAILED cases: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print("\nall %d Zeek cases passed" % len(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
