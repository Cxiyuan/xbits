#!/usr/bin/env python3
"""Validator stub: returns false_positive for sid 9103001, uncertain otherwise."""
from __future__ import annotations

import json
import sys


def main() -> int:
    req = json.load(sys.stdin)
    alert = req.get("alert", {})
    sid = alert.get("signature_id")
    verdict = "false_positive" if sid in (9103001, 9103002) else "uncertain"
    out = {
        "verdict": verdict,
        "confidence": 95 if verdict == "false_positive" else 10,
        "reason": "stub-validator",
        "evidence": [f"sid={sid}"],
    }
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
