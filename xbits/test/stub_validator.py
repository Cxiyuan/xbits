#!/usr/bin/env python3
"""Validator stub: returns false_positive for sid 9103001, uncertain otherwise."""
from __future__ import annotations

import json
import sys


def main() -> int:
    req = json.load(sys.stdin)
    alert = req.get("alert", {})
    sid = alert.get("signature_id")
    verdict = "false_positive" if sid in (9103001, 9103002, 9103003, 9103004, 9103005, 9103006) else "uncertain"
    # 9103006：低置信误报，用于验证 fp_confidence 门槛（默认 90）不为它建白名单。
    confidence = 40 if sid == 9103006 else 95
    out = {
        "verdict": verdict,
        "confidence": confidence if verdict == "false_positive" else 10,
        "reason": "stub-validator",
        "evidence": [f"sid={sid}"],
    }
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
