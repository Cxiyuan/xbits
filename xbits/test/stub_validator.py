#!/usr/bin/env python3
"""Validator stub: returns false_positive for the test fixtures' SIDs and the
production-metadata regression SIDs it drives; uncertain otherwise."""
from __future__ import annotations

import json
import sys


def main() -> int:
    req = json.load(sys.stdin)
    alert = req.get("alert", {})
    sid = alert.get("signature_id")
    # false_positive 覆盖：测试夹具 SID（9103001-9103006）+ 生产元数据回归用例 SID
    # （9104001 / 11020687，见 qa_xbits_match_context.py 的 --production-meta 段）。
    # 生产 SID 也必须是明确 FP，否则抑制语义（建 key → 写白名单 → 二次命中被抑制）
    # 永远走不到：stub 返回 uncertain 时 confidence=10、不写白名单，prod 用例必然
    # suppressed=0 —— 这正是 run 44770518125 的失败根因（测试 harness 缺陷，非产品缺陷）。
    fp_sids = (9103001, 9103002, 9103003, 9103004, 9103005, 9103006, 9104001, 11020687)
    verdict = "false_positive" if sid in fp_sids else "uncertain"
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
