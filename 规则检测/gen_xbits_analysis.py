#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 xbits 生产分析规则（SID 精确选择）。

从 规则检测/suricata 的实际 active 规则 + sid_library 分类生成：
  xbits/rules/analysis.json

规则只选 SID，不再用 signature_contains:"SQL" 这类宽匹配。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
SUR = ROOT / "suricata"
OUT = PROJECT / "xbits" / "rules" / "analysis.json"
SCENARIO_RECON = SUR / "侦察与攻击工具指纹"


def rule_sids(path: Path) -> set[int]:
    text = path.read_bytes().decode("utf-8", "replace")
    return {int(x) for x in re.findall(r"\bsid\s*:\s*(\d+)", text)}


def main() -> int:
    active: set[int] = set()
    for path in SUR.rglob("*.rules"):
        active |= rule_sids(path)

    lib = json.load(open(ROOT / "xbits/规则库元数据/sid_library.json", encoding="utf-8"))
    sqli = sorted(
        int(sid)
        for sid, meta in lib.items()
        if meta.get("subcategory") == "sql-injection" and int(sid) in active
    )
    # 自研 SQLi 规则不在 sid_library 中，显式加入
    if 9103001 in active and 9103001 not in sqli:
        sqli = sorted(set(sqli) | {9103001})

    recon: set[int] = set()
    for p in SCENARIO_RECON.glob("*.rules"):
        recon |= rule_sids(p)
    recon = sorted(recon)

    data = [
        {
            "id": "xb-suricata-web-sqli",
            "name": "Suricata Web SQLi (SID exact)",
            "source": "suricata",
            "kind": "alert",
            "sid_in": sqli,
            "require_context": True,
            "benign_uri_contains": ["/healthz", "/health", "/favicon.ico"],
            "min_confidence": 80,
            "score": 20,
            "threshold": 20,
            "reason": "suricata-sqli",
        },
        {
            "id": "xb-suricata-recon",
            "name": "Suricata Recon (SID exact)",
            "source": "suricata",
            "kind": "alert",
            "sid_in": recon,
            "require_context": True,
            "min_confidence": 60,
            "score": 10,
            "threshold": 10,
            "reason": "suricata-recon",
        },
        {
            "id": "xb-zeek-appid-scanner",
            "name": "Zeek app-id scanner alert",
            "source": "zeek",
            "kind": "alert",
            "event": "XbitsAlert::alert",
            "alert_kind": "scanner",
            "score": 30,
            "threshold": 30,
            "reason": "zeek-appid-scanner",
        },
    ]
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT}: sqli_sids={len(sqli)} recon_sids={len(recon)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())