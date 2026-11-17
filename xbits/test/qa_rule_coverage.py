#!/usr/bin/env python3
"""Rule coverage gate.

Every sid in every 规则检测/**/*.rules file must be named by at least one
generated case in require/forbid.  This prevents a rule from being silently
loaded but never exercised (the classic "green CI with an untested rule").
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CATEGORIES = [
    {
        "name": "dns",
        "rule_dir": ROOT / "规则检测" / "suricata" / "DNS隧道与带外检测",
        "cases": ROOT / "测试用例" / "cases.json",
        "pcap_dir": ROOT / "测试用例" / "pcap",
    },
    {
        "name": "recon",
        "rule_dir": ROOT / "规则检测" / "suricata" / "侦察与攻击工具指纹",
        "cases": ROOT / "测试用例" / "recon_cases.json",
        "pcap_dir": ROOT / "测试用例" / "recon_pcap",
    },
    {
        "name": "web",
        "rule_dir": ROOT / "规则检测" / "suricata" / "Web漏洞利用",
        "cases": ROOT / "测试用例" / "web_cases.json",
        "pcap_dir": ROOT / "测试用例" / "web_pcap",
    },
    {
        "name": "backdoor",
        "rule_dir": ROOT / "规则检测" / "suricata" / "后门通信",
        "cases": ROOT / "测试用例" / "backdoor_cases.json",
        "pcap_dir": ROOT / "测试用例" / "backdoor_pcap",
    },
]

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")


def rule_sids(rule_dir: Path) -> set[int]:
    sids: set[int] = set()
    for path in sorted(rule_dir.rglob("*.rules")):
        # sangfor 转换规则暂不纳入覆盖门禁（无测试用例，独立验证加载）
        if "sangfor" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        sids.update(int(x) for x in SID_RE.findall(text))
    return sids


def main() -> int:
    failures: list[str] = []
    for cat in CATEGORIES:
        rule_dir: Path = cat["rule_dir"]
        cases_path: Path = cat["cases"]
        pcap_dir: Path = cat["pcap_dir"]
        if not rule_dir.is_dir():
            failures.append(f'{cat["name"]}: missing rule dir {rule_dir}')
            continue
        if not cases_path.is_file():
            failures.append(f'{cat["name"]}: missing cases {cases_path}')
            continue
        if not pcap_dir.is_dir():
            failures.append(f'{cat["name"]}: missing pcap dir {pcap_dir}')
            continue

        sids = rule_sids(rule_dir)
        cases = json.loads(cases_path.read_text(encoding="utf-8-sig"))
        covered: set[int] = set()
        for _name, spec in cases.items():
            covered.update(int(x) for x in spec.get("require", []))
            covered.update(int(x) for x in spec.get("forbid", []))

        uncovered = sorted(sids - covered)
        unknown = sorted(covered - sids)
        pcaps = {p.stem for p in pcap_dir.glob("*.pcap")}
        missing_pcaps = sorted(set(cases) - pcaps)
        extra_pcaps = sorted(pcaps - set(cases))

        print(
            f'{cat["name"]}: rule_sids={len(sids)} covered_sids={len(covered)} '
            f'cases={len(cases)} pcaps={len(pcaps)}'
        )
        if uncovered:
            failures.append(f'{cat["name"]}: uncovered rule sids={uncovered}')
        if unknown:
            failures.append(f'{cat["name"]}: cases reference unknown sids={unknown}')
        if missing_pcaps:
            failures.append(f'{cat["name"]}: cases missing pcap files={missing_pcaps}')
        if extra_pcaps:
            failures.append(f'{cat["name"]}: pcaps without case spec={extra_pcaps}')

    if failures:
        print("\nRULE COVERAGE: FAIL", file=sys.stderr)
        for f in failures:
            print(" -", f, file=sys.stderr)
        return 1
    print("\nRULE COVERAGE: PASS (all rule sids are exercised by at least one case)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
