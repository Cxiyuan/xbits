#!/usr/bin/env python3
"""Rule coverage gate (honest scope).

本门禁只对 **4 个自研场景目录** 的规则做「必须被 require/forbid 命名」的强断言；
其余 11 个目录是转换自外部探针规则库的规则族，目前只有 `suricata -T` 加载校验，
没有 PCAP 命中回归，因此被**显式排除**并逐目录列出原因。输出必须同时打印
`covered X/Y`、排除目录数与排除 SID 数，禁止再用 "all sids" 文案（qa/QA_REPORT.md
V-17 / S-01）。

排除不是「看不见」：
- 新增的规则目录如果既不在 COVERED_CATEGORIES 也不在 EXCLUDED_RULE_DIRS，直接 FAIL；
- EXCLUDED_RULE_DIRS 里登记了但磁盘上不存在的目录，同样 FAIL（防列表腐烂）；
- 每个被排除目录都会打印 files/sids 与排除原因，排除总量参与最终 PASS 文案。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE_ROOT = ROOT / "规则检测" / "suricata"

# 强断言范围：这 4 个目录的每个 SID 必须被至少一个用例的 require/forbid 命名。
COVERED_CATEGORIES = [
    {
        "name": "dns",
        "rule_dir": RULE_ROOT / "DNS隧道与带外检测",
        "cases": ROOT / "测试用例" / "cases.json",
        "pcap_dir": ROOT / "测试用例" / "pcap",
    },
    {
        "name": "recon",
        "rule_dir": RULE_ROOT / "侦察与攻击工具指纹",
        "cases": ROOT / "测试用例" / "recon_cases.json",
        "pcap_dir": ROOT / "测试用例" / "recon_pcap",
    },
    {
        "name": "web",
        "rule_dir": RULE_ROOT / "Web漏洞利用",
        "cases": ROOT / "测试用例" / "web_cases.json",
        "pcap_dir": ROOT / "测试用例" / "web_pcap",
    },
    {
        "name": "backdoor",
        "rule_dir": RULE_ROOT / "后门通信",
        "cases": ROOT / "测试用例" / "backdoor_cases.json",
        "pcap_dir": ROOT / "测试用例" / "backdoor_pcap",
    },
]

# 显式排除清单：目录名 -> 排除原因（必须与磁盘目录一一对应，多/少都 FAIL）。
EXCLUDED_RULE_DIRS = {
    "Web攻击": "转换自探针规则库（25 个 .rules：SQLi/XSS/WebShell/扫描器/文件上传等）；"
    "只有 docker/probe-rules-*.yaml 的 `suricata -T` 加载校验，无 PCAP 正负例命中回归",
    "恶意软件": "转换自探针规则库（5 个 .rules：Shellcode/后门/木马/蠕虫/间谍软件）；只有加载校验，无命中回归",
    "主机系统漏洞": "转换自探针规则库（system.rules，749 SID）；只有加载校验，无命中回归",
    "应用软件漏洞": "转换自探针规则库（application/media，828 SID）；只有加载校验，无命中回归",
    "恶意URL": "转换自探针规则库（malice_url_report.rules，52 SID）；只有加载校验，无命中回归",
    "文件与协议解析漏洞": "转换自探针规则库（file.rules，606 SID）；只有加载校验，无命中回归",
    "暴力破解": "转换自探针规则库（brute_force.rules，88 SID）；只有加载校验，无命中回归",
    "网络服务漏洞": "转换自探针规则库（DNS/FTP/Telnet/TFTP/数据库/邮件，535 SID）；只有加载校验，无命中回归",
    "网络设备漏洞": "转换自探针规则库（network_device.rules，423 SID）；只有加载校验，无命中回归",
    "配置与运维缺陷": "转换自探针规则库（config_error.rules，100 SID）；只有加载校验，无命中回归",
    "其他": "转换自探针规则库（bp_ips/other，781 SID）；只有加载校验，无命中回归",
}

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")


def rule_sids(rule_dir: Path) -> set[int]:
    sids: set[int] = set()
    for path in sorted(rule_dir.rglob("*.rules")):
        text = path.read_text(encoding="utf-8", errors="replace")
        sids.update(int(x) for x in SID_RE.findall(text))
    return sids


def dir_stats(rule_dir: Path) -> tuple[int, set[int]]:
    files = 0
    sids: set[int] = set()
    for path in sorted(rule_dir.rglob("*.rules")):
        files += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        sids.update(int(x) for x in SID_RE.findall(text))
    return files, sids


def main() -> int:
    failures: list[str] = []
    covered_names = {cat["rule_dir"].name for cat in COVERED_CATEGORIES}

    if not RULE_ROOT.is_dir():
        print(f"RULE COVERAGE: FAIL (missing rule root: {RULE_ROOT})", file=sys.stderr)
        return 1

    on_disk = {p.name for p in RULE_ROOT.iterdir() if p.is_dir()}
    unclassified = sorted(on_disk - covered_names - set(EXCLUDED_RULE_DIRS))
    stale_excluded = sorted(set(EXCLUDED_RULE_DIRS) - on_disk - covered_names)
    if unclassified:
        failures.append(
            "new rule dir(s) not classified: "
            f"{unclassified} — 必须二选一：加入 COVERED_CATEGORIES（配 cases/pcap 断言）"
            "或加入 EXCLUDED_RULE_DIRS（写清排除原因）"
        )
    if stale_excluded:
        failures.append(f"EXCLUDED_RULE_DIRS 登记的目录已不存在（列表腐烂）: {stale_excluded}")

    covered_sids: set[int] = set()
    category_details: list[str] = []
    for cat in COVERED_CATEGORIES:
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
        covered_sids |= sids
        cases = json.loads(cases_path.read_text(encoding="utf-8-sig"))
        used: set[int] = set()
        for _name, spec in cases.items():
            used.update(int(x) for x in spec.get("require", []))
            used.update(int(x) for x in spec.get("forbid", []))

        uncovered = sorted(sids - used)
        unknown = sorted(used - sids)
        pcaps = {p.stem for p in pcap_dir.glob("*.pcap")}
        missing_pcaps = sorted(set(cases) - pcaps)
        extra_pcaps = sorted(pcaps - set(cases))

        category_details.append(
            f'{cat["name"]}: rule_sids={len(sids)} named_by_cases={len(used)} '
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

    excluded_rows: list[tuple[str, int, int, str]] = []
    excluded_sids: set[int] = set()
    for name, reason in EXCLUDED_RULE_DIRS.items():
        rule_dir = RULE_ROOT / name
        if not rule_dir.is_dir():
            continue  # 已在 stale_excluded 里报错
        files, sids = dir_stats(rule_dir)
        excluded_sids |= sids
        excluded_rows.append((name, files, len(sids), reason))

    total_sids = covered_sids | excluded_sids
    pct = (100.0 * len(covered_sids) / len(total_sids)) if total_sids else 0.0

    for line in category_details:
        print(line)
    print(
        f"\ncovered {len(covered_sids)}/{len(total_sids)} unique SIDs "
        f"({pct:.1f}%) | excluded {len(excluded_rows)} dirs / {len(excluded_sids)} SIDs"
    )
    print("excluded dirs (仅 `suricata -T` 加载校验，无命中回归):")
    for name, files, sids, reason in excluded_rows:
        print(f"  - {name}: files={files} sids={sids} — {reason}")

    if failures:
        print("\nRULE COVERAGE: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1

    print(
        f"\nRULE COVERAGE: PASS — {len(covered_sids)} of {len(total_sids)} SIDs are asserted by "
        f"require/forbid cases (4 scenario dirs); {len(excluded_sids)} SIDs in "
        f"{len(excluded_rows)} converted dirs are excluded by policy (see list above), "
        "not silently ignored."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
