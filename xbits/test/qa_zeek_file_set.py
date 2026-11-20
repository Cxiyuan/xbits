#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zeek 行为脚本文件集合守卫 + 历史转换器写盘路径静态检查（纯静态，stdlib only）。

来源：qa/QA_REPORT.md V-24 / R-08 / R-09 / TS-12。
不变量（任一破坏即 exit 1）：
  1. 规则检测/zeek/ 下 `*.zeek` 文件集合 == 3 个行为脚本（精确列名，多/少都 FAIL）；
     防止已删除的 威胁情报/*.zeek 被任何工具重建，也防止新增签名脚本混入。
  2. 规则检测/convert_probe_zeek.py **无任何写盘路径**：不得出现
     `OUT = ROOT/"zeek"`、`mkdir`、`write_text`、`open(..., "w")` 等；且 `main()`
     不得因输入目录缺失而 `return 2`（该脚本不再读任何输入）。
     防止「删了函数体但有人在 main() 加一行调用就重建目录」。
  3. 规则检测/docs/规则质量QA数据.json 的 zeek_scripts 键集合 == 实际 *.zeek 文件
     集合——防止删文件后 QA 数据仍列旧条目（TS-12 陈旧产物假绿）。

退出码：0=全部通过；1=守卫失败（逐条打印破坏项）；2=解析/读文件失败。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ZEEK_DIR = ROOT / "规则检测" / "zeek"
CONVERTER = ROOT / "规则检测" / "convert_probe_zeek.py"
QA_DATA = ROOT / "规则检测" / "docs" / "规则质量QA数据.json"

# 精确列名：Zeek 只做行为分析，这 3 个脚本手工维护，任何增删都要显式改这里。
EXPECTED_ZEEK = {
    "DNS隧道与带外检测/dns_tunnel_score.zeek",
    "侦察与攻击工具指纹/recon_score.zeek",
    "后门通信/backdoor_c2_score.zeek",
}

# convert_probe_zeek.py 中被禁止的写盘痕迹（大小写不敏感匹配源码行）。
WRITE_PATTERNS = (
    (re.compile(r"\bOUT\s*=\s*ROOT\s*/\s*[\"']zeek[\"']", re.I), "OUT = ROOT/\"zeek\""),
    (re.compile(r"\.mkdir\s*\(", re.I), ".mkdir("),
    (re.compile(r"\.write_text\s*\(", re.I), ".write_text("),
    (re.compile(r"\.write_bytes\s*\(", re.I), ".write_bytes("),
    (re.compile(r"\bopen\s*\([^)]*[\"'][wa+]", re.I), "open(..., 'w'/'a')"),
    (re.compile(r"\breturn\s+2\b"), "return 2（main 不再因输入目录失败）"),
)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    failures: list[str] = []

    # 1) 文件集合
    if not ZEEK_DIR.is_dir():
        print(f"FAIL: {ZEEK_DIR} 不存在", file=sys.stderr)
        return 2
    actual = {p.relative_to(ZEEK_DIR).as_posix() for p in ZEEK_DIR.rglob("*.zeek")}
    extra = sorted(actual - EXPECTED_ZEEK)
    missing = sorted(EXPECTED_ZEEK - actual)
    if extra or missing:
        failures.append(f"zeek 文件集合不符：多={extra}，少={missing}")
    print(f"zeek *.zeek = {len(actual)} 个：{sorted(actual)}")

    # 2) 转换器写盘痕迹
    if not CONVERTER.is_file():
        failures.append(f"缺少 {CONVERTER}")
    else:
        src = CONVERTER.read_text(encoding="utf-8", errors="replace")
        for regex, why in WRITE_PATTERNS:
            hits = [i + 1 for i, line in enumerate(src.splitlines()) if regex.search(line)]
            if hits:
                failures.append(f"convert_probe_zeek.py 残留写盘/失败逻辑 {why} @ 行 {hits}")

    # 3) QA 数据陈旧条目
    if QA_DATA.is_file():
        try:
            data = json.loads(QA_DATA.read_text(encoding="utf-8"))
            keys = set((data.get("zeek_scripts") or {}).keys())
            expected_qa = {f"zeek/{rel}" for rel in EXPECTED_ZEEK}
            stale = sorted(keys - expected_qa)
            miss = sorted(expected_qa - keys)
            if stale or miss:
                failures.append(f"规则质量QA数据.json zeek_scripts 陈旧：多={stale}，少={miss}")
            print(f"zeek_scripts QA keys = {len(keys)} 个")
        except (ValueError, OSError) as e:
            failures.append(f"规则质量QA数据.json 解析失败: {e}")
    else:
        failures.append(f"缺少 {QA_DATA}")

    if failures:
        print("FAIL: Zeek 文件集合/写盘路径守卫未通过：", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        print("修复方向：删掉多余 .zeek 与转换器写盘函数；刷新 docs/规则质量QA数据.json。",
              file=sys.stderr)
        return 1

    print("ZEEK FILE SET: PASS (3 behavior scripts, no write path, QA data fresh)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
