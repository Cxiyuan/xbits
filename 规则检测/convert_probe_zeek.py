#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部探针明文导出解析工具（历史转译参考）——**不产出任何文件**。

架构决策（Zeek 纯行为分析）：
- 规则检测/zeek/ 只保留 3 个行为分析脚本（DNS 突发 / 侦察 404+unique URI /
  C2 重复 URI），不再包含任何 content/UA 签名匹配，也不持有名单或情报数据；
- 白名单/基线由根目录 allowlist/ 子模块提供（custom/ + data/ + tools/），
  威胁情报由 threat-intel/ 子模块提供，均由 xbits 在 hook 到的事件上查询；
- 因此本文件保留的只是历史上解析明文导出 ini 段的工具函数，供人工核对；
  `main()` 固定返回 0，不读取输入目录、不创建目录、不写盘。
  任何写盘逻辑都不允许加回——`xbits/test/qa_zeek_file_set.py` 会静态扫描本文件，
  发现 OUT / mkdir / write_text 即 FAIL。

用法（仅为兼容历史命令，参数被忽略）：
  python 规则检测/convert_probe_zeek.py [--src <任意路径>]
"""
from __future__ import annotations

import argparse
from pathlib import Path


def parse_sections(path: Path) -> dict[str, dict[str, str]]:
    """解析明文导出的 ini 格式（[section] / key=value），仅供历史转译参考。"""
    sections: dict[str, dict[str, str]] = {}
    cur = None
    for raw in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections[cur] = {}
            continue
        if cur and "=" in line:
            k, v = line.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def main() -> int:
    parser = argparse.ArgumentParser(description="Zeek 历史解析工具（当前不产出文件）")
    parser.add_argument("--src", help="兼容历史命令的参数，已忽略（Zeek 只做行为分析）")
    parser.parse_args()
    print("nothing to generate: zeek is behavior-analysis only; "
          "allowlists live in allowlist/, intel in threat-intel/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
