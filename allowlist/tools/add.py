#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 自定义条目管理：add / remove / list，只改 custom/（refresh 后生效）。

用法：
  python3 allowlist/tools/add.py add domain example.com
  python3 allowlist/tools/add.py add ip 1.2.3.4
  python3 allowlist/tools/add.py add public_dns 9.9.9.9
  python3 allowlist/tools/add.py add domain a.com b.com c.org   # 批量
  python3 allowlist/tools/add.py remove domain example.com
  python3 allowlist/tools/add.py list
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOM_DIR = os.path.join(MODULE_ROOT, "custom")
RX_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

TARGETS = {"domain": "domain.txt", "ip": "ip.txt", "public_dns": "public_dns_servers.txt"}


def read_entries(path: str) -> set[str]:
    out = set()
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                v = line.strip().split("#")[0].strip()
                if v:
                    out.add(v)
    return out


def write_entries(path: str, header_lines: list[str], entries: set[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for h in header_lines:
            fh.write(h + "\n")
        for v in sorted(entries):
            fh.write(v + "\n")


def load_header(path: str, default: list[str]) -> list[str]:
    hdr = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    hdr.append(line.rstrip("\n"))
    return hdr or default


def validate(kind: str, value: str) -> str | None:
    if kind in ("ip", "public_dns"):
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return None
    v = value.strip().lower().lstrip(".")
    return v if RX_DOMAIN.match(v) else None


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    action = sys.argv[1]
    if action == "list":
        for kind, fname in TARGETS.items():
            p = os.path.join(CUSTOM_DIR, fname)
            n = len(read_entries(p))
            print(f"{kind:12} {fname:26} {n} 条")
        return 0
    if action not in ("add", "remove") or len(sys.argv) < 4:
        print(__doc__)
        return 1
    kind = sys.argv[2]
    if kind not in TARGETS:
        print(f"未知类型 {kind}（可选: {' '.join(TARGETS)}）")
        return 1
    path = os.path.join(CUSTOM_DIR, TARGETS[kind])
    header = load_header(path, [f"# allowlist 自定义白名单（类型: {kind}）"])
    entries = read_entries(path)
    changed = skipped = 0
    for raw in sys.argv[3:]:
        v = validate(kind, raw)
        if v is None:
            print(f"[SKIP] 非法条目: {raw}")
            skipped += 1
            continue
        if action == "add":
            if v in entries:
                skipped += 1
                continue
            entries.add(v)
            changed += 1
        else:
            if v not in entries:
                skipped += 1
                continue
            entries.discard(v)
            changed += 1
    if changed:
        write_entries(path, header, entries)
        print(f"[OK] {action} {kind}: 变更 {changed} 条，跳过 {skipped} 条 -> custom/{TARGETS[kind]}")
        print("     记得执行: python3 allowlist/tools/refresh.py  重建 data/ 后生效")
    else:
        print(f"[无变更] 跳过 {skipped} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
