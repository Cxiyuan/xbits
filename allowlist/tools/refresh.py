#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 刷新器：合并 custom/ 与（未来的）远端源，重建 data/ 快照。

设计（与 threat-intel 对称）：
  custom/  —— 手工白名单（tools/add.py 增删；refresh 永不覆盖）
  data/    —— 生成物快照：domain.txt / ip.txt / public_dns.txt + meta.json（消费方只读这里）

白名单是"允许/基线"方向的数据，质量与稳定性优先于时效：当前源均为静态转译，
refresh 的职责是校验 + 归一化 + 重建快照；后续若接远端公共白名单源（如公共后缀表、
常用 CDN 清单），在 sources.json 加条目并在本文件实现对应 fetch/parse。

用法：
  python3 allowlist/tools/refresh.py            # 重建 data/
  python3 allowlist/tools/refresh.py --check    # 只校验 custom/，不写 data/
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOM_DIR = os.path.join(MODULE_ROOT, "custom")
DATA_DIR = os.path.join(MODULE_ROOT, "data")

RX_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# custom 文件名 -> (data 输出名, 校验函数, 语义类型)
FILES = {
    "white_domains.txt": ("domain.txt", "domain", "业务白域名"),
    "public_dns_servers.txt": ("public_dns.txt", "ip", "公共 DNS 基线"),
    "ip.txt": ("ip.txt", "ip", "通用 IP 白名单"),
    "domain.txt": ("domain.txt", "domain", "通用域名白名单"),
}


def norm_domain(v: str) -> str | None:
    v = v.strip().lower().lstrip(".")
    return v if v and RX_DOMAIN.match(v) else None


def norm_ip(v: str) -> str | None:
    v = v.strip()
    try:
        return ipaddress.ip_address(v).exploded.lower() if ":" in v else v
    except ValueError:
        return None


def read_custom(fname: str, kind: str) -> tuple[list, list]:
    path = os.path.join(CUSTOM_DIR, fname)
    if not os.path.isfile(path):
        return [], []
    out, bad = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln, line in enumerate(fh, 1):
            v = line.strip().split("#")[0].strip()
            if not v:
                continue
            nv = norm_domain(v) if kind == "domain" else norm_ip(v)
            if nv is None:
                bad.append(f"{fname}:{ln}: {v}")
            else:
                out.append(nv)
    return out, bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验，不写 data/")
    args = ap.parse_args()

    domains, ips, bad = [], [], []
    for fname, (_out, kind, _desc) in FILES.items():
        vals, errs = read_custom(fname, kind)
        bad.extend(errs)
        if fname == "white_domains.txt":
            domains.extend(vals)
        elif fname == "public_dns_servers.txt":
            ips.extend(v for v in vals if v not in domains)  # 占位防重；见下归并
        elif fname == "domain.txt":
            domains.extend(vals)
        elif fname == "ip.txt":
            ips.extend(vals)
    domains = sorted(set(domains))
    ips = sorted(set(ips))
    # 公共 DNS 单独快照（行为基线语义独立于通用 IP 白名单）
    pub, _ = read_custom("public_dns_servers.txt", "ip")
    pub = sorted(set(pub))

    if bad:
        print("[FAIL] custom/ 存在非法条目：")
        for b in bad:
            print("   ", b)
        return 1
    if args.check:
        print(f"[OK] custom 校验通过：domain={len(domains)} ip={len(ips)} public_dns={len(pub)}")
        return 0

    os.makedirs(DATA_DIR, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    for name, lines in (("domain.txt", domains), ("ip.txt", ips), ("public_dns.txt", pub)):
        with open(os.path.join(DATA_DIR, name), "w", encoding="utf-8", newline="\n") as fh:
            for x in lines:
                fh.write(x + "\n")
    meta = {"refreshed_utc": now,
            "counts": {"domain": len(domains), "ip": len(ips), "public_dns": len(pub)},
            "layers": ["custom/（手工，不覆盖）"],
            "consumers": ["xbits（--allowlist-dir）", "tools/query.py"]}
    with open(os.path.join(DATA_DIR, "meta.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)
    print(f"[DONE] {now} domain={len(domains)} ip={len(ips)} public_dns={len(pub)} -> data/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
