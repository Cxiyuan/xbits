#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 白名单统一查询：CLI + Python API（对 xbits/人工排查提供服务）。

CLI：
  python3 allowlist/tools/query.py --stats
  python3 allowlist/tools/query.py --domain map.baidu.com      # 含子域名匹配
  python3 allowlist/tools/query.py --ip 8.8.8.8
  python3 allowlist/tools/query.py --ip 8.8.8.8 --kind public_dns

Python API：
  from allowlist_query import AllowlistStore
  st = AllowlistStore(); st.lookup_domain("map.baidu.com"); st.lookup_ip("8.8.8.8")
"""
from __future__ import annotations

import argparse
import json
import os

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(MODULE_ROOT, "data")


class AllowlistStore:
    """data/ 快照的内存集合查询；domain 支持子域名匹配（baidu.com 覆盖 *.baidu.com）。"""

    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or DATA_DIR
        self._domain_suffixes: list[str] | None = None
        self._ips: set[str] | None = None
        self._public_dns: set[str] | None = None
        self.meta: dict = {}

    def _load(self):
        if self._ips is not None:
            return
        def read(name):
            p = os.path.join(self.data_dir, name)
            s = set()
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        v = line.strip().split("#")[0].strip()
                        if v:
                            s.add(v.lower())
            return s
        self._domain_suffixes = sorted(read("domain.txt"))
        self._ips = read("ip.txt")
        self._public_dns = read("public_dns.txt")
        mp = os.path.join(self.data_dir, "meta.json")
        if os.path.isfile(mp):
            try:
                with open(mp, encoding="utf-8") as fh:
                    self.meta = json.load(fh)
            except Exception:
                self.meta = {}

    def lookup_domain(self, value: str):
        v = str(value).strip().lower().lstrip(".")
        self._load()
        for w in self._domain_suffixes:
            if v == w or v.endswith("." + w):
                return {"matched": True, "type": "domain", "value": v, "list": w}
        return None

    def lookup_ip(self, value: str, kind: str = "ip"):
        v = str(value).strip().lower()
        self._load()
        pool = self._public_dns if kind == "public_dns" else self._ips
        if v in pool:
            return {"matched": True, "type": "ip", "kind": kind, "value": v}
        return None

    def stats(self) -> dict:
        self._load()
        return {"counts": {"domain": len(self._domain_suffixes), "ip": len(self._ips),
                           "public_dns": len(self._public_dns)}, "meta": self.meta}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default=None)
    ap.add_argument("--ip", default=None)
    ap.add_argument("--kind", default="ip", choices=["ip", "public_dns"], help="IP 查询的名单类型")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--data-dir", default=DATA_DIR)
    args = ap.parse_args()

    st = AllowlistStore(args.data_dir)
    if args.stats:
        print(json.dumps(st.stats(), ensure_ascii=False, indent=2))
        return 0
    if not (args.domain or args.ip):
        ap.print_help()
        return 1
    hit = st.lookup_domain(args.domain) if args.domain else st.lookup_ip(args.ip, args.kind)
    print(json.dumps({"matched": bool(hit), "detail": hit}, ensure_ascii=False))
    return 0 if hit is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
