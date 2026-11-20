#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""threat-intel 统一查询：CLI + Python API。

各消费方（triage / Suricata / xbits / 人工排查）按需查询对应情报类型（ip/domain/md5/sha1/sha256）。

CLI：
  python3 threat-intel/tools/query.py --stats
  python3 threat-intel/tools/query.py --ip 50.16.16.211
  python3 threat-intel/tools/query.py --domain example.com
  python3 threat-intel/tools/query.py --hash <32|40|64位hex>   # 按长度自动判 md5/sha1/sha256

Python API：
  from threat_intel_query import IntelStore   # 复制本文件或 sys.path 指到本目录
  st = IntelStore(); st.lookup_ip("1.2.3.4"); st.lookup_hash("...")
"""
from __future__ import annotations

import argparse
import json
import os
import re

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(MODULE_ROOT, "data")

RX_HEX = re.compile(r"^[0-9a-f]+$")
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


class IntelStore:
    """把 data/ 加载进内存集合做快速精确匹配（数据量万级，集合查询 O(1)）。"""

    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or DATA_DIR
        self._sets: dict | None = None
        self.meta: dict = {}

    def _load(self) -> dict:
        if self._sets is None:
            sets = {}
            for name in ("md5", "sha1", "sha256", "ip", "domain"):
                p = os.path.join(self.data_dir, name + ".txt")
                s = set()
                if os.path.isfile(p):
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            v = line.strip().split("#")[0].strip()
                            if v:
                                s.add(v.lower())
                sets[name] = s
            self._sets = sets
            mp = os.path.join(self.data_dir, "meta.json")
            if os.path.isfile(mp):
                try:
                    with open(mp, encoding="utf-8") as fh:
                        self.meta = json.load(fh)
                except Exception:
                    self.meta = {}
        return self._sets

    # ---- 查询接口：命中返回 dict，未命中返回 None ----
    def lookup_hash(self, value: str):
        v = str(value).strip().lower()
        algo = HASH_LEN.get(len(v))
        if not algo or not RX_HEX.match(v):
            return None
        if v in self._load()[algo]:
            return {"matched": True, "type": algo, "value": v}
        return None

    def lookup_ip(self, value: str):
        v = str(value).strip().lower()
        if v and v in self._load()["ip"]:
            return {"matched": True, "type": "ip", "value": v}
        return None

    def lookup_domain(self, value: str):
        v = str(value).strip().lower().lstrip(".")
        s = self._load()["domain"]
        if v in s:
            return {"matched": True, "type": "domain", "value": v}
        return None

    def stats(self) -> dict:
        s = self._load()
        return {"counts": {k: len(v) for k, v in s.items()}, "meta": self.meta}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default=None)
    ap.add_argument("--domain", default=None)
    ap.add_argument("--hash", dest="hsh", default=None, help="md5/sha1/sha256（按长度自动判）")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--data-dir", default=DATA_DIR)
    args = ap.parse_args()

    st = IntelStore(args.data_dir)
    if args.stats:
        print(json.dumps(st.stats(), ensure_ascii=False, indent=2))
        return 0
    hit = None
    if args.ip:
        hit = st.lookup_ip(args.ip)
    if args.domain:
        hit = st.lookup_domain(args.domain)
    if args.hsh:
        hit = st.lookup_hash(args.hsh)
    if not (args.ip or args.domain or args.hsh):
        ap.print_help()
        return 1
    print(json.dumps({"matched": bool(hit), "detail": hit}, ensure_ascii=False))
    return 0 if hit is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
