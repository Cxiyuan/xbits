#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 工具单测：canonical_ip 单一归一化（V-23）+ 三端一致性。

运行（纯标准库，任意环境）：
    python3 allowlist/tests/test_allowlist.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "allowlist" / "tools"))

from ipnorm import canonical_ip  # noqa: E402
import add as add_mod  # noqa: E402
import refresh as refresh_mod  # noqa: E402
import query as query_mod  # noqa: E402


class CanonicalIpTests(unittest.TestCase):
    """canonical_ip 本体：IPv4/IPv6 规范化、大小写、::压缩、zone 拒绝。"""

    def test_ipv4_unchanged(self):
        self.assertEqual(canonical_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(canonical_ip(" 8.8.8.8 "), "8.8.8.8")

    def test_ipv6_compressed(self):
        # ::压缩：同一地址的多种写法必须归一到同一个规范串
        variants = ["2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001",
                    "2001:DB8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::0:1"]
        norm = {canonical_ip(v) for v in variants}
        self.assertEqual(len(norm), 1, f"IPv6 各写法应归一为同一表示: {sorted(norm)}")
        self.assertEqual(norm.pop(), "2001:db8::1")

    def test_ipv6_lowercase_and_v4_mapped(self):
        self.assertEqual(canonical_ip("::FFFF:192.0.2.1"), "::ffff:192.0.2.1")  # python ipaddress 保留 v4-mapped 点分
        self.assertEqual(canonical_ip("FE80::1A2B:3C4D"), "fe80::1a2b:3c4d")

    def test_zone_rejected(self):
        self.assertIsNone(canonical_ip("fe80::1%eth0"))
        self.assertIsNone(canonical_ip("fe80::1%25eth0"))

    def test_invalid_rejected(self):
        for bad in ("", "not-an-ip", "999.1.1.1", "2001:db8::zz", "1.2.3", ":::", None):
            self.assertIsNone(canonical_ip(bad), f"{bad!r} 应判为非法")


class CrossToolConsistencyTests(unittest.TestCase):
    """同一输入在三端（add.validate / refresh.norm_ip / query.lookup_ip）必须同形。"""

    def test_three_layers_agree_on_ipv6(self):
        raw = "2001:0DB8::0001"
        c = canonical_ip(raw)
        self.assertEqual(c, "2001:db8::1")
        # add 写入侧
        self.assertEqual(add_mod.validate("ip", raw), c)
        self.assertEqual(add_mod.validate("public_dns", raw), c)
        # refresh 归一化侧
        self.assertEqual(refresh_mod.norm_ip(raw), c)
        # query 加载侧：写进快照的行也能被归一回来
        self.assertEqual(refresh_mod.norm_ip(c), c)

    def test_end_to_end_lookup_ipv6(self):
        """add 压缩式写入 → data 快照 → query 查询原文/展开式，都必须命中。"""
        tmp = tempfile.mkdtemp(prefix="xbits-allowlist-")
        try:
            os.makedirs(os.path.join(tmp, "data"))
            with open(os.path.join(tmp, "data", "ip.txt"), "w", encoding="utf-8") as fh:
                fh.write("2001:db8::1\n8.8.8.8\n")
            st = query_mod.AllowlistStore(os.path.join(tmp, "data"))
            # 原文压缩式
            self.assertIsNotNone(st.lookup_ip("2001:db8::1"))
            # 大写 / 展开式（旧 add.py 的压缩、旧 refresh.py 的 exploded 都能命中）
            self.assertIsNotNone(st.lookup_ip("2001:DB8::1"))
            self.assertIsNotNone(st.lookup_ip("2001:0db8:0000:0000:0000:0000:0000:0001"))
            # zone 拒绝
            self.assertIsNone(st.lookup_ip("fe80::1%eth0"))
            # IPv4 正/负例
            self.assertIsNotNone(st.lookup_ip("8.8.8.8"))
            self.assertIsNone(st.lookup_ip("9.9.9.9"))
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_refresh_rejects_zone_entry_as_bad_line(self):
        """refresh 对 zone id 行按非法条目处理（fail fast），不会把同址条目写进快照。"""
        tmp = tempfile.mkdtemp(prefix="xbits-allowlist-")
        try:
            os.makedirs(os.path.join(tmp, "custom"))
            with open(os.path.join(tmp, "custom", "ip.txt"), "w", encoding="utf-8") as fh:
                fh.write("2001:db8::1\nfe80::1%eth0\n8.8.8.8\n")
            vals, bad = refresh_mod.read_custom("ip.txt", "ip", custom_dir=os.path.join(tmp, "custom"))
            self.assertEqual(vals, ["2001:db8::1", "8.8.8.8"])
            self.assertEqual(len(bad), 1, bad)
            self.assertIn("fe80::1%eth0", bad[0])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
