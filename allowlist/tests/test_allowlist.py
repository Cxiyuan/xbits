#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 工具单测：canonical_ip 单一归一化（V-23）+ 三端一致性。

运行（纯标准库，任意环境）：
    python3 allowlist/tests/test_allowlist.py
"""
from __future__ import annotations

import json
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


class V22SemanticSeparationTests(unittest.TestCase):
    """V-22：ip.txt / public_dns.txt 语义正交、sources.json 唯一真源、--check 真比对。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="xbits-allowlist-v22-")
        self.custom = os.path.join(self.tmp, "custom")
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.custom)
        os.makedirs(self.data)
        self.sources = os.path.join(self.tmp, "sources.json")
        # 预建 sources.json 会声明的 custom 文件（缺失是配置错误，见 test_missing_declared_source_is_failure）
        for fname in ("white_domains.txt", "domain.txt", "ip.txt", "public_dns_servers.txt"):
            with open(os.path.join(self.custom, fname), "w", encoding="utf-8") as fh:
                fh.write("")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_sources(self, sources: list[dict]) -> None:
        with open(self.sources, "w", encoding="utf-8") as fh:
            json.dump({"sources": sources}, fh, ensure_ascii=False, indent=2)

    def standard_sources(self) -> list[dict]:
        return [
            {"name": "custom-ips", "enabled": True, "type": "static-ip-list",
             "path": "custom/ip.txt", "output": "ip.txt", "kind": "ip", "options": {}},
            {"name": "public-dns-servers", "enabled": True, "type": "static-ip-list",
             "path": "custom/public_dns_servers.txt", "output": "public_dns.txt", "kind": "ip", "options": {}},
            {"name": "custom-domains", "enabled": True, "type": "static-domain-list",
             "path": "custom/domain.txt", "output": "domain.txt", "kind": "domain", "options": {}},
        ]

    def run_refresh(self, *, check: bool = False) -> int:
        argv = ["--sources", self.sources, "--custom-dir", self.custom, "--data-dir", self.data]
        if check:
            argv.append("--check")
        return refresh_mod.main(argv)

    def test_public_dns_not_in_ip_txt(self):
        """① public_dns_servers.txt 的 IP 只进 public_dns.txt，绝不反向并入 ip.txt。"""
        self.write_sources(self.standard_sources())
        with open(os.path.join(self.custom, "public_dns_servers.txt"), "w", encoding="utf-8") as fh:
            fh.write("8.8.8.8\n2001:db8::53\n")
        with open(os.path.join(self.custom, "ip.txt"), "w", encoding="utf-8") as fh:
            fh.write("203.0.113.10\n")
        self.assertEqual(self.run_refresh(), 0)

        def read(name):
            with open(os.path.join(self.data, name), encoding="utf-8") as fh:
                return [x.strip() for x in fh if x.strip()]

        ip_lines, dns_lines = read("ip.txt"), read("public_dns.txt")
        self.assertEqual(ip_lines, ["203.0.113.10"], "ip.txt 只应含通用白名单 IP")
        self.assertEqual(set(dns_lines), {"8.8.8.8", "2001:db8::53"})
        self.assertEqual(set(ip_lines) & set(dns_lines), set(), "两集合必须正交")
        with open(os.path.join(self.data, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual(meta["counts"], {"domain": 0, "ip": 1, "public_dns": 2})
        self.assertEqual(
            {(m["from"], m["to"]) for m in meta["source_map"]},
            {("custom/ip.txt", "ip.txt"), ("custom/public_dns_servers.txt", "public_dns.txt"),
             ("custom/domain.txt", "domain.txt")})
        self.assertIn("public_dns", meta["semantics"]["public_dns.txt"])

    def test_check_detects_snapshot_drift(self):
        """② --check 在 data/ 与 custom/ 推导结果不一致时非零退出并打印差异。"""
        self.write_sources(self.standard_sources())
        with open(os.path.join(self.custom, "ip.txt"), "w", encoding="utf-8") as fh:
            fh.write("203.0.113.10\n")
        self.assertEqual(self.run_refresh(), 0)
        # 篡改快照：加一条 data/ 里不该有的 IP，并删掉应有的一条
        with open(os.path.join(self.data, "ip.txt"), "w", encoding="utf-8") as fh:
            fh.write("198.51.100.99\n")
        self.assertNotEqual(self.run_refresh(check=True), 0, "快照漂移必须非零退出")
        diffs = refresh_mod.check_snapshot(
            refresh_mod.build_outputs(refresh_mod.load_sources(self.sources), self.custom)[0],
            data_dir=self.data)
        self.assertTrue(any("ip.txt" in d for d in diffs), diffs)
        self.assertTrue(any("缺少" in d and "多余" in d for d in diffs), diffs)

    def test_unknown_source_type_rejected(self):
        """③ sources.json 出现未实现 type → 配置错误非零退出（不是静默忽略）。"""
        sources = self.standard_sources()
        sources[0]["type"] = "remote-magic-feed"
        self.write_sources(sources)
        with open(os.path.join(self.custom, "ip.txt"), "w", encoding="utf-8") as fh:
            fh.write("203.0.113.10\n")
        self.assertNotEqual(self.run_refresh(), 0)
        with self.assertRaises(ValueError) as ctx:
            refresh_mod.load_sources(self.sources)
        self.assertIn("未知 type", str(ctx.exception))

    def test_reverse_merge_blocked_by_config(self):
        """③b 即使有人把 public_dns 源声明成 ip.txt 的 output，也必须被拒绝。"""
        sources = self.standard_sources()
        sources[1]["output"] = "ip.txt"
        self.write_sources(sources)
        with self.assertRaises(ValueError) as ctx:
            refresh_mod.load_sources(self.sources)
        self.assertIn("反向并入", str(ctx.exception))

    def test_ipv6_public_dns_add_to_query_end_to_end(self):
        """④ 保持 V-23：add public_dns IPv6 → refresh → query(kind=public_dns) 命中。"""
        self.write_sources(self.standard_sources())
        old_add_custom = add_mod.CUSTOM_DIR
        old_argv = sys.argv
        try:
            add_mod.CUSTOM_DIR = self.custom
            sys.argv = ["add.py", "add", "public_dns", "2001:db8::1"]
            self.assertEqual(add_mod.main(), 0)
        finally:
            add_mod.CUSTOM_DIR = old_add_custom
            sys.argv = old_argv
        with open(os.path.join(self.custom, "public_dns_servers.txt"), encoding="utf-8") as fh:
            written = fh.read()
        self.assertIn("2001:db8::1", written)
        self.assertEqual(self.run_refresh(), 0)
        st = query_mod.AllowlistStore(self.data)
        self.assertIsNotNone(st.lookup_ip("2001:db8::1", kind="public_dns"))
        self.assertIsNotNone(st.lookup_ip("2001:0db8:0000:0000:0000:0000:0000:0001", kind="public_dns"))
        self.assertIsNone(st.lookup_ip("2001:db8::1", kind="ip"), "IPv6 DNS 基线不得出现在通用 ip.txt")

    def test_missing_declared_source_is_failure(self):
        """④ sources.json 声明的 custom 源缺失 → 非零退出（不静默当空）。"""
        self.write_sources(self.standard_sources())
        os.remove(os.path.join(self.custom, "ip.txt"))  # 删掉已声明的源文件
        with open(os.path.join(self.custom, "public_dns_servers.txt"), "w", encoding="utf-8") as fh:
            fh.write("8.8.8.8\n")
        rc = self.run_refresh()
        self.assertNotEqual(rc, 0, "声明为 enabled 的源文件缺失必须非零退出")
        # 也覆盖 --check 路径：缺失源 + 快照有不一致 → 非零
        self.assertNotEqual(self.run_refresh(check=True), 0)
        outputs, source_map, bad = refresh_mod.build_outputs(
            refresh_mod.load_sources(self.sources), self.custom)
        self.assertTrue(any("源文件缺失" in b for b in bad), bad)

    def test_missing_source_but_data_empty_still_fails(self):
        """④b 即便 data/ 恰好为空，只要声明源缺失也算配置不完整（防止空快照掩盖缺失源）。"""
        self.write_sources(self.standard_sources())
        os.remove(os.path.join(self.custom, "ip.txt"))
        self.assertNotEqual(self.run_refresh(), 0)


        """真实 sources.json 必须能被唯一真源加载（防止本地测试只喂合成配置）。"""
        entries = refresh_mod.load_sources()
        by_output: dict[str, list[str]] = {}
        for e in entries:
            by_output.setdefault(e["output"], []).append(e["path"])
        self.assertEqual(by_output.get("public_dns.txt"), ["custom/public_dns_servers.txt"])
        self.assertEqual(by_output.get("ip.txt"), ["custom/ip.txt"])
        self.assertIn("custom/white_domains.txt", by_output.get("domain.txt", []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
