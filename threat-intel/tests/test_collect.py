#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-21 collect.py 自测：源失败/阈值/原子写回滚/未实现类型/配置驱动。

全部用本地 fixture + mock getter，不联网、不跑 CI。
运行：python -m unittest discover -s threat-intel/tests -v
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
MODULE_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(MODULE_ROOT / "tools"))
import collect  # noqa: E402

OLD_TIME = "2026-01-01 00:00:00Z"
NEW_TIME = "2026-11-21 00:00:00Z"
DATA_NAMES = ("md5.txt", "sha1.txt", "sha256.txt", "ip.txt", "domain.txt", "file_hash.txt", "meta.json")
SURI_NAMES = ("iprep.list", "iprep-categories.txt",
              "datasets/md5.txt", "datasets/sha1.txt", "datasets/sha256.txt", "datasets/domain.txt")


def args() -> argparse.Namespace:
    return argparse.Namespace(since=None, domain_max=50000)


def iplist_cfg(limit: int = 10, name: str = "feodo-tracker") -> dict:
    return {"sources": [{
        "name": name, "enabled": True, "type": "abusech-iplist",
        "url": "https://example.test/ipblocklist.txt",
        "options": {"min_fetched": limit},
    }]}


def ip_getter(n: int = 12, code: int = 200):
    body = ("# header\n" + "\n".join(f"198.51.100.{i}" for i in range(1, n + 1)) + "\n").encode()

    def getter(url: str, timeout: int = 20):
        return body, code

    return getter


class CollectV21Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="collect-v21-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.data = root / "data"
        self.suri = root / "exports" / "suricata"
        self.local = root / "local"
        self.data.mkdir()
        self.suri.mkdir(parents=True)
        self.local.mkdir()
        for name in DATA_NAMES[:-1]:
            (self.data / name).write_text(f"old-{name}\n", encoding="utf-8")
        old_meta = {
            "collected_utc": OLD_TIME, "last_success_utc": OLD_TIME,
            "counts": {"md5": 0, "sha1": 0, "sha256": 0, "ip": 0, "domain": 0},
            "sources": {"feodo-tracker": {"status": "ok", "last_success_utc": OLD_TIME, "ips": 11474}},
        }
        (self.data / "meta.json").write_text(json.dumps(old_meta), encoding="utf-8")
        for name in SURI_NAMES:
            p = self.suri / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"old-{name}\n", encoding="utf-8")
        self.attempt = root / "attempt.json"

    def snapshot(self) -> dict[str, str]:
        snap = {}
        for base, names in ((self.data, DATA_NAMES), (self.suri, SURI_NAMES)):
            for name in names:
                p = base / name
                snap[str(p.relative_to(self.data.parent if base == self.data else self.suri.parent.parent))] = (
                    p.read_text(encoding="utf-8") if p.is_file() else "<MISSING>")
        return snap

    def run_collect(self, cfg, getter, now: str = NEW_TIME, **kwargs):
        return collect.collect_once(
            cfg, args(), getter=getter,
            data_dir=str(self.data), suri_dir=str(self.suri), local_dir=str(self.local),
            attempt_path=str(self.attempt), now=now, **kwargs)

    # ① 某源 HTTP 500 → 非零退出 + 旧 data 未变 + 失败写入 attempt 记录
    def test_http_500_keeps_old_snapshot_and_records_failure(self):
        before = self.snapshot()

        def failing(url, timeout=20):
            raise collect.FetchError(f"HTTP 500 for {url}", 500)

        rc = self.run_collect(iplist_cfg(), failing)
        self.assertNotEqual(rc, 0, "HTTP 500 必须非零退出")
        self.assertEqual(self.snapshot(), before, "失败不得触碰任何 data/exports 文件")
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["failed_sources"], ["feodo-tracker"])
        src = attempt["sources"]["feodo-tracker"]
        self.assertEqual(src["status"], "failed")
        self.assertEqual(src["http_code"], 500)
        self.assertIn("HTTP 500", src["error"])
        self.assertEqual(src["last_success_utc"], OLD_TIME)
        self.assertEqual(attempt["last_success_utc"], OLD_TIME, "失败不得推进 last_success_utc")
        meta = json.loads((self.data / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["last_success_utc"], OLD_TIME)

    # ② 产出低于阈值 → 失败
    def test_below_threshold_is_failure(self):
        before = self.snapshot()
        rc = self.run_collect(iplist_cfg(limit=10), ip_getter(n=3))
        self.assertNotEqual(rc, 0, "3 条 < 阈值 10 必须失败")
        self.assertEqual(self.snapshot(), before)
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        src = attempt["sources"]["feodo-tracker"]
        self.assertEqual(src["status"], "failed")
        self.assertEqual(src["fetched"], 3)
        self.assertIn("最小阈值 10", src["error"])

    # ③ 全成功 → 原子替换 + last_success 更新 + meta.sources 结构
    def test_all_success_atomic_replace_and_last_success(self):
        rc = self.run_collect(iplist_cfg(limit=10), ip_getter(n=12))
        self.assertEqual(rc, 0, "全源达标应成功")
        lines = (self.data / "ip.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 12)
        self.assertEqual(lines[0], "198.51.100.1")
        meta = json.loads((self.data / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["last_success_utc"], NEW_TIME)
        self.assertEqual(meta["collected_utc"], NEW_TIME)
        self.assertEqual(meta["counts"]["ip"], 12)
        self.assertEqual(meta["sources"]["feodo-tracker"]["status"], "ok")
        self.assertTrue(meta["sources"]["feodo-tracker"]["ok"])
        self.assertEqual(meta["sources"]["feodo-tracker"]["fetched"], 12)
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        self.assertEqual(attempt["status"], "success")
        self.assertEqual(attempt["failed_sources"], [])
        suri_lines = (self.suri / "iprep.list").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(suri_lines), 12)

    # ③b 替换阶段中途失败 → 从备份回滚，旧快照保持原样
    def test_replace_failure_rolls_back(self):
        before = self.snapshot()
        original_replace = collect.os.replace
        state = {"tripped": False}

        def flaky(src, dst):
            if not state["tripped"] and str(dst).endswith("ip.txt"):
                state["tripped"] = True
                raise OSError("simulated replace failure")
            return original_replace(src, dst)

        collect.os.replace = flaky
        try:
            rc = self.run_collect(iplist_cfg(limit=10), ip_getter(n=12))
        finally:
            collect.os.replace = original_replace
        self.assertEqual(rc, 2, "写阶段失败必须以独立非零码退出")
        self.assertTrue(state["tripped"], "测试必须真的触发一次替换失败")
        self.assertEqual(self.snapshot(), before, "中途失败必须回滚到替换前的快照")
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        self.assertEqual(attempt["status"], "failed")
        self.assertIn("回滚", attempt["note"])

    # ④ enabled 且 type 未实现 → 非零
    def test_unimplemented_type_is_failure(self):
        before = self.snapshot()
        cfg = {"sources": [{
            "name": "malwarebazaar", "enabled": True, "type": "abusech-api",
            "options": {"min_fetched": 10},
        }]}
        rc = self.run_collect(cfg, ip_getter(n=12))
        self.assertNotEqual(rc, 0, "enabled 未实现类型必须失败")
        self.assertEqual(self.snapshot(), before)
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        src = attempt["sources"]["malwarebazaar"]
        self.assertEqual(src["status"], "failed")
        self.assertIn("unimplemented", src["error"])

    # ⑤ options 未知键 → 失败（配置不是装饰品）
    def test_unknown_option_is_failure(self):
        before = self.snapshot()
        cfg = iplist_cfg()
        cfg["sources"][0]["options"]["bogus_key"] = 1
        rc = self.run_collect(cfg, ip_getter(n=12))
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.snapshot(), before)
        attempt = json.loads(self.attempt.read_text(encoding="utf-8"))
        self.assertIn("未知键", attempt["sources"]["feodo-tracker"]["error"])

    # ⑥ to_ids 从 sources.json 读取，不再硬编码
    def test_to_ids_from_options(self):
        manifest = {"uuid-1": {"date": "2026-01-01", "info": "malware sample", "Tag": [{"name": "malware"}]}}
        event = {"Event": {"Attribute": [
            {"type": "md5", "value": "a" * 32, "to_ids": True},
            {"type": "md5", "value": "b" * 32, "to_ids": False},
            {"type": "ip-dst", "value": "203.0.113.9", "to_ids": False},
        ]}}

        def circl_getter(url, timeout=20):
            body = json.dumps(manifest if url.endswith("manifest.json") else event).encode()
            return body, 200

        src = {"name": "circl", "type": "circl-misp-feed", "url_base": "https://example.test/"}
        result_true = collect.src_circl_misp_feed(
            {**src, "options": {"to_ids": True, "malware_only": True}}, collect.new_store(), args(), circl_getter)
        self.assertTrue(result_true.ok)
        self.assertEqual(result_true.fetched, 1, "to_ids=true 只收 to_ids 属性")
        result_false = collect.src_circl_misp_feed(
            {**src, "options": {"to_ids": False, "malware_only": True}}, collect.new_store(), args(), circl_getter)
        self.assertEqual(result_false.fetched, 3, "to_ids=false 收全部非 deleted 属性")
        bad = collect.src_circl_misp_feed(
            {**src, "options": {"to_ids": "yes"}}, collect.new_store(), args(), circl_getter)
        self.assertFalse(bad.ok)
        self.assertIn("to_ids 必须是", bad.error)

    # ⑦ SourceResult 契约字段齐全
    def test_source_result_contract(self):
        r = collect.SourceResult(ok=False, fetched=3, http_code=500, error="HTTP 500", last_success_utc=OLD_TIME)
        m = r.to_meta()
        for key in ("ok", "fetched", "http_code", "error", "last_success_utc", "status"):
            self.assertIn(key, m)
        self.assertEqual(m["status"], "failed")
        self.assertEqual(m["http_code"], 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
