#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则检测/build_match_buffers.py 的单元测试（纯标准库，可在任意环境运行）。

覆盖 V-12（R-03 根治）：
  * canonical_buffer 精确整串匹配 —— http.uri.raw 不再被前缀塌缩成 http.uri；
  * 未登记 dotted 名 → None（不再静默放行），且 classify 会打 warning；
  * ALIASES / DOTTED 与共享真源 xbits/testdata/buffer_aliases.json 一致；
  * 共享真源里的规范名闭包自洽（canonical 值本身也能查到，http.status/http.status_msg 例外按字面规范名）。

运行：
    python3 规则检测/tests/test_build_match_buffers.py
或：
    python3 -m unittest 规则检测.tests.test_build_match_buffers -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "规则检测" / "build_match_buffers.py"
SHARED_ALIASES = ROOT / "xbits" / "testdata" / "buffer_aliases.json"

_spec = importlib.util.spec_from_file_location("build_match_buffers", MODULE_PATH)
bmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bmb)


def classify_quiet(rule: str) -> dict:
    """跑 classify 并吞掉 stderr（warning 行为单独用 capture 断言）。"""
    with contextlib.redirect_stderr(io.StringIO()):
        return bmb.classify(rule)


def classify_capture(rule: str) -> tuple[dict, str]:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        result = bmb.classify(rule)
    return result, buf.getvalue()


class CanonicalBufferTests(unittest.TestCase):
    def test_http_uri_raw_is_not_collapsed(self) -> None:
        # V-12 核心断言：dotted raw URI 必须保持 raw（安全语义，禁止归一化近似）
        self.assertEqual(bmb.canonical_buffer("http.uri.raw"), "http.uri.raw")

    def test_http_uri_stays_normalized(self) -> None:
        self.assertEqual(bmb.canonical_buffer("http.uri"), "http.uri")

    def test_underscore_aliases_unchanged(self) -> None:
        self.assertEqual(bmb.canonical_buffer("http_uri"), "http.uri")
        self.assertEqual(bmb.canonical_buffer("http_raw_uri"), "http.uri.raw")
        self.assertEqual(bmb.canonical_buffer("http_header"), "http.header")
        self.assertEqual(bmb.canonical_buffer("http_raw_header"), "http.header")
        self.assertEqual(bmb.canonical_buffer("file_data"), "file.data")
        self.assertEqual(bmb.canonical_buffer("dns_query"), "dns.query")
        self.assertEqual(bmb.canonical_buffer("http_stat_code"), "http.status")

    def test_registered_dotted_names_resolve_exactly(self) -> None:
        for name in (
            "http.uri.query",
            "http.request_header",
            "http.response_header",
            "http.headers",
            "http.stat_code",
            "dns.queries.rrname",
            "dns.rrtype",
            "tls.sni",
            "tls.alpn",
        ):
            self.assertIsNotNone(bmb.canonical_buffer(name), name)

    def test_unknown_dotted_name_returns_none(self) -> None:
        # 不再静默放行：未登记的 dotted 名必须返回 None（由调用方记 warning）
        self.assertIsNone(bmb.canonical_buffer("http.urix"))
        self.assertIsNone(bmb.canonical_buffer("http.uri.raw.query"))
        self.assertIsNone(bmb.canonical_buffer("http.unknown_thing"))

    def test_match_keywords_are_not_buffers(self) -> None:
        self.assertIsNone(bmb.canonical_buffer("content"))
        self.assertIsNone(bmb.canonical_buffer("pcre"))
        self.assertIsNone(bmb.canonical_buffer("msg"))

    def test_reserved_names_pass_through(self) -> None:
        self.assertEqual(bmb.canonical_buffer("payload"), "payload")
        self.assertEqual(bmb.canonical_buffer("stream"), "stream")
        self.assertEqual(bmb.canonical_buffer("lua"), "lua")


class ClassifyTests(unittest.TestCase):
    def test_dotted_raw_rule_keeps_raw_primary(self) -> None:
        # 自研场景规则（9103001 形态）：http.uri.raw; bsize:>0; lua:...;
        info = classify_quiet(
            "alert http any any -> any any ( http.uri.raw; bsize:>0; lua:web_sqli.lua; "
            "sid:9103001;)"
        )
        self.assertEqual(info["buffers"], ["http.uri.raw"])
        self.assertEqual(info["primary"], "http.uri.raw")
        self.assertFalse(info["app_tx_lua"])

    def test_underscore_raw_rule_keeps_raw_primary(self) -> None:
        info = classify_quiet(
            "alert tcp any any -> any any ( http_raw_uri; pcre:/x/i; sid:11020030;)"
        )
        self.assertEqual(info["buffers"], ["http.uri.raw"])
        self.assertEqual(info["primary"], "http.uri.raw")

    def test_normalized_uri_rule_stays_uri(self) -> None:
        info = classify_quiet(
            "alert tcp any any -> any any ( http_uri; content:\"select\"; nocase; sid:14010001;)"
        )
        self.assertEqual(info["buffers"], ["http.uri"])
        self.assertEqual(info["primary"], "http.uri")

    def test_mixed_uri_and_raw_keeps_both(self) -> None:
        info = classify_quiet(
            "alert tcp any any -> any any ( http_uri; content:\".jsp\"; nocase; "
            "http_raw_uri; pcre:/x/i; sid:11020687;)"
        )
        self.assertEqual(sorted(info["buffers"]), ["http.uri", "http.uri.raw"])

    def test_unknown_dotted_name_warns_and_is_ignored(self) -> None:
        info, warning = classify_capture(
            "alert tcp any any -> any any ( http.definitely_not_a_buffer; "
            "content:\"x\"; sid:123456;)"
        )
        self.assertIn("http.definitely_not_a_buffer", warning)
        self.assertIn("unknown dotted buffer name", warning)
        # 未知 buffer 不进 buffers：有 content → 只算 payload 规则
        self.assertEqual(info["buffers"], ["payload"])
        self.assertTrue(info["has_payload"])

    def test_unknown_dotted_name_without_match_keywords(self) -> None:
        info, warning = classify_capture(
            "alert tcp any any -> any any ( http.definitely_not_a_buffer; sid:123457;)"
        )
        self.assertIn("unknown dotted buffer name", warning)
        self.assertEqual(info["buffers"], [])


class SharedAliasesContractTests(unittest.TestCase):
    """xbits/src/analysis.rs 的单测读同一份 JSON 做集合相等断言（单一真源）。"""

    def test_shared_file_exists_and_matches_tables(self) -> None:
        self.assertTrue(SHARED_ALIASES.exists(), f"missing {SHARED_ALIASES}")
        data = json.loads(SHARED_ALIASES.read_text(encoding="utf-8"))
        merged = dict(bmb.ALIASES)
        merged.update(bmb.DOTTED)
        self.assertEqual(data["aliases"], merged)

    def test_critical_entries(self) -> None:
        data = json.loads(SHARED_ALIASES.read_text(encoding="utf-8"))
        aliases = data["aliases"]
        self.assertEqual(aliases["http.uri.raw"], "http.uri.raw")
        self.assertEqual(aliases["http.uri"], "http.uri")
        self.assertEqual(aliases["http_raw_uri"], "http.uri.raw")
        self.assertEqual(aliases["http_uri"], "http.uri")

    def test_canonical_targets_are_registered_names(self) -> None:
        data = json.loads(SHARED_ALIASES.read_text(encoding="utf-8"))
        aliases = data["aliases"]
        # 每个规范名要么自身也是键（可继续查表），要么是字面规范名（http.status / http.status_msg）
        for target in aliases.values():
            self.assertTrue(
                target in aliases or target in {"http.status", "http.status_msg"},
                f"canonical target {target!r} is neither a key nor a literal canonical name",
            )

    def test_no_value_collapses_raw_to_normalized(self) -> None:
        # raw→归一化塌缩仅允许"值域同源"豁免（Suricata/xbits 双侧约定一致，非近似）：
        #   http_raw_cookie → http.cookie（Suricata 对 raw cookie 只暴露归一化 http.cookie；CI 失败根因）
        #   http_raw_header → http.header、http.header.raw → http.header
        #   http_raw_host   → http.host、http.host.raw   → http.host
        # 这些对在 xbits 侧共用同一 canonical（analysis.rs canonical_buffer_name 同表），
        # raw 与归一化值域相同；而 http_raw_uri / http.uri.raw 必须保 raw（安全语义，
        # xbits 对 http.uri.raw 明令禁止归一化兜底——CONTEXT_ONLY_BUFFERS）。
        RAW_PRESERVING_EXEMPT = {
            "http_raw_cookie", "http_raw_header", "http_raw_host",
            "http.header.raw", "http.host.raw",
        }
        data = json.loads(SHARED_ALIASES.read_text(encoding="utf-8"))
        for source, target in data["aliases"].items():
            if "raw" in source and source not in RAW_PRESERVING_EXEMPT:
                self.assertIn("raw", target, f"{source} -> {target} collapses raw semantics")
        # 共享表里发生的每一处塌缩都必须在豁免清单里（新增塌缩需审核）；
        # 清单中的名字若当前表未登记不算失败（表随规则链重生成可演进）。
        collapsed = {
            source for source, target in data["aliases"].items()
            if "raw" in source and "raw" not in target
        }
        self.assertTrue(
            collapsed <= RAW_PRESERVING_EXEMPT,
            f"undocumented raw collapses: {sorted(collapsed - RAW_PRESERVING_EXEMPT)}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
