#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""triage/triage.py 的单元测试（纯标准库，可在任意环境运行）。

运行：
    python3 triage/tests/test_triage.py
或：
    python3 -m unittest triage.tests.test_triage -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from triage.triage import analyze  # noqa: E402

TRIAGE = ROOT / "triage" / "triage.py"


def write_tmp(dirpath: str, name: str, data: bytes) -> str:
    p = os.path.join(dirpath, name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


class TriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="xbits-triage-")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_php_webshell_is_malicious(self) -> None:
        sample = b"<?php\n@eval($_POST['cmd']);\nsystem($_GET['x']);\n?>\n"
        path = write_tmp(self.tmp, "shell.php", sample)
        r = analyze(path)
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"]["category"], "script")
        self.assertIn(r["verdict"], ("malicious", "suspicious"))
        self.assertGreaterEqual(r["score"], 55)
        ids = {f["id"] for f in r["findings"]}
        self.assertTrue({"php.eval", "php.system_exec"} & ids)
        self.assertEqual(r["file"]["sha256"], r["file"]["sha256"].lower())
        self.assertEqual(len(r["file"]["sha256"]), 64)

    def test_jsp_shell_detected(self) -> None:
        sample = (b"<%@ page import=\"java.util.*\" %>"
                  b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>")
        path = write_tmp(self.tmp, "shell.jsp", sample)
        r = analyze(path)
        self.assertEqual(r["type"]["category"], "script")
        self.assertIn(r["verdict"], ("malicious", "suspicious"))
        self.assertTrue(any(f["id"].startswith("java.") for f in r["findings"]))

    def test_benign_text_is_clean(self) -> None:
        path = write_tmp(self.tmp, "readme.txt", b"hello world\nthis is a benign note\n")
        r = analyze(path)
        self.assertEqual(r["type"]["category"], "text")
        self.assertEqual(r["verdict"], "clean")
        self.assertEqual(r["score"], 0)

    def test_elf_binary_detected(self) -> None:
        # 伪 ELF 头 + 一些高熵字节
        data = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 32
        path = write_tmp(self.tmp, "sample.bin", data)
        r = analyze(path)
        self.assertEqual(r["type"]["category"], "binary")
        self.assertIn("ELF", r["type"]["magic"])

    def test_pdf_javascript_flagged(self) -> None:
        data = b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
        path = write_tmp(self.tmp, "doc.pdf", data)
        r = analyze(path)
        self.assertEqual(r["type"]["category"], "document")
        self.assertTrue(any(f["id"].startswith("pdf.") for f in r["findings"]))
        self.assertIn(r["verdict"], ("suspicious", "malicious"))

    def test_missing_file_reports_error(self) -> None:
        r = analyze(os.path.join(self.tmp, "nope.bin"))
        self.assertFalse(r["ok"])
        self.assertIn("error", r)

    def test_cli_stdin_contract(self) -> None:
        sample = b"<?php eval($_POST['c']); ?>"
        path = write_tmp(self.tmp, "x.php", sample)
        proc = subprocess.run(
            [sys.executable, str(TRIAGE), "--stdin"],
            input=json.dumps({"path": path, "sid": 123}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertTrue(out["ok"])
        self.assertEqual(out["context"]["sid"], 123)

    def test_cli_positional(self) -> None:
        path = write_tmp(self.tmp, "a.txt", b"just some text\n")
        proc = subprocess.run(
            [sys.executable, str(TRIAGE), path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["type"]["category"], "text")

    # ---- 可选组件软接入：无论是否安装都不能崩，且 engines/info 结构齐全 ----
    def test_pe_input_no_crash_and_engines_reported(self) -> None:
        # 伪 PE（MZ 头 + 随机体）：pefile 存在则解析失败需优雅降级，不存在则跳过
        data = b"MZ" + b"\x00" * 64 + bytes(range(256)) * 8
        path = write_tmp(self.tmp, "sample.exe", data)
        r = analyze(path)
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"]["category"], "binary")
        self.assertIn("pefile", r["engines"])  # 无论装没装都要如实回显
        self.assertIn("info", r)
        self.assertIsInstance(r["findings"], list)

    def test_elf_input_no_crash_and_engines_reported(self) -> None:
        data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64 + bytes(range(256)) * 4
        path = write_tmp(self.tmp, "sample.elf", data)
        r = analyze(path)
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"]["category"], "binary")
        self.assertIn("pyelftools", r["engines"])

    def test_external_engines_off_by_default(self) -> None:
        path = write_tmp(self.tmp, "x.bin", b"MZ" + b"\x00" * 32)
        r = analyze(path)  # 不传 opts
        for tool in ("capa", "clamav", "semgrep", "binwalk"):
            self.assertIn(tool, r["engines"])
            self.assertFalse(r["engines"][tool], f"{tool} 默认应为 False（未显式开启）")

    def test_all_engines_flag_does_not_crash_without_tools(self) -> None:
        path = write_tmp(self.tmp, "x.txt", b"hello\n")
        r = analyze(path, opts={"all_engines": True})
        self.assertTrue(r["ok"])

    def test_fuzzy_hash_keys_present(self) -> None:
        path = write_tmp(self.tmp, "y.bin", b"binary-ish content" + bytes(range(64)))
        r = analyze(path)
        self.assertIn("ssdeep", r["engines"])
        self.assertIn("tlsh", r["engines"])

    def test_hash_intel_local_match_marks_malicious(self) -> None:
        data = b"\x7fELF\x02\x01\x01\x00 suspicious payload"
        path = write_tmp(self.tmp, "z.bin", data)
        import hashlib
        sha = hashlib.sha256(data).hexdigest()
        intel = os.path.join(self.tmp, "intel.txt")
        with open(intel, "w", encoding="utf-8") as fh:
            fh.write("# known bad\n" + sha + "\n")
        r = analyze(path, opts={"hash_intel": intel})
        self.assertEqual(r["verdict"], "malicious")
        self.assertTrue(any(f["id"] == "intel.known_bad" for f in r["findings"]))

    # ---- R1：hash 情报单一判定来源（xbits 传入 vs 独立 CLI） ----
    def test_payload_intel_is_single_conclusion_not_double_counted(self) -> None:
        """payload 同时带 md5+sha256 命中、且本地名单也判黑时，仍只产出一条 intel 结论、只计一次分。"""
        import hashlib
        data = b"hello intel note\n"
        path = write_tmp(self.tmp, "note.txt", data)
        md5 = hashlib.md5(data).hexdigest()
        sha = hashlib.sha256(data).hexdigest()
        local_intel = os.path.join(self.tmp, "file_hash.txt")
        with open(local_intel, "w", encoding="utf-8") as fh:
            fh.write(md5 + "\n" + sha + "\n")

        base = analyze(path, opts={"orchestrated": True})["score"]
        r = analyze(path, opts={
            "orchestrated": True,
            "hash_intel": local_intel,  # 本应被 payload 情报覆盖、不得再读
            "payload_intel": {"threat": [{"type": "md5", "value": md5},
                                         {"type": "sha256", "value": sha}]},
        })
        intel_findings = [f for f in r["findings"] if f["id"] == "intel.known_bad"]
        self.assertEqual(len(intel_findings), 1, intel_findings)
        self.assertEqual(r["info"]["intel_source"], "xbits-payload")
        self.assertTrue(r["engines"]["hash_intel"]["hit"])
        # 计分只加一次 90，不因两条命中重复计分
        self.assertEqual(r["score"], min(100, base + 90))
        self.assertEqual(r["verdict"], "malicious")

    def test_xbits_path_does_not_read_local_intel_file(self) -> None:
        """stdin/orchestrated 且 payload 未带情报时，绝不读本地 file_hash.txt（以传入为准）。"""
        import hashlib
        import triage.triage as tmod

        data = b"another intel note\n"
        path = write_tmp(self.tmp, "note2.txt", data)
        sha = hashlib.sha256(data).hexdigest()
        # 造一个“仓库布局”，让默认路径指向一份含该 hash 的本地名单
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, "triage"), exist_ok=True)
        os.makedirs(os.path.join(repo, "threat-intel", "data"), exist_ok=True)
        with open(os.path.join(repo, "threat-intel", "data", "file_hash.txt"), "w", encoding="utf-8") as fh:
            fh.write(sha + "\n")
        old = tmod._SCRIPT_DIR
        tmod._SCRIPT_DIR = os.path.join(repo, "triage")
        try:
            # 独立 CLI：仍读本地名单 -> 命中
            standalone = analyze(path)
            self.assertEqual(standalone["info"]["intel_source"], "local-file")
            self.assertTrue(any(f["id"] == "intel.known_bad" for f in standalone["findings"]))
            # xbits 路径（orchestrated、payload 无情报）：不读盘 -> 无 intel 结论
            xbits_path = analyze(path, opts={"orchestrated": True})
            self.assertEqual(xbits_path["info"]["intel_source"], "xbits-payload(none)")
            self.assertFalse(any(f["id"] == "intel.known_bad" for f in xbits_path["findings"]))
        finally:
            tmod._SCRIPT_DIR = old

    def test_cli_stdin_payload_intel_single_conclusion(self) -> None:
        """端到端：--stdin payload 携带 known-bad hash 时输出只有一份 intel 结论。"""
        import hashlib
        data = b"cli payload intel\n"
        path = write_tmp(self.tmp, "cli.txt", data)
        sha = hashlib.sha256(data).hexdigest()

        def run(payload: dict) -> dict:
            proc = subprocess.run(
                [sys.executable, str(TRIAGE), "--stdin"],
                input=json.dumps(payload),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)

        with_intel = run({"path": path, "sha256": sha,
                          "intel": {"threat": [{"type": "sha256", "value": sha}]}})
        intel_findings = [f for f in with_intel["findings"] if f["id"] == "intel.known_bad"]
        self.assertEqual(len(intel_findings), 1, intel_findings)
        self.assertEqual(with_intel["info"]["intel_source"], "xbits-payload")
        self.assertEqual(with_intel["verdict"], "malicious")
        self.assertEqual(with_intel["score"], 90)

        without_intel = run({"path": path, "sha256": sha})
        self.assertEqual(without_intel["info"]["intel_source"], "xbits-payload(none)")
        self.assertFalse(any(f["id"] == "intel.known_bad" for f in without_intel["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
