#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""triage/triage.py 的单元测试（纯标准库，可在任意环境运行）。

运行：
    python3 triage/tests/test_triage.py
或：
    python3 -m unittest triage.tests.test_triage -v
"""
from __future__ import annotations

import importlib.util
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

EXPECT_ENHANCED = os.environ.get("XBITS_EXPECT_ENHANCED", "") == "1"


def setUpModule() -> None:
    """XBITS_EXPECT_ENHANCED=1 的步骤必须真的装上可选依赖，禁止静默降级（V-18/V-19）。"""
    if not EXPECT_ENHANCED:
        return
    missing = [m for m in ("pefile", "elftools", "yara") if importlib.util.find_spec(m) is None]
    if missing:
        raise RuntimeError(
            "XBITS_EXPECT_ENHANCED=1 但缺少可选依赖 %s；CI 增强步骤负责安装，"
            "缺依赖必须让该步骤失败，不允许降级为 skip" % missing
        )


def minimal_pe() -> bytes:
    """最小但合法的 PE32（i386、1 个 .text 节、无导入），pefile 能真正解析。

    真实 PE 样本不便入库，也不该依赖本机编译器；用结构化字节构造，保证
    "增强路径"能断言 Machine/Subsystem/sections 的值，而不是只断言键存在。
    """
    import struct

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0x00E0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32
    struct.pack_into("<B", opt, 2, 14)
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)  # BaseOfCode
    struct.pack_into("<I", opt, 24, 0x2000)  # BaseOfData
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<H", opt, 40, 4)
    struct.pack_into("<H", opt, 48, 4)
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem: console
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    sec = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020,
    )
    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec
    return head.ljust(0x200, b"\x00") + b"\x90" * 0x200


def minimal_elf() -> bytes:
    """最小但合法的 ELF64（x86-64 ET_EXEC，无节/段表），pyelftools 能解析。"""
    import struct

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    return ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0
    )


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

    # ---- 可选组件：断言"值"，不再只断言"键存在"（V-18 增强路径假绿） ----
    def test_pe_enhanced_path_asserts_parsed_fields(self) -> None:
        r = analyze(write_tmp(self.tmp, "min.exe", minimal_pe()))
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"]["category"], "binary")
        if importlib.util.find_spec("pefile") is None:
            self.assertFalse(r["engines"]["pefile"], "未装 pefile 时 engines['pefile'] 必须如实为 False")
            self.skipTest("pefile 未安装（stdlib 路径）；CI 增强步骤会用真实 PE 断言字段值")
        self.assertTrue(r["engines"]["pefile"], "pefile 已安装时必须解析成功")
        pe = r["info"].get("pe")
        self.assertIsNotNone(pe, f"pefile 可用却没有 info['pe']（pe_error={r['info'].get('pe_error')}）")
        self.assertEqual(pe["machine"], "IMAGE_FILE_MACHINE_I386")
        self.assertEqual(pe["subsystem"], 3)  # IMAGE_SUBSYSTEM_WINDOWS_CUI
        self.assertEqual([s["name"] for s in pe["sections"]], [".text"])
        self.assertEqual(pe["import_count"], 0)
        self.assertFalse(pe["signed"])
        self.assertFalse(pe["signed_present"])
        self.assertFalse(pe["signature_verified"])

    def test_external_engines_off_by_default(self) -> None:
        path = write_tmp(self.tmp, "x.bin", b"MZ" + b"\x00" * 32)
        r = analyze(path)  # 不传 opts
        for tool in ("capa", "clamav", "semgrep", "binwalk"):
            self.assertIn(tool, r["engines"])
            self.assertFalse(r["engines"][tool], f"{tool} 默认应为 False（未显式开启）")
            self.assertFalse(r["engine_status"][tool]["present"], "未启用时 present 必须 False")

    def test_pe_invalid_binary_degrades_gracefully(self) -> None:
        # 伪 PE：pefile 可用时必须优雅降级（pe_error），不得崩溃、不得假称已解析
        r = analyze(write_tmp(self.tmp, "fake.exe", b"MZ" + b"\x00" * 64 + b"junk" * 64))
        self.assertTrue(r["ok"])
        if not EXPECT_ENHANCED:
            self.skipTest("pefile 未安装（stdlib 路径）；增强步骤断言降级路径")
        self.assertFalse(r["engines"]["pefile"], "engines 摘要=present and ok；解析失败必须为 False")
        self.assertIsNone(r["info"].get("pe"))
        self.assertTrue(r["info"].get("pe_error"), "非法 PE 必须留下 pe_error，而不是静默当成功")
        st = r["engine_status"]["pefile"]
        self.assertTrue(st["present"] and not st["ok"], "解析失败必须 present=True, ok=False")
        self.assertTrue(st["error"], "解析失败必须带 error")

    def test_elf_enhanced_path_asserts_parsed_fields(self) -> None:
        r = analyze(write_tmp(self.tmp, "min.elf", minimal_elf()))
        self.assertTrue(r["ok"])
        self.assertEqual(r["type"]["category"], "binary")
        if importlib.util.find_spec("elftools") is None:
            self.assertFalse(r["engines"]["pyelftools"], "未装 pyelftools 时 engines['pyelftools'] 必须为 False")
            self.skipTest("pyelftools 未安装（stdlib 路径）；CI 增强步骤会用真实 ELF 断言字段值")
        self.assertTrue(r["engines"]["pyelftools"], "pyelftools 已安装时必须解析成功")
        elf = r["info"].get("elf")
        self.assertIsNotNone(elf, f"pyelftools 可用却没有 info['elf']（elf_error={r['info'].get('elf_error')}）")
        self.assertEqual(elf["machine"], "x64")
        self.assertEqual(elf["type"], "ET_EXEC")
        self.assertEqual(elf["entry"], hex(0x400000))
        self.assertTrue(elf["statically_linked"])

    # ---- V-20：engine_status 三态 + degraded（外部失败 ≠ 未检出） ----
    def test_engine_status_schema_and_backcompat_summary(self) -> None:
        """每个工具必须有 {present, ok, error} 结构化状态；engines[tool] 摘要 = present and ok。"""
        r = analyze(write_tmp(self.tmp, "x.txt", b"hello\n"))
        self.assertIn("engine_status", r)
        status = r["engine_status"]
        # 文本文件不触发的组件（capa/binwalk 只对 binary/archive 跑）也要有完整三态键
        for tool in ("capa", "clamav", "semgrep", "binwalk", "ssdeep", "tlsh", "yara"):
            self.assertIn(tool, status, f"{tool} 缺少 engine_status")
            st = status[tool]
            self.assertEqual(set(st.keys()), {"present", "ok", "error"}, st)
            self.assertIsInstance(st["present"], bool)
            self.assertIsInstance(st["ok"], bool)
            self.assertTrue(st["error"] is None or isinstance(st["error"], str))
            # 向后兼容摘要：engines[tool] == present and ok（capa/binwalk 未跑，engines 无键也允许）
            if tool in r["engines"]:
                self.assertEqual(r["engines"][tool], st["present"] and st["ok"],
                                 f"{tool}: engines 摘要与 engine_status 不一致")
        # 默认未显式开启外部命令 → present=False；not-applicable 也如实带原因；没有 degraded（未启用≠失败）
        for tool in ("capa", "clamav", "semgrep", "binwalk"):
            self.assertFalse(status[tool]["present"])
            if tool in ("capa", "binwalk"):
                self.assertIn("not-applicable", status[tool]["error"])
            else:
                self.assertIsNone(status[tool]["error"])
        self.assertFalse(r["degraded"])
        self.assertEqual(r["engine_errors"], {})

    def test_clamav_failure_is_degraded_not_clean(self) -> None:
        """clamscan rc=2（如病毒库缺失）必须记 error/degraded，不得当"已扫描且干净"。"""
        if os.name != "nt":
            self.skipTest("用 Windows cmd 造稳定 rc!=0 的假 clamscan")
        r = analyze(write_tmp(self.tmp, "z.bin", b"MZ" + b"\x00" * 32),
                    opts={"clamscan_cmd": "cmd /c exit 2"})
        st = r["engine_status"]["clamav"]
        self.assertTrue(st["present"])
        self.assertFalse(st["ok"])
        self.assertTrue(st["error"], "rc!=0 必须带 error 说明")
        self.assertTrue(r["degraded"], "引擎失败必须置 degraded=true")
        self.assertIn("clamav", r["engine_errors"])
        self.assertFalse(r["engines"]["clamav"], "engines 摘要在失败时必须为 False")

    def test_external_engine_true_only_after_real_success(self) -> None:
        """外部命令真实成功（rc=0）才允许 engines[..]=True（present and ok）。"""
        if os.name != "nt":
            self.skipTest("用 Windows cmd 造稳定 rc=0 的假 clamscan")
        r = analyze(write_tmp(self.tmp, "z2.bin", b"MZ" + b"\x00" * 32),
                    opts={"clamscan_cmd": "cmd /c exit 0"})
        st = r["engine_status"]["clamav"]
        self.assertTrue(st["present"] and st["ok"])
        self.assertTrue(r["engines"]["clamav"])
        self.assertIsNone(st["error"])
        # clamav 成功了；本例的二进制不是合法 PE，pefile 解析失败也计入 degraded——
        # 正是 V-20 要的语义：解析失败 ≠ "扫描过且干净"。
        self.assertIsNone(r["engine_errors"].get("clamav"))
        self.assertTrue(r["degraded"])
        self.assertIn("pefile", r["engine_errors"])

    # ---- V-22：签名降级只认 signature_verified，证书表存在不得洗白 ----
    def test_signed_present_never_dampens_high_evidence(self) -> None:
        """pe.inject_* 高置信证据 + 证书表存在（signature_verified=False）→ 不许洗白成 clean。"""
        pe = minimal_pe()
        # 在文件尾追加一段伪 Authenticode 证书表 blob（未验证、可伪造）
        blob = pe + b"\x00" * 8 + b"AUTHENTICODE-BLOB-ANYONE-CAN-APPEND" * 4
        r = analyze(write_tmp(self.tmp, "signed_suspicious.exe", blob))
        self.assertTrue(r["ok"])
        ids = {f["id"] for f in r["findings"]}
        pe_info = r["info"].get("pe", {})
        self.assertFalse(pe_info.get("signature_verified", False),
                         "triage 不做证书链校验，signature_verified 必须为 False")
        # 有高置信证据时 verdict 不得被压成 clean
        self.assertNotEqual(r["verdict"], "clean",
                            "证书表存在不得把 high/critical 证据洗白成 clean")
        self.assertNotIn("pe.signed_dampened", ids)

    def test_signed_dampening_only_on_verified(self) -> None:
        """降级路径只存在于 signature_verified=True（当前不可达）——静态保证不可被伪造利用。"""
        src = Path(ROOT / "triage" / "triage.py").read_text(encoding="utf-8")
        self.assertIn("signature_verified", src)
        # 降级分支必须以 signature_verified 为闸门
        self.assertLess(src.index("signature_verified = bool"), src.index("if signature_verified and not has_strong"))
        # signed_present 只作展示，不再参与降级判定
        self.assertNotIn('if signed and not has_strong', src)

    # ---- V-23（allowlist）：IPv6 归一化在 allowlist/tests/test_allowlist.py ----
    def test_allowlist_canonical_ip_single_normalizer(self) -> None:
        """跨模块引用 allowlist/tools/ipnorm.py：单一归一化实现必须存在且行为一致。"""
        sys.path.insert(0, str(ROOT / "allowlist" / "tools"))
        from ipnorm import canonical_ip  # noqa: E402
        self.assertEqual(canonical_ip("2001:0DB8::0001"), "2001:db8::1")
        self.assertIsNone(canonical_ip("fe80::1%eth0"))
        # add/refresh/query 三处都走 canonical_ip
        add_src = (ROOT / "allowlist" / "tools" / "add.py").read_text(encoding="utf-8")
        refresh_src = (ROOT / "allowlist" / "tools" / "refresh.py").read_text(encoding="utf-8")
        query_src = (ROOT / "allowlist" / "tools" / "query.py").read_text(encoding="utf-8")
        for name, src in (("add.py", add_src), ("refresh.py", refresh_src), ("query.py", query_src)):
            self.assertIn("canonical_ip", src, f"{name} 必须使用共享 canonical_ip")
        self.assertNotIn("exploded.lower", refresh_src, "refresh 不得再用 exploded 归一")
        self.assertNotIn("str(ipaddress.ip_address(value.strip()))", add_src,
                         "add 不得再自建 str() 归一")

    def test_all_engines_flag_does_not_crash_without_tools(self) -> None:
        path = write_tmp(self.tmp, "x.txt", b"hello\n")
        r = analyze(path, opts={"all_engines": True})
        self.assertTrue(r["ok"])

    def test_fuzzy_hash_engine_values_match_importability(self) -> None:
        path = write_tmp(self.tmp, "y.bin", b"binary-ish content" + bytes(range(64)))
        r = analyze(path)
        for mod in ("ssdeep", "tlsh"):
            expected = importlib.util.find_spec(mod) is not None
            self.assertIs(
                r["engines"][mod],
                expected,
                f"{mod} 的回显值必须与 import 可用性一致（期望 {expected}，实际 {r['engines'][mod]}）",
            )

    # ---- YARA：正例必须出现 yara.*，负例不得出现（V-19 只验"能编译"） ----
    def test_yara_positive_sample_hits_webshell_rules(self) -> None:
        sample = b"<?php\n@eval($_POST['cmd']);\nsystem($_GET['x']);\n?>\n"
        r = analyze(write_tmp(self.tmp, "shell_probe.php", sample))
        if not r["engines"].get("yara"):
            self.assertFalse(EXPECT_ENHANCED, "XBITS_EXPECT_ENHANCED=1 时 yara 必须可用")
            self.skipTest("yara-python 未安装（stdlib 路径）；CI 增强步骤断言正例必须命中")
        yara_ids = [f["id"] for f in r["findings"] if f["id"].startswith("yara.")]
        self.assertTrue(yara_ids, f"已知 PHP webshell 样本必须命中 YARA 规则，实际 findings={r['findings']}")
        self.assertIn("yara.webshell_php_eval_superglobal", yara_ids)
        self.assertIn(r["verdict"], ("malicious", "suspicious"))

    def test_yara_benign_sample_has_no_yara_hits(self) -> None:
        r = analyze(write_tmp(self.tmp, "weekly_report.txt", b"weekly report\nall good\nwindow 42\n"))
        if not r["engines"].get("yara"):
            self.assertFalse(EXPECT_ENHANCED, "XBITS_EXPECT_ENHANCED=1 时 yara 必须可用")
            self.skipTest("yara-python 未安装（stdlib 路径）；CI 增强步骤断言负例不得命中")
        yara_ids = [f["id"] for f in r["findings"] if f["id"].startswith("yara.")]
        self.assertEqual(yara_ids, [], f"良性文本不得命中 YARA 规则，实际 {yara_ids}")

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
