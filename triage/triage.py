#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xbits 静态 Triage：不运行样本，只根据文件字节/结构/字符串/规则快速初筛。

设计原则
--------
- **纯标准库必跑**：magic 嗅探、hash、熵、strings、脚本危险函数扫描全部用标准库实现，
  任何环境可直接跑；无论可选组件是否安装都不会导致崩溃。
- **可选开源组件软接入（有则增强，无则降级）**：
    * python 库（自动启用）：python-magic、yara-python、oletools、pefile、pyelftools、
      ssdeep、tlsh
    * 外部命令（显式开启，避免拖慢默认路径）：capa、clamscan、semgrep、binwalk
- **绝不执行样本、不落盘、不联网**：只读文件做静态判断；hash 情报只用本地文件/调用方传入值，不联网上传。
- **hash 情报的单一判定来源**（避免与 xbits 重复判定）：
    * 由 xbits 以 `--stdin` 调起时，以 payload 里的 `intel` 标注为准，**不再读本地 file_hash.txt**；
    * 独立 CLI（`--file` / 位置参数）仍可读本地 `threat-intel/data/file_hash.txt`；
    * 显式 `--hash-intel FILE` 仅独立 CLI（非 `--stdin`）生效。

CLI
---
  python3 triage/triage.py --file PATH
  python3 triage/triage.py PATH
  python3 triage/triage.py --stdin                 # 从 stdin 读 {"path": ..., "intel": {...}}
可选增强：
  --rules-dir DIR          YARA 规则目录(*.yar/*.yara)
  --capa-cmd CMD           外部 capa 命令(默认 "capa")
  --clamscan-cmd CMD       外部 ClamAV 命令(默认 "clamscan")
  --semgrep-config CFG     semgrep 规则 config（启用 semgrep）
  --semgrep-cmd CMD        semgrep 命令(默认 "semgrep")
  --binwalk-cmd CMD        binwalk 命令(默认 "binwalk")
  --hash-intel FILE        本地已知恶意 hash 名单(独立 CLI 用；xbits 传入情报时忽略)
  --all-engines            尝试启用所有可在 PATH 找到的外部命令

输出（stdout 单行 JSON）：见 triage/README.md。
- engines[tool]=bool 为向后兼容摘要（present and ok）；结构化三态在 `engine_status[tool] = {present, ok, error}`；
  顶层 `degraded`/`engine_errors` 表示"有引擎执行失败，证据不完整"，与"未检出"严格区分。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

MAX_ANALYZE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 60
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 文件哈希算法按十六进制长度判定（与 threat-intel/query.py、intel.rs 一致）
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}

# 脚本/代码危险信号：id -> (正则, 严重度, 权重)
SCRIPT_PATTERNS = [
    ("php.eval", r"\beval\s*\(", "critical", 60),
    ("php.assert", r"\bassert\s*\(", "high", 35),
    ("php.system_exec", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
     "critical", 55),
    ("php.base64_decode", r"\bbase64_decode\s*\(", "medium", 20),
    ("php.gzinflate", r"\b(?:gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(", "medium", 20),
    ("php.preg_replace_e", r"preg_replace\s*\(\s*['\"].*?/e", "high", 35),
    ("php.dynamic_include", r"\b(?:include|require)(?:_once)?\s*\(?\s*\$", "high", 30),
    ("php.superglobal_sink",
     r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]*\]\s*(?:\)|;|,|\])", "low", 8),
    ("php.file_upload", r"\bmove_uploaded_file\s*\(", "medium", 18),
    ("php.backtick", r"`[^`\n]{1,200}`", "medium", 15),
    ("java.runtime_exec", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec", "critical", 55),
    ("java.process_builder", r"new\s+ProcessBuilder\s*\(", "high", 40),
    ("java.classloader", r"\b(?:defineClass|Class\.forName|URLClassLoader)\s*\(", "medium", 25),
    ("java.script_engine", r"javax\.script|ScriptEngineManager", "medium", 25),
    ("jsp.scriptlet", r"<%\s*(?:@|!|=)?", "low", 6),
    ("html.script_tag", r"<\s*script\b", "low", 8),
    ("js.eval", r"\beval\s*\(", "medium", 15),
    ("js.fromcharcode", r"String\.fromCharCode\s*\(", "low", 10),
    ("html.event_handler", r"\bon(?:error|load|click)\s*=", "low", 8),
]

# 二进制可执行体常见危险字符串（无解析库时的启发式；有 pefile/ELF 时更准）
BINARY_SUSPICIOUS = [
    ("bin.virtualalloc", r"VirtualAlloc(?:Ex)?", "medium", 15),
    ("bin.writeprocessmemory", r"WriteProcessMemory", "high", 30),
    ("bin.createremotethread", r"CreateRemoteThread", "high", 30),
    ("bin.loadlibrary", r"LoadLibrary[AW]?", "low", 8),
    ("bin.shell", r"/bin/sh|cmd\.exe|powershell", "medium", 18),
    ("bin.ptrace", r"\bptrace\b", "medium", 18),
]

PDF_SUSPICIOUS = [
    ("pdf.javascript", "/JavaScript", "high", 35),
    ("pdf.openaction", "/OpenAction", "high", 30),
    ("pdf.launch", "/Launch", "critical", 45),
    ("pdf.embedded", "/EmbeddedFile", "high", 30),
    ("pdf.aa", "/AA", "medium", 15),
]

# PE 危险导入 API -> (id, 严重度, 权重, 行为描述)
# 注意：导入表单独出现多为弱信号（系统 DLL 也大量导入这些 API），权重刻意压低，
# 需多个组合（如 注入三件套）才升级；已签名二进制另有降级策略（见 analyze）。
PE_SUSPICIOUS_IMPORTS = {
    # 进程注入
    "virtualallocex": ("pe.inject_alloc", "medium", 18, "远程分配内存(注入)"),
    "writeprocessmemory": ("pe.inject_write", "high", 25, "写远程进程内存(注入)"),
    "createremotethread": ("pe.inject_thread", "high", 25, "远程线程执行(注入)"),
    "ntunmapviewofsection": ("pe.inject_unmap", "high", 20, "进程镂空"),
    "setthreadcontext": ("pe.inject_ctx", "high", 20, "线程上下文劫持"),
    "queueuserapc": ("pe.inject_apc", "medium", 16, "APC 注入"),
    # 反调试/规避
    "isdebuggerpresent": ("pe.antidebug", "low", 6, "反调试"),
    "checkremotedebuggerpresent": ("pe.antidebug2", "low", 6, "反调试"),
    "outputdebugstringa": ("pe.antidebug3", "low", 4, "反调试探测"),
    "virtualprotect": ("pe.mprotect", "low", 5, "修改内存保护(规避)"),
    # 网络/下载
    "internetopenurl": ("pe.download", "medium", 12, "URL 下载"),
    "internetopen": ("pe.internet", "low", 8, "WinINet 网络访问"),
    "httpsendrequest": ("pe.http", "low", 8, "HTTP 请求"),
    "winhttpopen": ("pe.winhttp", "low", 8, "WinHTTP 网络访问"),
    "urldownloadtofile": ("pe.urldl", "high", 18, "下载并落盘"),
    "wsastartup": ("pe.socket", "low", 5, "套接字"),
    # 持久化/服务
    "createservicea": ("pe.service", "medium", 12, "创建服务(持久化)"),
    "regsetvalueexa": ("pe.registry", "low", 8, "写注册表(持久化)"),
    # 加解密
    "cryptencrypt": ("pe.crypto", "medium", 10, "加密(勒索嫌疑)"),
    "cryptdecrypt": ("pe.crypto2", "low", 5, "解密"),
}


def _which(cmd: str | None) -> str | None:
    if not cmd:
        return None
    return shutil.which(cmd)


# ---------------- 引擎状态：present/ok/error 三态（V-20） ----------------
# engines[tool] = bool 只是向后兼容摘要（present and ok），不再承担"执行成功"的语义；
# 结构化状态统一写 engine_status[tool] = {"present", "ok", "error"}：
#   present=False            组件未安装/未启用（可选缺失，不算"证据不完整"）
#   present=True, ok=True    本次真实执行成功（含"执行了且未检出"）
#   present=True, ok=False   执行失败（rc!=0 / 超时 / 解析失败 / 库在但用不了）→ 计入 degraded
def _set_engine(engines: dict, status: dict, name: str, *,
                present: bool, ok: bool, error: str | None = None,
                failed_files: list[str] | None = None,
                unreadable_errors: list[str] | None = None) -> None:
    status[name] = {"present": bool(present), "ok": bool(ok),
                    "error": (error[:200] if error else None)}
    # R8-3：YARA 的结构化失败明细（编译失败文件名 / 目录或文件不可读原因）
    if failed_files:
        status[name]["failed_files"] = list(failed_files)
    if unreadable_errors:
        status[name]["unreadable_errors"] = [e[:200] for e in unreadable_errors[:5]]
    engines[name] = bool(present and ok)


def _hash_stream(path: str) -> dict:
    md5 = hashlib.md5(); sha1 = hashlib.sha1(); sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk); size += len(chunk)
    return {"size": size, "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data); total = len(data); ent = 0.0
    for n in counts.values():
        p = n / total
        ent -= p * math.log2(p)
    return round(ent, 3)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def _shannon(data: bytes) -> float:
    return _entropy(data)


def _sniff_type(path: str, data: bytes) -> dict:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    magic = "data"; category = "other"; mime = "application/octet-stream"
    try:  # 可选 python-magic
        import magic as _magic  # type: ignore
        m = _magic.Magic(mime=True)
        guessed = m.from_buffer(data[:4096])
        if guessed:
            mime = guessed; magic = guessed
    except Exception:
        pass

    def starts(sig: bytes) -> bool:
        return data.startswith(sig)

    if starts(b"\x7fELF"):
        category, magic = "binary", "ELF executable"
    elif starts(b"MZ"):
        category, magic = "binary", "PE executable (MZ)"
    elif starts(b"\xcf\xfa\xed\xfe") or starts(b"\xce\xfa\xed\xfe") or starts(b"\xca\xfe\xba\xbe"):
        category, magic = "binary", "Mach-O executable"
    elif starts(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        category, magic = "document", "OLE compound document (doc/xls/ppt)"
    elif starts(b"%PDF"):
        category, magic = "document", "PDF document"
    elif starts(b"PK\x03\x04"):
        category, magic = "archive", "ZIP archive (zip/jar/apk/docx/xlsx)"
    elif starts(b"\x1f\x8b"):
        category, magic = "archive", "gzip archive"
    elif starts(b"Rar!\x1a\x07"):
        category, magic = "archive", "RAR archive"
    elif starts(b"7z\xbc\xaf\x27\x1c"):
        category, magic = "archive", "7z archive"
    else:
        head_txt = data[:4096].decode("latin-1", "replace").lower()
        script_exts = {
            "php", "php3", "php4", "php5", "php7", "phtml", "phar",
            "jsp", "jspx", "jspf", "asp", "aspx", "ashx", "asmx", "asa", "cer",
            "js", "jse", "vbs", "ps1", "py", "rb", "pl", "sh", "bash",
        }
        if "<?php" in head_txt or "<?=" in head_txt:
            category, magic = "script", "PHP script"
        elif "<%" in data[:4096].decode("latin-1", "replace") and ext in {"jsp", "jspx", "asp", "aspx"}:
            category, magic = "script", "JSP/ASP script"
        elif starts(b"#!"):
            category, magic = "script", "script (shebang)"
        elif ext in script_exts:
            category, magic = "script", f"script (.{ext})"
        elif _printable_ratio(data) > 0.85:
            category, magic = "text", "text/plain"; mime = "text/plain"
        else:
            category, magic = "binary", "unknown binary"
    return {"category": category, "magic": magic, "ext": ext or None, "mime": mime}


def _extract_strings(data: bytes, min_len: int = 4, limit: int = 500) -> list[str]:
    out: list[str] = []; cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "ignore"))
                if len(out) >= limit:
                    break
            cur = bytearray()
    if len(cur) >= min_len and len(out) < limit:
        out.append(cur.decode("ascii", "ignore"))
    return out


def _scan_patterns(text: str, patterns, findings: list, scope: str) -> None:
    for pid, pat, sev, weight in patterns:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({"id": pid, "severity": sev,
                             "detail": f"{scope} 命中危险模式: {pat}", "weight": weight})


# ---------------- 可选：PE 结构分析（pefile） ----------------
def _pe_scan(path: str, data: bytes, engines: dict, status: dict, findings: list, info: dict) -> None:
    try:
        import pefile  # type: ignore
    except Exception:
        _set_engine(engines, status, "pefile", present=False, ok=False)
        return
    try:
        pe = pefile.PE(data=data, fast_load=True)
        # PE 数据目录索引（PE 规范固定）：EXPORT=0 IMPORT=1 RESOURCE=2 DEBUG=6 TLS=9 LOAD_CONFIG=10
        try:
            pe.parse_data_directories(directories=[1, 0, 2, 6, 9, 10])
        except Exception:
            pass
    except Exception as exc:  # 非有效 PE / 解析失败：降级为字符串启发（如实记 failed，不与"未检出"同形）
        _set_engine(engines, status, "pefile", present=True, ok=False,
                    error=f"parse-failed: {exc}")
        info["pe_error"] = str(exc)[:200]
        return
    _set_engine(engines, status, "pefile", present=True, ok=True)

    sections = []
    for s in pe.sections:
        try:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "ignore")
            sections.append({"name": name, "entropy": round(s.get_entropy(), 2),
                             "vsize": int(s.Misc_VirtualSize)})
        except Exception:
            continue
    imports: list[str] = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", "ignore") if entry.dll else ""
                for imp in entry.imports:
                    if imp.name:
                        imports.append(f"{dll}!{imp.name.decode('latin-1', 'ignore')}")
    except Exception:
        pass

    imphash = ""
    try:
        imphash = pe.get_imphash() or ""
    except Exception:
        pass
    authentihash = ""
    try:
        fn = getattr(pe, "get_authentihash", None)
        if callable(fn):
            authentihash = fn() or ""
    except Exception:
        authentihash = ""

    machine = ""
    try:
        machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, str(pe.FILE_HEADER.Machine))
    except Exception:
        machine = str(getattr(getattr(pe, "FILE_HEADER", None), "Machine", ""))

    info["pe"] = {
        "machine": machine,
        "timestamp": getattr(pe.FILE_HEADER, "TimeDateStamp", None),
        "subsystem": getattr(getattr(pe, "OPTIONAL_HEADER", None), "Subsystem", None),
        "is_dll": bool(getattr(pe, "is_dll", lambda: False)()),
        "entrypoint": hex(getattr(getattr(pe, "OPTIONAL_HEADER", None), "AddressOfEntryPoint", 0) or 0),
        "sections": sections,
        "imports": imports[:200],
        "import_count": len(imports),
        "imphash": imphash,
        "authentihash": authentihash,
    }
    # 数字签名：区分"存在性探测"与"可信验证"（V-22）。
    # 我们只读证书表是否非空（signed_present）；signature_verified 恒 False——本工具不做
    # 证书链/信任校验，绝不允许凭"证书表非空"降级 verdict（恶意 PE 可伪造证书表洗白）。
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        info["pe"]["signed_present"] = bool(sec_dir.VirtualAddress and sec_dir.Size)
    except Exception:
        info["pe"]["signed_present"] = False
    info["pe"]["signature_verified"] = False
    # 兼容旧消费方（只读布尔）；语义 = signed_present，绝非"可信"
    info["pe"]["signed"] = info["pe"]["signed_present"]

    # 危险导入判定
    seen = set()
    for imp in imports:
        fn = imp.split("!")[-1].lower()
        if fn in PE_SUSPICIOUS_IMPORTS and fn not in seen:
            seen.add(fn)
            pid, sev, weight, desc = PE_SUSPICIOUS_IMPORTS[fn]
            findings.append({"id": pid, "severity": sev,
                             "detail": f"PE 导入 {imp} —— {desc}", "weight": weight})
    # 高熵节区（加壳/加密）
    for sec in sections:
        if sec["entropy"] > 7.2 and sec["vsize"] > 4096:
            findings.append({"id": "pe.packed_section", "severity": "medium",
                             "detail": f"节区 {sec['name']} 高熵({sec['entropy']})，疑似加壳/加密",
                             "weight": 18})
            break


# ---------------- 可选：ELF 结构分析（pyelftools） ----------------
def _elf_scan(path: str, data: bytes, engines: dict, status: dict, findings: list, info: dict) -> None:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        from elftools.elf.dynamic import DynamicSection  # type: ignore
    except Exception:
        _set_engine(engines, status, "pyelftools", present=False, ok=False)
        return
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            try:
                machine = elf.get_machine_arch()
            except Exception:
                machine = str(elf.header.e_machine)
            needed: list[str] = []
            has_dynamic = False
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    has_dynamic = True
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
            info["elf"] = {
                "machine": machine,
                "type": elf.header.e_type,
                "entry": hex(elf.header.e_entry),
                "needed": needed,
                "statically_linked": not has_dynamic,
            }
    except Exception as exc:
        _set_engine(engines, status, "pyelftools", present=True, ok=False,
                    error=f"parse-failed: {exc}")
        info["elf_error"] = str(exc)[:200]
        return
    _set_engine(engines, status, "pyelftools", present=True, ok=True)

    if info.get("elf", {}).get("statically_linked"):
        findings.append({"id": "elf.static", "severity": "low",
                         "detail": "静态链接 ELF（无动态段，常见于打包/持久化植入）", "weight": 10})


# ---------------- 可选：YARA ----------------
_YARA_CACHE: dict = {}
# YARA include 语法：`include "path"`（YARA 只支持双引号；路径相对当前规则文件目录，
# 本文件同时兼容以 rules_dir 为基准的写法）。
_YARA_INCLUDE_RE = re.compile(r'^\s*include\s+"([^"]+)"', re.MULTILINE)


def _yara_include_target(including_file: str, inc: str, rules_dir: str) -> str:
    """解析 include 目标：优先相对当前规则文件目录，其次相对 rules_dir。"""
    p = os.path.normpath(os.path.join(os.path.dirname(including_file), inc))
    if os.path.exists(p):
        return p
    return os.path.normpath(os.path.join(rules_dir, inc))


def _yara_include_within(rules_dir: str, target: str) -> bool:
    """include 目标必须落在 rules_dir 内（resolved realpath，拒绝 symlink 逃逸）。"""
    root = os.path.realpath(rules_dir)
    path = os.path.realpath(target)
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:  # Windows 跨盘符等
        return False


def _compiled_yara_rules(yara_mod, rules_dir: str) -> tuple[list, list[str], list[str]]:
    """编译目录（递归含子目录）下所有 YARA 规则；带 R11-1 目录级缓存；兼容非 ASCII 路径。

    返回 (compiled, failed_paths, unreadable_errors)（R8-3/V-19/V-20，R9-1/R10-1/R11-1）：
      * 目录/文件不可读：进 unreadable_errors（walk 失败＝无法枚举；单文件 stat 失败＝该条规则
        无法确认，不进 failed_paths，避免双重计数）；
      * 规则文件编译失败：文件名进 failed_paths（部分失败 ≠ 全部生效）；
      * include 越界（目标不在 rules_dir 内）：该规则不编译，计入 unreadable_errors
        （error 可见 + 顶层 degraded），绝不静默忽略；
      * 匹配异常由 _yara_scan 计数（不在此层）。

    R11-1 缓存契约（方案 b）：缓存键 = rules_dir 下所有 `.yar/.yara`（递归）**以及被 include
    引用的文件**的 `(relpath, mtime, size, 状态)` 排序元组。任一规则文件或被 include 文件
    变化（含新增/删除/权限变化）→ 签名变化 → 整体重编译；完全无变化 → 命中缓存返回**同一**
    compiled 对象。代价：任一规则变化会让整个规则集缓存失效（当前 ~7 个规则文件，可接受）。
    """
    failed: list[str] = []
    unreadable_errors: list[str] = []
    candidates: list[tuple] = []  # 目录级指纹：排序后的 (rel, mtime, size, 状态)
    seen_candidates: set[tuple] = set()

    def add_candidate(rel: str, mtime, size, state: str) -> None:
        item = (rel, mtime, size, state)
        if item not in seen_candidates:
            seen_candidates.add(item)
            candidates.append(item)

    try:
        roots: list[tuple[str, str, float, int]] = []
        files: list[tuple[str, float, int]] = []
        for dp, _dirs, fnames in os.walk(rules_dir):
            for name in sorted(fnames):
                if name.endswith(".yar") or name.endswith(".yara"):
                    fp = os.path.join(dp, name)
                    rel = os.path.relpath(fp, rules_dir)
                    try:
                        st = os.stat(fp)
                    except OSError as exc:
                        # 单个文件 stat 失败（权限/竞态）：该条规则不可用，只记不可读原因（R9-1）
                        unreadable_errors.append(f"stat-failed: {fp}: {exc}")
                        # 失败条目也进缓存键（R10-1）：否则删除坏文件后旧结果会一直命中
                        add_candidate(
                            rel, None, None,
                            f"stat-failed:{exc.errno}:{type(exc).__name__}",
                        )
                        continue
                    roots.append((fp, rel, st.st_mtime, st.st_size))
                    files.append((fp, st.st_mtime, st.st_size))
                    add_candidate(rel, st.st_mtime, st.st_size, "ok")

        # R11-1：解析 include 依赖（含嵌套），把 rules_dir 内被 include 文件纳入指纹；
        # 越界 include 标记所属根规则为坏规则（不编译，错误/降级可见）。
        bad_roots: set[str] = set()
        parsed: set[str] = set()
        queue: list[tuple[str, str]] = [(fp, fp) for fp, _rel, _m, _s in roots]
        while queue:
            current, root = queue.pop()
            if current in parsed:
                continue
            parsed.add(current)
            try:
                with open(current, "rb") as fh:
                    text = fh.read().decode("utf-8", "replace")
            except OSError:
                # 规则文件本身读不了会让后面的 compile 失败；这里不重复记 unreadable。
                continue
            for inc in _YARA_INCLUDE_RE.findall(text):
                target = _yara_include_target(current, inc, rules_dir)
                if not _yara_include_within(rules_dir, target):
                    bad_roots.add(root)
                    unreadable_errors.append(
                        "include-outside-rules-dir: "
                        f"{os.path.relpath(root, rules_dir)} -> {inc}"
                    )
                    add_candidate(f"include:{inc}", None, None, "include-outside-rules-dir")
                    continue
                rel = os.path.relpath(target, rules_dir)
                try:
                    st = os.stat(target)
                except OSError as exc:
                    add_candidate(
                        rel, None, None,
                        f"include-stat-failed:{exc.errno}:{type(exc).__name__}",
                    )
                    continue
                add_candidate(rel, st.st_mtime, st.st_size, "include")
                queue.append((target, root))

        if bad_roots:
            files = [item for item in files if item[0] not in bad_roots]
        files.sort()
        candidates.sort(key=lambda c: c[0])
    except OSError as exc:
        # 目录本身不可读：规则集完全不可用（不写缓存，下次必然重试）
        return [], [], [f"walk-failed: {rules_dir}: {exc}"]

    key = os.path.abspath(rules_dir)
    sig = tuple(candidates)
    cached = _YARA_CACHE.get(key)
    if cached and cached[0] == sig:
        return cached[1], cached[2], cached[3]
    compiled: list = []
    for fp, _m, _s in files:
        r = None
        try:
            r = yara_mod.compile(filepath=fp)  # ASCII 路径首选（支持 include）
        except Exception:
            # 非 ASCII 路径（如中文目录）下 C 库打不开文件：读字节用 source 编译
            try:
                with open(fp, "rb") as fh:
                    r = yara_mod.compile(source=fh.read().decode("utf-8", "replace"))
            except Exception:
                r = None
        if r is not None:
            compiled.append(r)
        else:
            failed.append(os.path.basename(fp))
    _YARA_CACHE[key] = (sig, compiled, failed, unreadable_errors)
    return compiled, failed, unreadable_errors


def _yara_scan(path: str, rules_dir: str | None, engines: dict, status: dict,
               findings: list, info: dict) -> None:
    try:
        import yara  # type: ignore
    except Exception:
        _set_engine(engines, status, "yara", present=False, ok=False)
        return
    if not rules_dir or not os.path.isdir(rules_dir):
        # 库在但没有规则目录：如实回显"未配置规则"，不得假装"扫描过"
        _set_engine(engines, status, "yara", present=True, ok=False,
                    error=f"rules-dir-missing: {rules_dir or '(none)'}")
        return
    match_errors = 0
    try:
        with open(path, "rb") as fh:
            target = fh.read(MAX_ANALYZE_BYTES)
    except OSError as exc:
        _set_engine(engines, status, "yara", present=True, ok=False,
                    error=f"read-failed: {exc}")
        return
    # 三类失败（R8-3）：目录不可读 / 规则文件编译失败 / 匹配异常。
    # 部分编译失败时已编译规则仍要跑（可用部分生效），但 ok=False + degraded 必须可见。
    compiled, failed_files, unreadable_errors = _compiled_yara_rules(yara, rules_dir)
    if failed_files:
        info["yara_rules_failed"] = sorted(failed_files)
    if unreadable_errors:
        info["yara_unreadable_errors"] = [e[:200] for e in unreadable_errors[:5]]
    if not compiled:
        detail = (f"no-rules-compiled (compile-failed={len(failed_files)}, "
                  f"unreadable={len(unreadable_errors)})")
        if unreadable_errors:
            detail = f"{detail}; {unreadable_errors[0][:150]}"
        _set_engine(engines, status, "yara", present=True, ok=False, error=detail,
                    failed_files=sorted(failed_files), unreadable_errors=unreadable_errors)
        return
    for rules in compiled:
        try:
            matches = rules.match(data=target)  # 用 data 匹配，规避非 ASCII 路径
        except Exception:
            try:
                matches = rules.match(path)
            except Exception:
                matches = []
                match_errors += 1
        for match in matches:
            name = getattr(match, "rule", str(match))
            # 严重度优先取规则 meta.severity（V-19），缺失时才按家族名保守推断
            meta = getattr(match, "meta", None) or {}
            sev = str(meta.get("severity", "")).lower()
            if sev not in ("critical", "high", "medium", "low"):
                sev = "critical" if any(t in name.lower() for t in
                                        ("rat", "ransom", "webshell", "backdoor", "trojan",
                                         "malware", "shellcode")) else "high"
            findings.append({"id": f"yara.{name}", "severity": sev,
                             "detail": f"YARA 命中规则 {name}", "weight": 45})
    info.setdefault("yara_rules", {})["loaded"] = len(compiled)
    info["yara_rules"]["failed"] = len(failed_files)

    # 结论：任何一类失败（编译失败 / 目录不可读 / 匹配异常）都 ok=False + degraded；
    # 但已编译规则的命中照常产出（可用部分生效，不被跳过）。
    problems: list[str] = []
    if failed_files:
        problems.append(f"compile-failed: {','.join(sorted(failed_files))}")
    if unreadable_errors:
        problems.append(f"unreadable: {unreadable_errors[0][:120]}"
                        + (f" (+{len(unreadable_errors) - 1} more)" if len(unreadable_errors) > 1 else ""))
    if match_errors:
        info["yara_match_errors"] = match_errors
        problems.append(f"match-errors: {match_errors}")
    if problems:
        _set_engine(engines, status, "yara", present=True, ok=False,
                    error="; ".join(problems),
                    failed_files=sorted(failed_files), unreadable_errors=unreadable_errors)
    else:
        _set_engine(engines, status, "yara", present=True, ok=True)


# ---------------- 可选：Office 宏（oletools） ----------------
def _office_scan(path: str, data: bytes, engines: dict, status: dict, findings: list, info: dict) -> None:
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except Exception:
        _set_engine(engines, status, "oletools", present=False, ok=False)
        if data.startswith(b"\xd0\xcf\x11\xe0"):
            findings.append({"id": "office.macro_capable", "severity": "low",
                             "detail": "OLE 复合文档（可含宏；未安装 oletools 无法深入分析）", "weight": 10})
        return
    try:
        vba = VBA_Parser(path, data=data)
    except Exception as exc:
        # 库在但解析失败（加密文档/损坏 OLE）：必须与"无宏"区分（V-20）
        _set_engine(engines, status, "oletools", present=True, ok=False,
                    error=f"parse-failed: {exc}")
        info["oletools_error"] = str(exc)[:200]
        if data.startswith(b"\xd0\xcf\x11\xe0"):
            findings.append({"id": "office.analysis_failed", "severity": "low",
                             "detail": "OLE 文档宏分析失败（无法判定是否有宏；不等于无宏）", "weight": 10})
        return
    try:
        hit = False
        if vba.detect_vba_macros():
            for _s, _st, _v, code in vba.extract_macros():
                if re.search(r"(AutoOpen|CreateObject|Shell|WScript|XMLHTTP|powershell|URLDownload)",
                             code, re.IGNORECASE):
                    hit = True
                    findings.append({"id": "office.suspicious_macro", "severity": "high",
                                     "detail": "Office 宏含可疑调用(AutoOpen/CreateObject/Shell/HTTP)",
                                     "weight": 45})
                    break
        vba.close()
        _set_engine(engines, status, "oletools", present=True, ok=True)
        info.setdefault("oletools", {})["macro_analysis"] = "suspicious" if hit else "clean"
    except Exception as exc:
        _set_engine(engines, status, "oletools", present=True, ok=False,
                    error=f"scan-failed: {exc}")
        info["oletools_error"] = str(exc)[:200]


def _pdf_scan(data: bytes, findings: list) -> None:
    _scan_patterns(data.decode("latin-1", "replace"), PDF_SUSPICIOUS, findings, "pdf")


# ---------------- 可选：模糊哈希（ssdeep / tlsh） ----------------
def _fuzzy_hash(path: str, engines: dict, status: dict, info: dict) -> None:
    try:
        import ssdeep  # type: ignore
        try:
            info.setdefault("fuzzy", {})["ssdeep"] = ssdeep.hash_from_file(path)
            _set_engine(engines, status, "ssdeep", present=True, ok=True)
        except Exception as exc:
            _set_engine(engines, status, "ssdeep", present=True, ok=False,
                        error=f"hash-failed: {exc}")
    except Exception:
        _set_engine(engines, status, "ssdeep", present=False, ok=False)
    try:
        import tlsh  # type: ignore
        try:
            with open(path, "rb") as fh:
                info.setdefault("fuzzy", {})["tlsh"] = tlsh.hash(fh.read(MAX_ANALYZE_BYTES))
            _set_engine(engines, status, "tlsh", present=True, ok=True)
        except Exception as exc:
            _set_engine(engines, status, "tlsh", present=True, ok=False,
                        error=f"hash-failed: {exc}")
    except Exception:
        _set_engine(engines, status, "tlsh", present=False, ok=False)


def _load_hash_intel(path: str | None) -> set[str]:
    if not path or not os.path.isfile(path):
        return set()
    out = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                h = line.strip().lower().split("#")[0].strip()
                if h:
                    out.add(h)
    except OSError:
        pass
    return out


# ---------------- hash 情报：单一判定来源 ----------------
# 语义（xbits 编排路径 与 独立 CLI 路径严格区分，避免两套数据源并存）：
#   * xbits 调用（`--stdin`，payload 可携带 "intel" 字段 = 引擎在进 triage 之前算好的
#     情报标注）：**以传入情报为准，不读本地 threat-intel/data/file_hash.txt**。这样
#     情报只有一个数据源（xbits 引擎）、一个判定点，triage 不会另判一份 intel.known_bad
#     造成重复/冲突计分。
#   * 独立 CLI（`--file/位置参数`）：保留本地 file_hash.txt 离线判定能力（不联网）。
#   * 显式 `--hash-intel FILE`：操作者显式指定的本地名单，仅在独立 CLI（非 --stdin）时生效。
# 优先级：payload 情报 > xbits(--stdin) 无情报即视为“无命中” > 显式 --hash-intel > 独立 CLI 默认本地名单。
def _payload_threat_hashes(payload_intel) -> tuple[bool, list[dict]]:
    """解析 xbits 传入的情报标注，返回 (是否传入情报, 文件哈希类威胁命中列表)。

    兼容形状（xbits 侧 EventIntelAnnotations 及简化写法）：
      {"threat": [{"type": "sha256", "value": "<hex>"}, ...], ...}
      [{"type": "...", "value": "..."}, ...] / ["<hex>", ...]
      {"hashes": ["<hex>", ...]} / {"type": "...", "value": "..."} / "<hex>"
    只保留长度 32/40/64 的十六进制值（md5/sha1/sha256）；ip/domain 等其它类型忽略。
    返回的命中去重（同一 algo+value 只留一条）。
    """
    if payload_intel is None:
        return False, []
    entries: list = []
    if isinstance(payload_intel, dict):
        if isinstance(payload_intel.get("threat"), list):
            entries = payload_intel["threat"]
        elif isinstance(payload_intel.get("hashes"), list):
            entries = [{"value": v} for v in payload_intel["hashes"]]
        elif "value" in payload_intel:
            entries = [payload_intel]
    elif isinstance(payload_intel, list):
        entries = payload_intel
    elif isinstance(payload_intel, str):
        entries = [{"value": payload_intel}]

    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for e in entries:
        if isinstance(e, str):
            v, t = e, ""
        elif isinstance(e, dict):
            v, t = str(e.get("value", "")), str(e.get("type", "")).lower()
        else:
            continue
        v = v.strip().lower()
        if len(v) not in HASH_LEN or re.fullmatch(r"[0-9a-f]+", v) is None:
            continue
        algo = HASH_LEN[len(v)]
        if t in ("md5", "sha1", "sha256") and t != algo:
            continue
        if (algo, v) in seen:
            continue
        seen.add((algo, v))
        hits.append({"type": algo, "value": v})
    return True, hits


# ---------------- 可选：外部命令组件（显式开启） ----------------
def _run(cmd_list, timeout=DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def _capa_scan(path: str, cmd: str | None, engines: dict, status: dict,
               findings: list, info: dict) -> None:
    if not cmd:
        _set_engine(engines, status, "capa", present=False, ok=False)
        return
    exe = _which(cmd.split()[0])
    if not exe:
        _set_engine(engines, status, "capa", present=False, ok=False)
        return
    try:
        args = cmd.split() + ["-j", path]
        rc, out, err = _run(args)
        if rc != 0:
            # rc!=0（规则缺失/样本不支持/内部错误）≠ "未检出"（V-20）
            _set_engine(engines, status, "capa", present=True, ok=False,
                        error=f"exit={rc}: {(err or out or '').strip()[:150]}")
            return
        data = json.loads(out) if out.strip() else {}
        rules = data.get("rules", {}) if isinstance(data, dict) else {}
        caps = list(rules.keys())
        info["capa"] = {"capability_count": len(caps), "capabilities": caps[:40]}
        hottags = ("create process", "inject", "persist", "encrypt", "communicate", "download",
                   "write file", "modify registry", "anti", "obfuscat")
        for cap in caps:
            cl = cap.lower()
            if any(t in cl for t in hottags):
                findings.append({"id": "capa." + re.sub(r"\W+", "_", cap)[:60],
                                 "severity": "high",
                                 "detail": f"capa 能力: {cap}", "weight": 22})
        _set_engine(engines, status, "capa", present=True, ok=True)
    except subprocess.TimeoutExpired:
        _set_engine(engines, status, "capa", present=True, ok=False,
                    error=f"timeout after {DEFAULT_TIMEOUT}s")
    except Exception as exc:
        _set_engine(engines, status, "capa", present=True, ok=False,
                    error=f"run-failed: {exc}")


def _clamav_scan(path: str, cmd: str | None, engines: dict, status: dict,
                 findings: list, info: dict) -> None:
    if not cmd:
        _set_engine(engines, status, "clamav", present=False, ok=False)
        return
    exe = _which(cmd.split()[0])
    if not exe:
        _set_engine(engines, status, "clamav", present=False, ok=False)
        return
    try:
        args = cmd.split() + ["--no-summary", path]
        rc, out, err = _run(args, timeout=DEFAULT_TIMEOUT)
        text = (out or "") + (err or "")
        if "FOUND" in text:
            sig = ""
            for line in text.splitlines():
                if "FOUND" in line:
                    sig = line.strip()
                    break
            info["clamav"] = {"signature": sig}
            findings.append({"id": "clamav.detected", "severity": "critical",
                             "detail": f"ClamAV 命中: {sig}", "weight": 80})
            _set_engine(engines, status, "clamav", present=True, ok=True)
        elif rc == 0:
            # 真正的"扫描完成且未检出"
            info["clamav"] = {"signature": None}
            _set_engine(engines, status, "clamav", present=True, ok=True)
        else:
            # rc!=0：病毒库缺失/过期/IO 错误（clamscan 约定 2=错误）——不是"未检出"
            info["clamav"] = {"signature": None, "error": f"exit={rc}: {text.strip()[:150]}"}
            _set_engine(engines, status, "clamav", present=True, ok=False,
                        error=f"exit={rc}: {text.strip()[:150]}")
    except subprocess.TimeoutExpired:
        info["clamav"] = {"signature": None, "error": f"timeout after {DEFAULT_TIMEOUT}s"}
        _set_engine(engines, status, "clamav", present=True, ok=False,
                    error=f"timeout after {DEFAULT_TIMEOUT}s")
    except Exception as exc:
        info["clamav_error"] = str(exc)[:200]
        _set_engine(engines, status, "clamav", present=True, ok=False,
                    error=f"run-failed: {exc}")


def _semgrep_error_summary(err) -> str:
    """把 semgrep JSON errors[] 的单项压成一行摘要（R8-4）。

    semgrep 的 error 形状不固定：dict（含 message/type/code/path/spans）或字符串。
    dict 优先取 message，其次 type/code（含 level），末尾补 path 便于定位。
    """
    if isinstance(err, dict):
        parts = []
        for key in ("message", "type", "code", "level"):
            value = err.get(key)
            if value not in (None, ""):
                parts.append(str(value))
        summary = "; ".join(parts) or json.dumps(err, ensure_ascii=False)
        path = err.get("path")
        if path:
            summary = f"{summary} @ {path}"
    else:
        summary = str(err)
    return summary[:200]


def _semgrep_scan(path: str, category: str, cmd: str | None, config: str | None,
                  engines: dict, status: dict, findings: list, info: dict) -> None:
    if not cmd or not config or category not in ("script", "text"):
        _set_engine(engines, status, "semgrep", present=False, ok=False)
        return
    exe = _which(cmd.split()[0])
    if not exe:
        _set_engine(engines, status, "semgrep", present=False, ok=False)
        return
    try:
        args = cmd.split() + ["--json", "--config", config, path]
        rc, out, err = _run(args)
        if rc != 0 and not out.strip():
            # 无输出且非零：配置错/引擎崩溃（semgrep 命中时也可能 rc=1，故以有无输出区分）
            _set_engine(engines, status, "semgrep", present=True, ok=False,
                        error=f"exit={rc}: {(err or '').strip()[:150]}")
            return
        data = json.loads(out) if out.strip() else {}
        results = data.get("results", []) if isinstance(data, dict) else []
        errors = data.get("errors", []) if isinstance(data, dict) else []
        info["semgrep"] = {"result_count": len(results)}
        if errors:
            info["semgrep"]["errors"] = [_semgrep_error_summary(e) for e in errors[:5]]
        for r in results[:50]:
            rule_id = r.get("check_id", "semgrep")
            findings.append({"id": "semgrep." + re.sub(r"\W+", "_", rule_id)[:60],
                             "severity": "high", "detail": f"semgrep 命中: {rule_id}",
                             "weight": 25})
        # R8-4：JSON 里的 errors[] 非空 = 本次执行有失败（解析/规则/文件错误），
        # 不能因为"有输出"就判 ok=True。命中结果照常输出（不丢证据），
        # 但 ok=False + degraded 必须可见——"部分失败"≠"扫描通过未检出"。
        if errors:
            detail = f"json-errors: {len(errors)}; first={_semgrep_error_summary(errors[0])}"
            if rc != 0:
                detail = f"exit={rc}; {detail}"
            _set_engine(engines, status, "semgrep", present=True, ok=False, error=detail)
        elif rc == 0 or out.strip():
            # 有 JSON 输出且无 errors 即视为真实执行（semgrep 对命中惯例 rc=1）
            _set_engine(engines, status, "semgrep", present=True, ok=True)
        else:
            _set_engine(engines, status, "semgrep", present=True, ok=False,
                        error=f"exit={rc} no-output")
    except subprocess.TimeoutExpired:
        _set_engine(engines, status, "semgrep", present=True, ok=False,
                    error=f"timeout after {DEFAULT_TIMEOUT}s")
    except Exception as exc:
        _set_engine(engines, status, "semgrep", present=True, ok=False,
                    error=f"run-failed: {exc}")


def _binwalk_scan(path: str, category: str, cmd: str | None, engines: dict,
                  status: dict, info: dict) -> None:
    if not cmd or category not in ("binary", "archive"):
        _set_engine(engines, status, "binwalk", present=False, ok=False)
        return
    exe = _which(cmd.split()[0])
    if not exe:
        _set_engine(engines, status, "binwalk", present=False, ok=False)
        return
    try:
        rc, out, err = _run(cmd.split() + [path])
        if rc != 0:
            _set_engine(engines, status, "binwalk", present=True, ok=False,
                        error=f"exit={rc}: {(err or out or '').strip()[:150]}")
            return
        sigs = [ln.strip() for ln in (out or "").splitlines() if re.match(r"^\d+", ln.strip())]
        info["binwalk"] = {"embedded": sigs[:30], "count": len(sigs)}
        _set_engine(engines, status, "binwalk", present=True, ok=True)
    except subprocess.TimeoutExpired:
        _set_engine(engines, status, "binwalk", present=True, ok=False,
                    error=f"timeout after {DEFAULT_TIMEOUT}s")
    except Exception as exc:
        _set_engine(engines, status, "binwalk", present=True, ok=False,
                    error=f"run-failed: {exc}")


def _external_opts(opts: dict) -> dict:
    """解析外部命令开关；--all-engines 时尝试默认命令名。"""
    all_on = bool(opts.get("all_engines"))
    def pick(key, default):
        v = opts.get(key)
        if v:
            return v
        return default if all_on else None
    return {
        "capa_cmd": pick("capa_cmd", "capa"),
        "clamscan_cmd": pick("clamscan_cmd", "clamscan"),
        "semgrep_cmd": pick("semgrep_cmd", "semgrep"),
        "semgrep_config": opts.get("semgrep_config"),
        "binwalk_cmd": pick("binwalk_cmd", "binwalk"),
    }


def analyze(path: str, rules_dir: str | None = None, opts: dict | None = None) -> dict:
    opts = opts or {}
    if not os.path.isfile(path):
        return {"ok": False, "error": f"not a file: {path}"}

    file_meta = _hash_stream(path)
    with open(path, "rb") as fh:
        head = fh.read(MAX_ANALYZE_BYTES)
    ftype = _sniff_type(path, head)
    category = ftype["category"]
    findings: list[dict] = []
    info: dict = {}
    # engines[tool] = bool 向后兼容摘要（present and ok）；
    # 结构化三态在 engine_status：{present, ok, error}（见 _set_engine 注释）。
    engines: dict = {"magic_builtin": True,
                     "magic_lib": ftype.get("mime") not in (None, "application/octet-stream")}
    engine_status: dict = {}
    ext_opts = _external_opts(opts)

    text = head.decode("latin-1", "replace")
    if category in ("script", "text", "document"):
        _scan_patterns(text, SCRIPT_PATTERNS, findings, category)
    if category == "binary":
        _scan_patterns(text, BINARY_SUSPICIOUS, findings, "binary")
        if head.startswith(b"MZ"):
            _pe_scan(path, head, engines, engine_status, findings, info)
        elif head.startswith(b"\x7fELF"):
            _elf_scan(path, head, engines, engine_status, findings, info)
    if category == "document":
        if head.startswith(b"%PDF"):
            _pdf_scan(head, findings)
        if head.startswith(b"\xd0\xcf\x11\xe0"):
            _office_scan(path, head, engines, engine_status, findings, info)

    # 可选组件
    eff_rules_dir = rules_dir or opts.get("rules_dir")
    if not eff_rules_dir:
        default_rules = os.path.join(_SCRIPT_DIR, "rules")
        if os.path.isdir(default_rules):
            eff_rules_dir = default_rules
    _yara_scan(path, eff_rules_dir, engines, engine_status, findings, info)
    _fuzzy_hash(path, engines, engine_status, info)
    if category == "binary":
        _capa_scan(path, ext_opts["capa_cmd"], engines, engine_status, findings, info)
    else:
        # capa/binwalk 只对 binary/archive 有意义；其他类别显式记"不适用"，
        # 保证每个工具的 engine_status 键都存在（消费方不用猜）。
        _set_engine(engines, engine_status, "capa", present=False, ok=False,
                    error=f"not-applicable for category '{category}'")
    _clamav_scan(path, ext_opts["clamscan_cmd"], engines, engine_status, findings, info)
    _semgrep_scan(path, category, ext_opts["semgrep_cmd"], ext_opts["semgrep_config"],
                  engines, engine_status, findings, info)
    _binwalk_scan(path, category, ext_opts["binwalk_cmd"], engines, engine_status, info)
    if category not in ("binary", "archive"):
        _set_engine(engines, engine_status, "binwalk", present=False, ok=False,
                    error=f"not-applicable for category '{category}'")

    # ---- hash 情报：单一判定来源（语义见 _payload_threat_hashes 上方注释）----
    # 优先级：payload 情报 > xbits(--stdin) 无情报即视为无命中 > 显式 --hash-intel > 独立 CLI 默认本地名单。
    # 关键点：--stdin（xbits 调用）下绝不读本地名单，避免第二数据源与重复计分。
    payload_present, payload_hits = _payload_threat_hashes(opts.get("payload_intel"))
    orchestrated = bool(opts.get("orchestrated"))  # 由 xbits 以 --stdin 调起
    file_hashes = {file_meta["md5"], file_meta["sha1"], file_meta["sha256"]}
    intel_source = "none"
    intel_hit: dict | None = None
    if payload_present:
        intel_source = "xbits-payload"
        intel_hit = next((h for h in payload_hits if h["value"] in file_hashes), None)
    elif orchestrated:
        # xbits 未传情报：以“无命中”为准，绝不自行读盘另判（避免两套数据源并存）
        intel_source = "xbits-payload(none)"
    elif opts.get("hash_intel"):
        # 操作者显式指定本地名单（仅独立/调试场景；--stdin 下不会走到这里）；不联网
        local = _load_hash_intel(opts.get("hash_intel"))
        if local:
            intel_source = "local-file"
            intel_hit = next(
                ({"type": algo, "value": file_meta[key]}
                 for key, algo in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"))
                 if file_meta[key] in local),
                None,
            )
    else:
        # 独立 CLI：默认读取根目录威胁情报子模块 threat-intel/data/file_hash.txt（不联网）
        _repo_root = os.path.dirname(_SCRIPT_DIR)
        intel_path = None
        for _p in (os.path.join(_repo_root, "threat-intel", "data", "file_hash.txt"),
                   os.path.join(_SCRIPT_DIR, "intel", "known_bad.txt")):  # 兼容旧位置
            if os.path.isfile(_p):
                intel_path = _p
                break
        local = _load_hash_intel(intel_path)
        if local:
            intel_source = "local-file"
            intel_hit = next(
                ({"type": algo, "value": file_meta[key]}
                 for key, algo in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"))
                 if file_meta[key] in local),
                None,
            )
    if intel_hit:
        # 单一结论、单次计分：即便传入情报里同一文件有多条哈希命中，也只产出一条 finding。
        findings.append({"id": "intel.known_bad", "severity": "critical",
                         "detail": f"命中已知恶意 hash({intel_source}): {intel_hit['value']}",
                         "weight": 90})
    info["intel_source"] = intel_source
    info["intel_hit"] = intel_hit["value"] if intel_hit else None
    engines["hash_intel"] = {"source": intel_source, "hit": intel_hit is not None}

    # 标准库启发
    entropy = _entropy(head)
    printable = _printable_ratio(head)
    strings = _extract_strings(head)
    if category == "binary" and entropy > 7.2 and len(head) > 1024:
        # 只有在没有更细粒度 PE/ELF 判定时才用整体熵兜底
        if not any(f["id"].startswith(("pe.", "elf.")) for f in findings):
            findings.append({"id": "bin.high_entropy", "severity": "medium",
                             "detail": f"高熵({entropy})，可能加壳/加密", "weight": 20})
    b64 = re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", text)
    if b64:
        findings.append({"id": "content.long_base64", "severity": "low",
                         "detail": f"检测到 {len(b64)} 段长 base64 编码块", "weight": 10})
    name = os.path.basename(path)
    if re.search(r"\.(php|jsp|asp|aspx|phtml)\.(jpg|png|gif|txt|pdf)$", name, re.IGNORECASE):
        findings.append({"id": "name.double_extension", "severity": "medium",
                         "detail": f"可疑双扩展名伪装: {name}", "weight": 25})

    score = min(100, sum(f["weight"] for f in findings))
    severities = {f["severity"] for f in findings}
    strong_prefixes = ("yara.", "clamav.", "capa.", "semgrep.", "intel.")
    has_strong = any(f["id"].startswith(strong_prefixes) for f in findings)
    # V-22：只有"可信验证过的签名"才允许降级。本工具不做证书链/信任校验
    # （signature_verified 恒 False），因此证书表存在（signed_present）绝不构成
    # 洗白依据——恶意 PE 追加任意 Authenticode blob 不得改变 verdict。
    signature_verified = bool(info.get("pe", {}).get("signature_verified"))
    if signature_verified and not has_strong:
        # 已可信验证 + 只有启发式（导入/字符串/熵）命中：按合法二进制处理，
        # 避免把 kernel32.dll 等系统 DLL 误判为恶意（其导入表天然含注入类 API）。
        verdict = "clean"
        score = min(score, 20)
        findings.append({"id": "pe.signed_dampened", "severity": "low",
                         "detail": "签名可信验证通过且仅启发式命中，按合法二进制处理", "weight": 0})
    else:
        if "critical" in severities or score >= 60:
            verdict = "malicious"
        elif score >= 25 or "high" in severities:
            verdict = "suspicious"
        elif findings:
            verdict = "clean"
        else:
            verdict = "unknown" if category in ("binary", "other") else "clean"
        if verdict == "clean" and score >= 25:
            verdict = "suspicious"

    # V-20：外部引擎/解析失败 ≠ "未检出"。degraded 透出"证据不完整"，
    # 供 xbits/消费方对 completed 文档降低置信度，而不是当作干净。
    engine_errors = {k: v["error"] for k, v in engine_status.items()
                     if v.get("present") and not v.get("ok")}
    degraded = bool(engine_errors)

    evidence = [f"{f['id']}[{f['severity']}]" for f in findings]
    evidence.append(f"sha256={file_meta['sha256']}")
    evidence.append(f"category={category}")
    if info.get("pe", {}).get("imphash"):
        evidence.append(f"imphash={info['pe']['imphash']}")
    if "pe" in info:
        evidence.append(f"signed_present={info['pe'].get('signed_present')}")
        evidence.append(f"signature_verified={info['pe'].get('signature_verified')}")
    if degraded:
        evidence.append("degraded=true")

    return {
        "ok": True,
        "file": {"path": path, "name": name, "size": file_meta["size"],
                 "sha256": file_meta["sha256"], "sha1": file_meta["sha1"], "md5": file_meta["md5"]},
        "type": ftype,
        "verdict": verdict,
        "score": score,
        "degraded": degraded,
        "engine_errors": engine_errors,
        "entropy": entropy,
        "printable_ratio": round(printable, 3),
        "strings_sample": strings[:40],
        "findings": findings,
        "evidence": evidence,
        "info": info,
        "engines": engines,
        "engine_status": engine_status,
    }


def _load_input(args) -> dict:
    if args.stdin:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bad stdin json: {exc}"}
        if not isinstance(payload, dict) or not payload.get("path"):
            return {"ok": False, "error": "stdin json must be {\"path\": ...}"}
        return payload
    path = args.file or args.path
    if not path:
        return {"ok": False, "error": "no path given (use --file PATH or positional PATH)"}
    return {"path": path}


def _opts_from_args(args) -> dict:
    return {
        "rules_dir": args.rules_dir,
        "capa_cmd": args.capa_cmd,
        "clamscan_cmd": args.clamscan_cmd,
        "semgrep_cmd": args.semgrep_cmd,
        "semgrep_config": args.semgrep_config,
        "binwalk_cmd": args.binwalk_cmd,
        "hash_intel": args.hash_intel,
        "all_engines": args.all_engines,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="xbits static triage (no execution)")
    parser.add_argument("path", nargs="?", help="file to analyze")
    parser.add_argument("--file", help="file to analyze")
    parser.add_argument("--stdin", action="store_true", help="read {path:...} JSON from stdin")
    parser.add_argument("--rules-dir", default=None, help="YARA rules directory")
    parser.add_argument("--capa-cmd", default=None, help="external capa command (default 'capa')")
    parser.add_argument("--clamscan-cmd", default=None, help="external ClamAV command (default 'clamscan')")
    parser.add_argument("--semgrep-cmd", default=None, help="external semgrep command (default 'semgrep')")
    parser.add_argument("--semgrep-config", default=None, help="semgrep rules config (enables semgrep)")
    parser.add_argument("--binwalk-cmd", default=None, help="external binwalk command (default 'binwalk')")
    parser.add_argument("--hash-intel", default=None,
                        help="local known-bad hash list file (independent CLI only; "
                             "ignored under --stdin / when xbits supplies intel)")
    parser.add_argument("--all-engines", action="store_true",
                        help="try all external commands found on PATH")
    args = parser.parse_args(argv)

    payload = _load_input(args)
    if not payload.get("path"):
        print(json.dumps(payload, ensure_ascii=False))
        return 0 if payload.get("ok") else 1

    opts = _opts_from_args(args)
    # --stdin 即“由 xbits 编排调用”：以 payload 传入的情报为准，绝不自行读盘另判。
    opts["orchestrated"] = bool(args.stdin)
    opts["payload_intel"] = payload.get("intel") if args.stdin else None
    result = analyze(payload["path"], rules_dir=args.rules_dir, opts=opts)
    for key in ("sid", "flow_id", "sha256", "name"):
        if key in payload:
            result.setdefault("context", {})[key] = payload[key]
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
