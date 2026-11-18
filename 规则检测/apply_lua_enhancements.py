#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为转换后的 Suricata 规则挂载 Lua 上下文增强脚本。

只处理需要“内容命中后再做上下文/结构判定”的 HTTP 规则组：
  WebShell、SQLi、gray keyword、scanner、information disclosure、malicious URL、
  command injection、traversal/LFI、file upload、XSS。
不改写规则内容/pcre；只在 sid 前追加 lua:<script>.lua。
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUR = ROOT / "suricata"
DOC = ROOT / "docs" / "Lua强化清单.json"

SCANNER_RE = re.compile(
    r"(?:scanner|acunetix|netsparker|appscan|webinspect|nstalker|nmap|nikto|"
    r"sqlmap|nuclei|wpscan|joomscan|droopescan|zgrab|masscan|dirbuster|gobuster|"
    r"feroxbuster|ffuf|whatweb|httpx|wafw00f|burp|xray|nessus|openvas|qualys|"
    r"dirsearch|webscarab|paros|w3af|skipfish|vega|zap)",
    re.I,
)


def inject(line: str, script: str) -> tuple[str, bool]:
    if re.search(r"\blua\s*:", line, re.I):
        return line, False
    if re.search(r"\bsid\s*:", line) is None:
        return line, False
    new = re.sub(r"(?=\s*sid\s*:)", f" lua:{script}; ", line, count=1)
    return new, new != line


def main() -> int:
    stats: Counter[str] = Counter()
    files: Counter[str] = Counter()
    touched: list[dict] = []

    targets = [
        ("Web攻击/WebShell/webshell_detect.rules", "webshell_response.lua", "to_client"),
        ("Web攻击/WebShell/webshell_detect.request.rules", "webshell_param.lua", "to_server"),
        ("Web攻击/WebShell/webshell.rules", "flow", "flow"),
        ("Web攻击/WebShell/pvs-webshell.rules", "flow", "flow"),
        ("Web攻击/SQL注入/sql.rules", "sqli_context.lua", "all"),
        ("Web攻击/SQL注入/sql.strong.rules", "sqli_context.lua", "all"),
        ("Web攻击/SQL注入/sql.weak.rules", "sqli_context.lua", "all"),
        ("Web攻击/敏感关键词/gray_keyword.rules", "keyword_context.lua", "all"),
        ("Web攻击/信息泄露/information_disclose.rules", "info_disclosure_context.lua", "info"),
        ("恶意URL/malice_url_report.rules", "malice_url_context.lua", "to_client"),
        ("Web攻击/扫描器/web_scan.rules", "scanner_context.lua", "scanner"),
        ("Web攻击/命令执行/cmd_executed.request.rules", "cmdi_context.lua", "to_server"),
        ("Web攻击/命令执行/cmd_executed.rules", "cmdi_context.lua", "to_server"),
        ("Web攻击/命令注入/cmd.rules", "cmdi_context.lua", "to_server"),
        ("Web攻击/命令注入/oscmd.rules", "cmdi_context.lua", "to_server"),
        ("Web攻击/目录遍历/directory_tranversal.rules", "traversal_context.lua", "to_server"),
        ("Web攻击/目录遍历/directory_traversal.rules", "traversal_context.lua", "to_server"),
        ("Web攻击/文件包含/file_include.rules", "traversal_context.lua", "to_server"),
        ("Web攻击/文件包含/rfi.rules", "traversal_context.lua", "to_server"),
        ("Web攻击/文件上传/file_upload.rules", "upload_context.lua", "to_server"),
        ("Web攻击/XSS/pvs-xss.rules", "xss_context.lua", "to_server"),
        ("Web攻击/XSS/xss.rules", "xss_context.lua", "to_server"),
    ]

    for rel, script, mode in targets:
        path = SUR / rel
        if not path.exists():
            continue
        out_lines: list[str] = []
        changed = 0
        used_scripts: Counter[str] = Counter()
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw
            if line.lstrip().startswith("alert"):
                low = line.lower()
                use = None
                if mode == "flow":
                    if re.search(r"\bflow\s*:\s*to_client\b", low):
                        use = "webshell_response.lua"
                    else:
                        use = "webshell_param.lua"
                elif mode == "to_client":
                    if re.search(r"\bflow\s*:\s*to_client\b", low):
                        use = script
                elif mode == "to_server":
                    if re.search(r"\bflow\s*:\s*to_server\b", low):
                        use = script
                elif mode == "info":
                    if re.search(r"\bflow\s*:\s*to_client\b", low):
                        use = "info_disclosure_context.lua"
                    else:
                        use = "info_disclosure_request.lua"
                elif mode == "scanner":
                    # 只挂扫描器/工具指纹规则，不覆盖同文件里的注入规则
                    if SCANNER_RE.search(line):
                        use = script
                elif mode == "all":
                    use = script
                if use:
                    line, did = inject(line, use)
                    if did:
                        changed += 1
                        used_scripts[use] += 1
            out_lines.append(line)
        if changed:
            path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
            stats.update(used_scripts)
            files[rel] = changed
            touched.append({"file": rel, "script": "+".join(used_scripts.keys()), "count": changed})

    DOC.parent.mkdir(parents=True, exist_ok=True)
    # 少量规则需要单独的脚本，而不是整组扫描器 gate
    sid_targets = [
        ("Web攻击/扫描器/web_scan.rules", "info_disclosure_request.lua", {13109046}),
        ("Web攻击/扫描器/web_scan.rules", "sqli_context.lua", {13109105, 13109106}),
    ]
    for rel, script, sids in sid_targets:
        path = SUR / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        out: list[str] = []
        for line in lines:
            match = re.search(r"\bsid\s*:\s*(\d+)", line)
            if line.lstrip().startswith("alert") and match and int(match.group(1)) in sids:
                line, _did = inject(line, script)
            out.append(line)
        path.write_text("\n".join(out) + "\n", encoding="utf-8")

    # 重新按落盘内容统计，保证脚本可重复运行且报告不丢失已注入规则
    final_stats: Counter[str] = Counter()
    final_files: Counter[str] = Counter()
    for rel, _script, _mode in targets:
        path = SUR / rel
        if not path.exists():
            continue
        count = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.lstrip().startswith("alert"):
                continue
            match = re.search(r"\blua\s*:\s*([^;]+);", line, re.I)
            if match:
                final_stats[match.group(1).strip()] += 1
                count += 1
        if count:
            final_files[rel] = count
    # scanner 文件可能混挂多个脚本，单独按全文件重算
    for rel in {x[0] for x in sid_targets}:
        path = SUR / rel
        if path.exists():
            count = 0
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lstrip().startswith("alert") and "lua:" in line:
                    count += 1
            if count:
                final_files[rel] = count
    DOC.write_text(json.dumps({"stats": dict(final_stats), "files": dict(final_files), "items": touched}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"stats": dict(final_stats), "files": dict(final_files)}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())