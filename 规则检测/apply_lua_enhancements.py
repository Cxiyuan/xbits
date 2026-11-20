#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为转换后的 Suricata 规则挂载 Lua 上下文增强脚本。

只处理需要“内容命中后再做上下文/结构判定”的 HTTP 规则组：
  WebShell、SQLi、gray keyword、scanner、information disclosure、malicious URL、
  command injection、traversal/LFI、file upload、XSS。
不改写规则内容/pcre；只在 sid 前追加 lua:<script>.lua。

前置（V-13，R-05 根治）：目标规则必须已有 sticky buffer——`lua:` 之前存在
buffer 关键词（与 build_match_buffers.py/match_buffers.json 词汇一致，含
http_uri/http.header/payload/file_data/http_stat_code/http.method 等）。
无 buffer 的规则脚本拿不到 buffer 输入（init(args)=[]、args 不消费），
`lua:` 之前的匹配退化为 payload 全文，Lua 增强静默失效——因此默认**拒绝注入**：
  * 默认模式：跳过无 buffer 的规则并把明细写入 docs/Lua强化拒绝.json；
  * `--strict`：发现任何"无 buffer 可注入"规则 → 非零退出（CI 用）；
  * `--allow-no-buffer`：显式放开（仅调试用；列出但仍然注入并告警）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUR = ROOT / "suricata"
DOC = ROOT / "docs" / "Lua强化清单.json"
REJECT_DOC = ROOT / "docs" / "Lua强化拒绝.json"

# sticky-buffer 词汇表：与 build_match_buffers.py 的 ALIASES/BUFFER_CANON 语义一致
# （旧式 Snort 名 + Suricata dotted 名 + payload 显式重置词）
BUFFER_KEYWORD_RE = re.compile(
    r"\b(?:http_uri|http_raw_uri|http_method|http_header|http_raw_header|"
    r"http_cookie|http_client_body|http_server_body|http_host|http_raw_host|"
    r"http_user_agent|http_stat_code|http_stat_msg|file_data|dns_query|"
    r"http\.uri|http\.header|http\.method|http\.status|http\.cookie|"
    r"http\.user_agent|http\.host|http\.request_body|http\.response_body|"
    r"file\.data|dns\.query|payload|pkt_data)\b",
    re.I,
)

SCANNER_RE = re.compile(
    r"(?:scanner|acunetix|netsparker|appscan|webinspect|nstalker|nmap|nikto|"
    r"sqlmap|nuclei|wpscan|joomscan|droopescan|zgrab|masscan|dirbuster|gobuster|"
    r"feroxbuster|ffuf|whatweb|httpx|wafw00f|burp|xray|nessus|openvas|qualys|"
    r"dirsearch|webscarab|paros|w3af|skipfish|vega|zap)",
    re.I,
)


def rule_body(line: str) -> str:
    end = line.rfind(")")
    return line[line.find("(") + 1 : end if end >= 0 else len(line)]


def has_buffer_before_lua(line: str) -> bool:
    """V-13 前置：`lua:`（注入点 = sid: 之前）之前必须已绑定 sticky buffer。

    两种状态都合法：
      * 规则已带 `lua:` → 检查 lua: 之前有无 buffer；
      * 规则未带 `lua:`（待注入候选）→ lua 将插在 sid: 之前，检查 sid: 之前有无 buffer。
    """
    body = rule_body(line)
    m = re.search(r"\blua\s*:", body, re.I)
    if m:
        return bool(BUFFER_KEYWORD_RE.search(body[: m.start()]))
    m_sid = re.search(r"\bsid\s*:", body, re.I)
    if m_sid:
        return bool(BUFFER_KEYWORD_RE.search(body[: m_sid.start()]))
    return False


def inject(line: str, script: str) -> tuple[str, bool]:
    if re.search(r"\blua\s*:", line, re.I):
        return line, False
    if re.search(r"\bsid\s*:", line) is None:
        return line, False
    new = re.sub(r"(?=\s*sid\s*:)", f" lua:{script}; ", line, count=1)
    return new, new != line


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="发现任何'无 buffer 可注入'规则 → 非零退出（CI 门禁用）")
    ap.add_argument("--allow-no-buffer", action="store_true",
                    help="显式放开：无 buffer 的规则也注入（仅调试；仍逐条列出）")
    args = ap.parse_args()

    stats: Counter[str] = Counter()
    files: Counter[str] = Counter()
    touched: list[dict] = []
    rejected: list[dict] = []  # V-13：无 buffer 被拒绝注入的规则明细
    hard_failures = 0

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
                    if re.search(r"\blua\s*:", line, re.I):
                        pass  # 已挂脚本，不动
                    elif not has_buffer_before_lua(line):
                        # V-13：无 sticky buffer → Lua 增强必然静默失效，拒绝注入
                        hard_failures += 1
                        sid = re.search(r"\bsid\s*:\s*(\d+)", line)
                        rejected.append({
                            "sid": int(sid.group(1)) if sid else None,
                            "file": rel,
                            "script": use,
                            "mode": mode,
                            "head": line[:160],
                        })
                        if args.allow_no_buffer:
                            line, did = inject(line, use)
                            if did:
                                changed += 1
                                used_scripts[use] += 1
                        # 非 allow 模式：保持原行（纯 content/pcre 规则仍生效）
                    else:
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
            if (line.lstrip().startswith("alert") and match
                    and int(match.group(1)) in sids
                    and not re.search(r"\blua\s*:", line, re.I)):
                if not has_buffer_before_lua(line) and not args.allow_no_buffer:
                    hard_failures += 1
                    rejected.append({
                        "sid": int(match.group(1)),
                        "file": rel,
                        "script": script,
                        "mode": "sid-target",
                        "head": line[:160],
                    })
                else:
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
    REJECT_DOC.write_text(json.dumps({
        "rejected_count": len(rejected),
        "note": "V-13 前置拒绝明细：这些规则在 lua: 之前没有 sticky buffer，"
                "Lua 增强必然静默失效（脚本 init(args)=[] 不消费 buffer 输入）。"
                "补 buffer 或剔除由 convert/维护流程处理；本脚本不静默注入。",
        "items": rejected,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    summary = {"stats": dict(final_stats), "files": dict(final_files),
               "rejected_no_buffer": len(rejected)}
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    if rejected:
        print(f"lua-without-buffer rejected: {len(rejected)} 条（明细见 docs/Lua强化拒绝.json）")
        if args.strict:
            print("FAIL: 存在'无 buffer 可注入'规则（--strict 门禁）", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())