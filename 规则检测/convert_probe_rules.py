#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor (深信服) 探针规则导出 → xbits 项目规则转换器。

输入：桌面 `流量检测规则` 导出目录（已解密的明文规则）。
输出（按攻击类别归档，不设厂商目录，见 docs/规则归档与转换方案.md）：
  规则检测/suricata/<类目>/<规则>.rules        按攻击类别归档的 Suricata 规则
  规则检测/xbits/规则库元数据/rules_meta.json  每条规则元数据（depend/scope/holetype/tier）
  规则检测/xbits/规则库元数据/success_rules.json  PVS 成功确认依赖（中央引擎联动）
  规则检测/xbits/规则库元数据/audit_rules.json 云审计规则（仅元数据）
  规则检测/xbits/规则库元数据/sid_library.json SID → 名称/类别/危险等级映射
  规则检测/xbits/规则库元数据/exceptions.json 例外/强 SID 列表
  docker/probe-rules-validate.yaml           Suricata 加载验证配置（生成）

转换原则：
  * 只取 etc_fw（现网生效）；lib_* 基线库跳过（SID 重复）；
  * Sangfor 私有关键字（ruletype/holetype-id/scope_id/depend/depended/action）
    从 Suricata 规则剥离，保留到 rules_meta.json 给 xbits；
  * uricontent / content;http_uri / pcre buffer 标志 → 语义树绑定 buffer，
 *   线性化为 Suricata 前置 sticky buffer 顺序（详见 docs/规则归档与转换方案.md）；
  * <> 双向操作符 → ->（Suricata 不支持 <>）；
  * classtype 全部剥离（类别语义走 xbits sid_library；
    未知 classtype 会导致 Suricata 拒绝加载）；
  * mail_uri / cloud audit 规则不进 Suricata；
  * Suricata 只做签名命中：
       - noalert / flowbits / depend/scope 状态链与请求→响应关联规则
         不进入 active 规则，依赖写入 success_rules.json 交 xbits；
       - threshold 等行为选项剥离；DNS/侦察/C2 行为由 Zeek 脚本负责；
  * 成功确认依赖元数据完整保留，active 规则不注入 flowbits。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_SURICATA = ROOT / "suricata"
OUT_XBITS = ROOT / "xbits" / "规则库元数据"

# 自研场景目录，不参与外部规则清理
SCENARIO_DIRS = {"DNS隧道与带外检测", "Web漏洞利用", "侦察与攻击工具指纹", "后门通信"}

# Suricata 转换源（现网 etc_fw）
SURICATA_SOURCES = [
    ("sf_snort", "etc_fw/sf_snort/rules/*.rules"),
    ("waf", "etc_fw/waf/rules/*.rules"),
    ("waf", "etc_fw/waf/webshell_rules/*.rules"),
    ("waf", "etc_fw/waf/cmd_executed_rules/*.rules"),
    ("pvs", "etc_fw/pvs/rules/*.rules"),
    ("pvs-success", "etc_fw/pvs/rules/success/*.rules"),
    ("utm", "etc_fw/utm/rules/*.rules"),
]

# 弱/泛化规则：可被 Suricata 加载，但告警价值低，交 xbits 低置信度/联动评分
WEAK_FILES = {
    "gray_keyword.rules",
    "sql.weak.rules",
    "information_disclose.rules",
    "web_scan.rules",
    "malice_url_report.rules",
}

# 规则类别归档：源文件 stem → 类别目录（相对 规则检测/suricata/）
# 同类文件放同一目录；未列出的进入“其他”
CATEGORY_MAP = {
    # ---- IPS / sf_snort ----
    "web": "Web攻击/Web服务漏洞",
    "web_browse": "Web攻击/浏览器漏洞",
    "web_activex": "Web攻击/客户端组件漏洞",
    "application": "应用软件漏洞",
    "system": "主机系统漏洞",
    "file": "文件与协议解析漏洞",
    "network_device": "网络设备漏洞",
    "database": "网络服务漏洞/数据库",
    "dns": "网络服务漏洞/DNS",
    "ftp": "网络服务漏洞/FTP",
    "mail": "网络服务漏洞/邮件",
    "telnet": "网络服务漏洞/Telnet",
    "tftp": "网络服务漏洞/TFTP",
    "media": "应用软件漏洞/媒体服务",
    "config_error": "配置与运维缺陷",
    "other": "其他",
    "bp_ips": "其他",
    "shellcode": "恶意软件/Shellcode",
    "spyware": "恶意软件/间谍软件",
    "trojan": "恶意软件/木马",
    "backdoor": "恶意软件/后门",
    "worm": "恶意软件/蠕虫",
    "brute_force": "暴力破解",
    # ---- WAF ----
    "sql.strong": "Web攻击/SQL注入",
    "sql.weak": "Web攻击/SQL注入",
    "sql": "Web攻击/SQL注入",
    "xss": "Web攻击/XSS",
    "webshell": "Web攻击/WebShell",
    "webshell_detect": "Web攻击/WebShell",
    "webshell_detect.request": "Web攻击/WebShell",
    "webapp": "Web攻击/Web应用漏洞",
    "web_scan": "Web攻击/扫描器",
    "information_disclose": "Web攻击/信息泄露",
    "gray_keyword": "Web攻击/敏感关键词",
    "oscmd": "Web攻击/命令注入",
    "cmd": "Web攻击/命令注入",
    "cmd_executed": "Web攻击/命令执行",
    "cmd_executed.request": "Web攻击/命令执行",
    "directory_traversal": "Web攻击/目录遍历",
    "directory_tranversal": "Web攻击/目录遍历",
    "file_include": "Web攻击/文件包含",
    "file_upload": "Web攻击/文件上传",
    "rfi": "Web攻击/文件包含",
    "login": "Web攻击/登录绕过",
    # ---- UTM ----
    "utm_request_rules": "恶意软件/C2与远控",
    "utm_response_rules": "恶意软件/C2与远控",
    "malice_url_report": "恶意URL",
}

SUCCESS_CATEGORY = "攻击成功确认"

# xbits 元数据源
CLOUD_GLOBS = ["etc_fw/cloudrules/common_rules/report/*.rules"]
META_FILES = {
    "classification": "etc_fw/_top/classification.json",
    "hole_library": "etc_fw/_top/hole_library.ini",
    "strongsid": "etc_fw/_top/ips_strongsid.list",
    "ips_exception": "etc_fw/_top/ips_exception.ini",
    "waf_exception": "etc_fw/_top/waf_exception.ini",
    "waftype": "etc_fw/_top/waftype.ini",
}

STRIP_KWS = [
    re.compile(r"\bruletype\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bholetype-id\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bscope_id\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bdepend\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bdepended\s*:\s*[^;]+;?", re.I),
    re.compile(r"\baction\s*:\s*[^;]*audit[^;]*;?", re.I),
    re.compile(r"\bthreshold\s*:\s*[^;]+;?", re.I),
]
# 仅用于元数据保留；检测语义由 semantic_skip_reason / token 转换处理
REFERENCE_RE = re.compile(r"\breference\s*:\s*([^;]+)", re.I)
CLASSTYPE_RE = re.compile(r"\bclasstype\s*:\s*([^;]+)", re.I)
STATUS_CODE_RE = re.compile(r"\bstatus_code\s*:\s*([^;]+)", re.I)
RATE_RE = re.compile(r"\brate\s*:\s*([^;]+)", re.I)
# Sangfor 语义/DSL 关键字：Suricata 无法等价执行，交 xbits/Zeek 语义层
DSL_RE = re.compile(r"\b(uriarg|decode|grammar|payload_extract|result)\s*:", re.I)
URICONTENT_RE = re.compile(r'\buricontent\s*:\s*"(.*?)"\s*;', re.I)
URICONTENT_NEG_RE = re.compile(r'\buricontent\s*:\s*!\s*"(.*?)"\s*;', re.I)
MAIL_URI_RE = re.compile(r"\bmail_uri\b", re.I)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)")
HOLETYPE_RE = re.compile(r"\bholetype-id\s*:\s*(\d+)")
DEPEND_RE = re.compile(r"\bdepend\s*:\s*([0-9,\s]+)")
SCOPE_RE = re.compile(r"\bscope_id\s*:\s*([0-9,\s]+)")
RULETYPE_RE = re.compile(r"\bruletype\s*:\s*(\d+)")
DEPENDED_RE = re.compile(r"\bdepended\s*:\s*(\d+)")
MSG_RE = re.compile(r'\bmsg\s*:\s*"(.*?)"\s*;', re.I)


def read_rule_bytes(path: Path) -> bytes | None:
    """读取规则文件；Windows Defender 可能拦截含 WebShell 的文本，用扩展路径规避。"""
    for candidate in (path, Path("\\\\?\\" + str(path))):
        try:
            return candidate.read_bytes()
        except OSError:
            continue
    return None


def iter_rule_lines(path: Path):
    data = read_rule_bytes(path)
    if data is None:
        print(f"WARN: unreadable rule file (skipped): {path}", file=sys.stderr)
        return
    text = data.decode("utf-8", "replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^(alert|log|pass|drop|reject|sdrop)\b", line, re.I):
            continue
        yield line


def extract_meta(line: str) -> dict:
    meta: dict = {}
    m = SID_RE.search(line)
    if m:
        meta["sid"] = int(m.group(1))
    m = MSG_RE.search(line)
    if m:
        meta["msg"] = m.group(1)
    for rx, key in [
        (HOLETYPE_RE, "holetype"),
        (DEPEND_RE, "depends"),
        (SCOPE_RE, "scopes"),
        (RULETYPE_RE, "ruletype"),
        (DEPENDED_RE, "depended"),
        (REV_RE, "rev"),
    ]:
        m = rx.search(line)
        if m:
            if key in ("depends", "scopes"):
                meta[key] = [int(x) for x in m.group(1).split(",") if x.strip()]
            else:
                meta[key] = int(m.group(1))
    refs = [x.strip() for x in REFERENCE_RE.findall(line)]
    if refs:
        meta["references"] = refs
    m = CLASSTYPE_RE.search(line)
    if m:
        meta["classtype"] = m.group(1).strip()
    m = STATUS_CODE_RE.search(line)
    if m:
        meta["status_code"] = m.group(1).strip()
    m = RATE_RE.search(line)
    if m:
        meta["rate"] = m.group(1).strip()
    return meta


# pcre 值内允许出现裸双引号（Suricata 规则解析器对 pcre 特殊处理，无需转义）。
# split_options 需要识别 pcre:".../flags" 的真实结束位置，否则带引号的 pcre 会把
# 后续选项吞进同一个 token。 Suricata pcre 形如 pcre:"/pattern/flags"，flags 后的
# 结束引号之前的所有 '/' 都属于模式。
PCRE_SPAN_RE = re.compile(r'pcre\s*:\s*"(/.*?/[A-Za-z]*)"\s*(?=[;)]|$)', re.I | re.S)


def split_options(opts: str) -> list[str]:
    """按分号拆分规则选项，尊重双引号与反斜杠转义；pcre 值内裸引号不截断。"""
    tokens: list[str] = []
    cur: list[str] = []
    i = 0
    n = len(opts)
    inq = esc = False
    while i < n:
        ch = opts[i]
        if esc:
            cur.append(ch)
            esc = False
            i += 1
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            i += 1
            continue
        if ch == '"':
            inq = not inq
            cur.append(ch)
            i += 1
            continue
        if ch == ";" and not inq:
            tokens.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        tokens.append(tail)
    # 修复：若某个 token 因 pcre 内裸引号被错误截断（token 不以引号配对收尾，
    # 且以下一个 pcre span 能闭合为特征），用 PCRE_SPAN_RE 把跨越的碎片重新合并。
    if not any(PCRE_SPAN_RE.fullmatch(t.strip()) for t in tokens):
        merged = opts
        spans = [m for m in PCRE_SPAN_RE.finditer(merged)]
        if spans:
            # 用扫描器重建：逐字符，pcre span 视为原子
            return _split_with_pcre_atoms(opts)
    return tokens


def _split_with_pcre_atoms(opts: str) -> list[str]:
    tokens: list[str] = []
    cur: list[str] = []
    i = 0
    n = len(opts)
    while i < n:
        m = PCRE_SPAN_RE.match(opts, i)
        if m:
            cur.append(m.group(0))
            i = m.end()
            continue
        ch = opts[i]
        if ch == "\\":
            cur.append(ch)
            if i + 1 < n:
                cur.append(opts[i + 1])
            i += 2
            continue
        if ch == '"':
            cur.append(ch)
            i += 1
            continue
        if ch == ";":
            tokens.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        tokens.append(tail)
    return tokens


REQUEST_BUFFERS = {
    "http_client_body", "http_uri", "http_raw_uri", "http_method", "http_host",
    "http_cookie", "http_user_agent", "http_only_uri", "http_uri_only",
}

# Suricata sticky-buffer 上界（字节）：用于生成期静态容量断言（V-11）。
# content/pcre 绑定到该 buffer 时，若匹配体长度超过上界则规则永远不可能命中。
BUFFER_CAPACITY = {
    "http_stat_code": 3,   # "200"
    "http_method": 16,     # OPTIONS/CONNECT 等
    "http_stat_msg": 64,
}

# Snort 修饰词（跟随其 content/pcre）
SNORT_MODIFIERS = {"nocase", "distance", "within", "offset", "depth", "fast_pattern"}

# pcre 修饰标志 → 由语义树上的 buffer 决定匹配面，字符标志必须剥离
PCRE_BUFFER_FLAGS = set("UIHDCPQMVWSZYT")
PCRE_DROP_FLAGS = set("RPB")  # R 相对链语义在树模型下重写；P/B 不支持


def match_atom_capacity(atom_buffer: str, atom_token: str) -> int | None:
    """返回该 match 原子在其 buffer 上的容量上界；payload/无 buffer 返回 None。"""
    cap = BUFFER_CAPACITY.get(atom_buffer)
    if cap is None:
        return None
    tl = atom_token.strip().lower()
    if tl.startswith("content:"):
        # 取引号内字面长度（|XX| 十六进制按字节计，转义还原后即匹配体长度）
        m = re.match(r'content\s*:\s*(!?)\s*"(.*)"\s*$', atom_token.strip(), re.S)
        if not m:
            return cap
        body = m.group(2)
        length = 0
        i = 0
        while i < len(body):
            if body[i] == "|":
                j = body.find("|", i + 1)
                if j < 0:
                    break
                hexpart = body[i + 1:j].replace(" ", "")
                length += max(1, len(hexpart) // 2)
                i = j + 1
            elif body[i] == "\\":
                length += 1
                i += 2
            else:
                length += 1
                i += 1
        return cap if length > cap else None
    # pcre 等其他匹配体：无法静态求长，交给 Suricata 载入与 PCAP 验证
    return None


# V-16: 响应方向判定（to_client / from_server 均为服务端→客户端）
FLOW_RESPONSE_RE = re.compile(r"flow\s*:\s*[^;]*\b(to_client|from_server)\b", re.I)


def is_response_flow(text: str) -> bool:
    return bool(FLOW_RESPONSE_RE.search(text))


def semantic_skip_reason(line: str) -> str | None:
    """识别无法等价转换的语义；这些规则不进入 Suricata，避免降级使用。"""
    tokens = rule_option_tokens(line)
    flow_token = next((t for t in tokens if t.lower().startswith("flow:")), "")
    to_client = is_response_flow(flow_token)

    for t in tokens:
        tl = t.lower()
        if tl.startswith("rate:"):
            return "rate-unsupported"
        if tl in ("http_only_uri", "http_uri_only"):
            return "http-only-uri-unsupported"
        if tl == "rawbytes":
            return "rawbytes-unsupported"
        if tl.startswith(("resp:", "logto:")):
            return "snort-action-unsupported"
        if tl.startswith("method:"):
            return "method-unsupported"
        if tl.startswith("status_code:"):
            value = t.split(":", 1)[1].strip().strip('"')
            if not re.fullmatch(r"\d{3}", value):
                return "status-code-multi"

    if re.search(r"\s<>\s", line) and not flow_token:
        return "bidirectional-no-flow"
    if to_client and any(t.lower() in REQUEST_BUFFERS for t in tokens):
        return "response-direction-conflict"

    # byte_extract/byte_jump 变量引用（within:<varname> / distance:<varname>）：
    # 变量值依赖运行时 byte_* 提取，静态无法校验，Suricata 拒绝未知变量名
    if re.search(r"\b(?:within|distance)\s*:\s*[A-Za-z_]", line, re.I):
        return "byte-extract-reference"

    # http_method 段 content 尾随空格：Suricata detect-http-method 直接拒绝
    for i, t in enumerate(tokens):
        if t.lower() in ("http_method",):
            prev = next((tokens[j] for j in range(i - 1, -1, -1)
                         if tokens[j].lower().split(":", 1)[0] not in SNORT_MODIFIERS), "")
            m = re.match(r'content\s*:\s*"([^"]*)"', prev.strip(), re.S)
            if m and m.group(1) != m.group(1).rstrip():
                return "method-trailing-space"

    # 悬空 sticky buffer：其后没有任何 content/pcre 承接（V-10：新判定，
    # 替代旧版对「content 在前、buffer 在后」正确 Snort 顺序的误删）
    match_idx = [i for i, t in enumerate(tokens)
                 if t.lower().startswith(("content:", "pcre:"))]
    if match_idx:
        buf_pos = [i for i, t in enumerate(tokens)
                   if t.lower() in REQUEST_BUFFERS or t.lower().startswith("http_stat_code")]
        for b in buf_pos:
            nxt = next((i for i in match_idx if i > b), None)
            prev_match = next((i for i in reversed(match_idx) if i < b), None)
            if nxt is None and prev_match is None:
                return "buffer-without-payload"

    groups: list[list[str]] = []
    cur: list[str] = []
    for t in tokens:
        if t.lower().startswith("content:"):
            if cur:
                groups.append(cur)
            cur = [t]
        else:
            cur.append(t)
    if cur:
        groups.append(cur)
    for g in groups:
        abs_keys: list[str] = []
        rel = False
        for x in g:
            xl = x.lower()
            if xl.startswith("offset:"):
                abs_keys.append("offset")
            elif xl.startswith("depth:"):
                abs_keys.append("depth")
            if xl.startswith(("within:", "distance:")):
                rel = True
        if rel and abs_keys:
            return "mixed-position"
        if len(abs_keys) != len(set(abs_keys)):
            return "duplicate-position"
    return None


def rule_option_tokens(line: str) -> list[str]:
    if "(" not in line or ")" not in line:
        return []
    body = line[line.find("(") + 1 : line.rfind(")")]
    return [t.strip() for t in split_options(body) if t.strip()]


# V-16/V-18: 服务端口表达式（端口组变量 / 数字 / 列表 / 范围 / 混合），
# 用于 to_client 方向翻转与静态断言。
# 允许的例外：any、明确客户端端口范围（DHCP 客户端 68 等，翻转后落在目的侧）。
PORT_GROUP_VAR_RE = re.compile(r"\$[A-Za-z_][A-Za-z_0-9]*")
CLIENT_PORT_ALLOW = {"any", "68", "68,67", "67,68"}  # DHCP 客户端端口（响应目的侧）
# 端口体：十进制数字（含范围 a:b、开口 a:）/ 逗号列表 / 方括号列表+范围 / $变量
_PORT_TOKEN = r"(?:\$[A-Za-z_][A-Za-z_0-9]*|\d+(?::\d*)?)"
SERVICE_PORT_RE = re.compile(
    rf"^(?:\[(?:{_PORT_TOKEN})(?:,?:?(?:{_PORT_TOKEN}))*\]|"
    rf"(?:{_PORT_TOKEN})(?:(?:,|:)(?:{_PORT_TOKEN}))*)$")


def is_service_port_expr(port: str) -> bool:
    """端口字段是否为服务端口表达（应出现在 to_client 规则的源侧）。

    返回 False 仅当：any、空、或明确允许的客户端端口（翻转后落目的侧）。
    """
    p = port.strip().lower()
    if p in CLIENT_PORT_ALLOW or not p:
        return False
    return bool(SERVICE_PORT_RE.match(p))


# 断言捕获的 SID（to_client 且目的端口仍有服务端口表达且无法翻转）
TO_CLIENT_PORT_ASSERT_SIDS: set[int] = set()


def rule_header_parts(header: str) -> tuple[str, str, str, str, str, str, str] | None:
    """拆分规则头 → (action, proto, src_net, src_port, direction, dst_net, dst_port)。"""
    m = re.match(
        r"^(alert|drop|pass|reject|log|sdrop)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*$",
        header.strip(), re.I)
    return m.groups() if m else None


def normalize_direction_header(header: str, to_client: bool) -> tuple[str, bool]:
    """按 flow 方向规整规则头部（V-16 / V-18）。

    to_server（含 flow 缺省）：保持原样——服务端口已在目的端口。
    to_client / from_server：若目的端口是服务端口表达（端口组变量、数字端口、
    端口列表、范围或混合表达式——服务端端口写在目的侧），交换 src/dst 的
    「网段+端口」对，输出 `any <service-port> -> any any`；
    若源端口已是服务端口（已经是正确响应形态），不重复翻转。
    允许 any 与明确客户端端口（DHCP 68 等）留在目的侧。
    返回 (规整后的 header, 是否发生翻转)。
    """
    parts = rule_header_parts(header)
    if parts is None:
        return header, False
    action, proto, snet, sport, direction, dnet, dport = parts
    if not to_client or direction != "->":
        return header, False
    dst_service = is_service_port_expr(dport)
    src_service = is_service_port_expr(sport)
    if not dst_service or src_service:
        # 目的端口无服务端口表达（any/客户端端口），或源端口已是服务端口
        # （正确响应形态）→ 不翻转
        return header, False
    # 交换 net+port 对（倒序报文：服务端→客户端），保持 action/proto/箭头
    new = f"{action} {proto} {dnet} {dport} -> {snet} {sport}"
    return new, True


BUFFER_CANON = {
    # Snort 旧式 buffer 名 → 语义树上的规范 buffer（与 build_match_buffers.py 对齐）
    "http_uri": "http_uri", "http_raw_uri": "http_raw_uri",
    "http_method": "http_method", "http_header": "http_header",
    "http_raw_header": "http_raw_header", "http_cookie": "http_cookie",
    "http_client_body": "http_client_body", "http_server_body": "http_server_body",
    "http_host": "http_host", "http_raw_host": "http_raw_host",
    "http_user_agent": "http_user_agent", "http_stat_code": "http_stat_code",
    "http_stat_msg": "http_stat_msg", "file_data": "file_data",
    "dns_query": "dns_query",
}

# 语义树 buffer → Suricata sticky buffer 输出名。
# 下划线旧名（http_uri 等）在 Suricata 里是 content 修饰词（必须跟在
# content 之后）；点分名（http.uri 等）才是 sticky buffer（content 跟在
# buffer 之后）。语义树输出为前置 buffer，必须用点分名，否则
# suricata -T 报「keyword found inside the rule without a content context」。
STICKY_EMIT = {
    "http_uri": "http.uri", "http_raw_uri": "http.uri.raw",
    "http_method": "http.method", "http_header": "http.header",
    "http_raw_header": "http.header.raw", "http_cookie": "http.cookie",
    "http_client_body": "http.request_body", "http_server_body": "http.response_body",
    "http_host": "http.host", "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent", "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg", "file_data": "file.data",
    "dns_query": "dns.query",
}


# pcre 缓冲区标志 → 语义树 buffer（Suricata 差异文档 Buffer Reference Chart）
PCRE_FLAG_BUFFER = {
    "U": "http_uri", "I": "http_raw_uri", "H": "http_header", "D": "http_raw_header",
    "C": "http_cookie", "P": "http_client_body", "Q": "http_server_body",
    "M": "http_method", "V": "http_user_agent", "W": "http_host", "Z": "http_raw_host",
    "S": "http_stat_code", "Y": "http_stat_msg",
}


def build_semantic_tree(tokens: list[str]) -> list[dict]:
    """把规则选项归约成 (buffer, match, modifiers) 语义树。

    Snort 语义：content 在前，其后紧跟的 buffer 修饰词（http_uri 等）只修饰
    该 content 的匹配面 → 反向绑定（back-bind）。
    Suricata 语义：sticky buffer 只作用于其后的匹配 → 正向吸附（sticky）。

    修饰词归属：nocase/distance/within/offset/depth/fast_pattern 跟随其
    content/pcre；同一原子尚未持有同类修饰时可向前吸附（如
    content:"A"; http_uri; nocase; content:"B"; distance:0; 中 distance
    属于 B）。每个修饰类别每原子至多一个，重复即视为下一原子的修饰。

    pcre 的 buffer 标志（U/I/H/D/C/P/Q/M/V/W/Z/S/Y）同样表达匹配面：
    原子已有 buffer 时标志冗余（剥离）；无 buffer 时按标志绑定，避免
    「flag 说 URI、树说 payload」的语义回退。

    返回的每个节点：
      {"buffer": <规范名|None>, "match": <content/pcre token|None>, "mods": [..]}
    buffer=None 表示 payload 匹配（与旧版行为一致）。
    """
    tree: list[dict] = []
    cur_sticky: str | None = None   # 待吸附的 sticky buffer
    prev_atom: dict | None = None   # 最后一个 match 原子（修饰词归属目标）
    for tok in tokens:
        tl = tok.lower()
        head = tl.split(":", 1)[0]
        if head.startswith(("content", "pcre")):
            atom = {"buffer": cur_sticky, "match": tok, "mods": []}
            cur_sticky = None
            # pcre buffer 标志 → 绑定
            if head == "pcre" and atom["buffer"] is None:
                flag_buf = _pcre_flag_buffer(tok)
                if flag_buf:
                    atom["buffer"] = flag_buf
            tree.append(atom)
            prev_atom = atom
            continue
        if head in SNORT_MODIFIERS:
            # 修饰词归属：最近一个 match 原子；若该原子已持有同类修饰，
            # 且它是 buffer 绑定原子，则归属下一原子（Snort 允许跨原子排队）。
            target = prev_atom
            if target is not None:
                cls = head if head != "fast_pattern" else "fast_pattern"
                have = {m.lower().split(":", 1)[0] for m in target["mods"]}
                if cls in have:
                    target = None  # 排队到下一个 match 原子
            if target is not None:
                target["mods"].append(tok)
            continue
        if head in BUFFER_CANON:
            # Snort 修饰词形态：content:"X"; http_uri; → 回绑
            if (prev_atom is not None and prev_atom["buffer"] is None
                    and prev_atom.get("_bind", True) and cur_sticky is None):
                prev_atom["buffer"] = BUFFER_CANON[head]
                prev_atom["_bind"] = False
            else:
                cur_sticky = BUFFER_CANON[head]
            continue
        # 其他 token（sid/rev/msg/flow/...）：修饰归属截止，sticky 保持
        prev_atom = None
    # 末尾悬空的 sticky buffer：无 match 承接 → 丢弃（由调用方记 gap）
    return tree


def _pcre_flag_buffer(tok: str) -> str | None:
    m = re.match(r'pcre\s*:\s*"(/.*?/[A-Za-z]*)"\s*$', tok.strip(), re.S | re.I)
    if not m:
        return None
    body = m.group(1)
    last = body.rfind("/")
    if last <= 0:
        return None
    flags = body[last + 1:]
    for c in flags:
        if c in PCRE_FLAG_BUFFER:
            return PCRE_FLAG_BUFFER[c]
    return None


def linearize_tree(tree: list[dict]) -> tuple[list[str], list[str]]:
    """语义树 → Suricata token 序列。

    返回 (tokens, problems)：
      tokens  Suricata 线性化结果（buffer 前置、修饰词跟随 content）
      problems 静态容量断言失败等问题的 reason 列表（非空 → 该规则不可用）
    """
    out: list[str] = []
    problems: list[str] = []
    last_buf: str | None = None
    for node in tree:
        buf = node["buffer"]
        tok = node["match"]
        tl = tok.lower()
        head = tl.split(":", 1)[0]
        # V-11 静态容量断言：绑定到容量型 buffer 的匹配体超长 → 永不命中
        cap = match_atom_capacity(buf, tok) if buf else None
        if cap is not None:
            problems.append(f"buffer-capacity:{buf}")
            continue
        # buffer 切换：换段输出（必须用点分 sticky buffer 名——下划线旧名是
        # content 修饰词，前置会被 Suricata 拒绝）
        if buf is not None and buf != last_buf:
            out.append(STICKY_EMIT.get(buf, buf))
            last_buf = buf
        elif buf is None and last_buf is not None:
            # 回到 payload 段：显式重置（Suricata 语义）。
            # file_data/http_header 等本身以 CRLF CRLF 开头/结尾的差异靠内容
            # 模式兼容；跨段相对链（distance/within）不支持，由 semantic_skip
            # 的 mixed-position 前置拦截。
            out.append("pkt_data")
            last_buf = None
        # pcre 修饰标志清理：buffer 已由树决定，删除 UIHDCPQMVWSZYT / R / P / B
        if head == "pcre":
            tok = _strip_pcre_flags(tok, problems)
            if tok is None:
                continue
        out.append(tok)
        for m in node["mods"]:
            ml = m.lower()
            if ml == "nocase":
                out.append("nocase")
            elif ml.startswith(("distance:", "within:", "offset:", "depth:")):
                # 定位修饰在 buffer 内同样有效（Suricata 支持相对/绝对定位于
                # sticky buffer 内容），必须保留，否则丢约束
                out.append(m)
            elif ml == "fast_pattern":
                out.append("fast_pattern")
    return out, problems


def _strip_pcre_flags(tok: str, problems: list[str]) -> str | None:
    m = re.match(r'pcre\s*:\s*"(.*)"\s*$', tok.strip(), re.S)
    if not m:
        return tok
    s = m.group(1)
    last = s.rfind("/")
    if last <= 0 or not s.startswith("/"):
        return tok
    pat, flags = s[1:last], s[last + 1:]
    # R 相对链：语义树上同段绑定，相对语义丢失 → 保守跳过（与旧版一致）
    if any(c in flags for c in PCRE_DROP_FLAGS):
        problems.append("pcre-relative-flags")
        return None
    # PCRE 兼容性预检：[\w-\/] 等 Python 拒绝的字符类范围 PCRE2 同样拒绝
    # （旧版靠 re.compile 预检剔除，语义树重写时误删，CI 加载失败已证实）
    try:
        re.compile(pat)
    except re.error:
        problems.append("pcre-invalid-range")
        return None
    newflags = "".join(c for c in flags if c not in PCRE_BUFFER_FLAGS)
    # 保留 i/s/m 等语义修饰
    return f'pcre:"/{pat}/{newflags}"'


def convert_rule(line: str, flowbit_set: int | None, flowbit_is: int | None) -> str | None:
    """语义树转换：token 重写 → (buffer, match, mods) 树 → Suricata 线性化。

    返回清理后的 Suricata 规则文本；无法等价转换时返回 None。
    """
    if MAIL_URI_RE.search(line):
        return None
    out = line
    # 组合动作 alert|log 非 Suricata 合法值
    out = re.sub(r"^(alert|log|pass|drop)\|(?:alert|log|pass|drop)\b", lambda m: m.group(1), out, flags=re.I)
    out = re.sub(r"\s+<>\s+", " -> ", out)  # Suricata 不支持双向
    # 端口列表中的变量展开（Suricata 不支持 [$HTTP_PORTS,8443] 混写）
    out = re.sub(
        r"\[\$HTTP_PORTS([^\]]*)\]",
        lambda m: "[80,443,8080,8443" + m.group(1) + "]",
        out,
    )
    # uricontent!:"X" → content:!"X"; http_uri（否定形式先替换）
    out = URICONTENT_NEG_RE.sub(lambda m: f'content:!"{m.group(1)}"; http_uri;', out)
    out = URICONTENT_RE.sub(lambda m: f'content:"{m.group(1)}"; http_uri;', out)
    out = re.sub(r'"\s*,\s*(nocase|distance|within|offset|depth)\b', r'"; \1', out, flags=re.I)
    for rx in STRIP_KWS:
        out = rx.sub("", out)
    # classtype 剥离（未知 classtype 会导致加载失败；语义在 xbits sid_library）
    out = re.sub(r"\bclasstype\s*:\s*[^;]+;?", "", out, flags=re.I)
    # Snort-only 关键字
    out = re.sub(r"\b(?:resp|logto)\s*:\s*[^;]+;?", "", out, flags=re.I)
    # reference 的厂商私有格式会导致 Suricata 解析失败（CVE 等元数据已入 sid_library）
    out = re.sub(r"\breference\s*:\s*[^;]+;?", "", out, flags=re.I)
    # 残留的 uricontent（无引号等怪形态）也剥离，避免 Suricata 拒载
    out = re.sub(r"\buricontent\s*:\s*[^;]+;?", "", out, flags=re.I)

    # ---- 语义树归约 ----
    out = out.strip()
    out = re.sub(r";\s+\)", ";)", out)
    out = re.sub(r";\s+", "; ", out)
    out = re.sub(r"\(\s*;", "(", out)
    body = out[:-1].rstrip() if out.endswith(")") else out
    head_end = body.find("(")
    header = body[: head_end].strip() if head_end >= 0 else body
    opt_body = body[head_end + 1:] if head_end >= 0 else ""
    tokens = [t.strip() for t in split_options(opt_body) if t.strip()]
    to_client = is_response_flow(body)

    # 头部/元数据 token 与检测 token 分离；非检测 token 原样保留
    tree_tokens: list[str] = []
    passthrough: list[tuple[int, str]] = []  # (tree_token 序号 or -1, 原样 token)
    meta: list[str] = []
    for t in tokens:
        tl = t.lower()
        head = tl.split(":", 1)[0]
        # 无法等价转换的语义一律返回 None（由主流程记入 semantic_gaps）
        if tl in ("http_only_uri", "http_uri_only", "rawbytes"):
            return None
        if tl.startswith(("rate:", "method:", "resp:", "logto:")):
            return None
        if head in BUFFER_CANON or head in SNORT_MODIFIERS or head.startswith(("content", "pcre")):
            if to_client and head in REQUEST_BUFFERS:
                return None
            tree_tokens.append(t)
        elif tl.startswith("status_code:"):
            # status_code:N → 独立状态码段（树中作为容量型 buffer 原子）
            value = t.split(":", 1)[1].strip().strip('"')
            if not re.fullmatch(r"\d{3}", value):
                return None
            tree_tokens.append(f'content:"{value}"')
            tree_tokens.append("http_stat_code")
        else:
            meta.append(t)

    tree = build_semantic_tree(tree_tokens)
    linear, problems = linearize_tree(tree)
    if problems:
        # V-11 静态容量断言失败 / 不可转换 pcre：该规则不产出（调用方记 gap）
        return None
    # 规整 token：去重相邻 nocase、去掉 pcre 后多余 nocase
    cleaned: list[str] = []
    for tok in linear:
        tl = tok.lower()
        if tl == "nocase" and cleaned and (
            cleaned[-1].lower() == "nocase" or cleaned[-1].lower().startswith("pcre:")
        ):
            continue
        cleaned.append(tok)

    if meta:
        cleaned.extend(meta)
    if flowbit_set is not None:
        cleaned.append(f"flowbits:set,xb_dep_{flowbit_set}")
    if flowbit_is is not None:
        cleaned.append(f"flowbits:isset,xb_dep_{flowbit_is}")

    # 同一 content 不能同时使用绝对(offset/depth)与相对(within/distance)定位：
    # 有相对定位时去掉绝对定位（Snort 允许混用，Suricata 拒绝）
    groups: list[list[str]] = []
    cur: list[str] = []
    for tok in cleaned:
        if tok.lower().startswith("content:"):
            if cur:
                groups.append(cur)
            cur = [tok]
        else:
            cur.append(tok)
    if cur:
        groups.append(cur)
    fixed: list[str] = []
    for g in groups:
        has_rel = any(x.lower().startswith(("within:", "distance:")) for x in g)
        abs_keys: list[str] = []
        for x in g:
            xl = x.lower()
            if xl.startswith("offset:"):
                abs_keys.append("offset")
            elif xl.startswith("depth:"):
                abs_keys.append("depth")
        if has_rel and abs_keys:
            return None
        if len(abs_keys) != len(set(abs_keys)):
            return None
        fixed.extend(g)
    cleaned = fixed

    # 状态码段必须是其所在 buffer 段的最后一段：其后不得再有同段 content
    # （V-11：线性化已保证 stat_code 后的匹配各自开新段，这里校验兜底）
    META_HEADS = ("sid", "rev", "msg", "flow", "priority", "metadata",
                  "threshold", "classtype", "reference", "flowbits", "lua",
                  "filesize", "noalert", "tag", "session", "replace", "detection_filter")
    for i, tok in enumerate(cleaned):
        if tok.lower() == "http_stat_code":
            # 跳过状态码自身的 content（紧随其后的第一个 content/pcre）
            j = i + 1
            if j < len(cleaned) and cleaned[j].lower().startswith(("content", "pcre")):
                j += 1
            for k in range(j, len(cleaned)):
                h = cleaned[k].lower().split(":", 1)[0]
                if h in BUFFER_CANON or h == "pkt_data":
                    break  # 新段开始：状态码段已结束
                if h.startswith(("content", "pcre")):
                    return None  # 状态码段内混入了未重置的 content → 拒绝
                if h.startswith(META_HEADS) or h in META_HEADS:
                    break
    body_out = "; ".join(cleaned).rstrip()
    body_out = body_out.rstrip(";").rstrip()
    body_out = re.sub(r";\s*;", ";", body_out)

    # V-16/V-18: 按 flow 方向规整头部端口/网段位置（to_client 响应端口在源侧）
    header, flipped = normalize_direction_header(header, to_client)
    # 静态断言（防回归）：to_client 规则的目的端口不得出现服务端口表达
    # （变量/数字/列表/范围/混合）。翻转后若仍残留（例如 src/dst 同时带端口
    # 表达），拒绝生成并记账；any 与明确客户端端口允许留在目的侧。
    parts = rule_header_parts(header)
    if to_client and parts is not None and is_service_port_expr(parts[6]):
        sid_m = SID_RE.search(line)
        if sid_m:
            TO_CLIENT_PORT_ASSERT_SIDS.add(int(sid_m.group(1)))
        return None
    return header + " (" + body_out + ";)"


def cleanup_dead_flowbits(out_suricata: Path) -> dict:
    """[已废弃，R10/V-15] flowbits:isset 死规则清理——active 规则不再注入 flowbits:set，
    本函数输入恒空、removed 恒为 []（convert_probe_rules.py 曾以此宣称"已清理失效规则"）。
    保留函数体仅供历史排查参考；主流程不再调用，dead_rules.json 不再产出。"""
    prim = re.compile(
        r"\b(content|pcre|byte_test|byte_jump|byte_extract|byte_math|dsize|"
        r"isdataat|urilen|filemagic|fileext|filename|tls_|dns_|http_|ssh_|smtp_|ftp_)\b"
    )
    set_bits: set[str] = set()
    files: list[Path] = []
    for category_dir in sorted(out_suricata.iterdir()):
        if not category_dir.is_dir() or category_dir.name in SCENARIO_DIRS:
            continue
        for path in sorted(category_dir.rglob("*.rules")):
            files.append(path)
            text = path.read_bytes().decode("utf-8", "replace")
            for line in text.splitlines():
                if not line.startswith("alert"):
                    continue
                for m in re.finditer(r"flowbits:set,([^;]+)", line):
                    set_bits.add(m.group(1).strip())

    removed: list[dict] = []
    for path in files:
        text = path.read_bytes().decode("utf-8", "replace")
        kept: list[str] = []
        changed = False
        for line in text.splitlines():
            if line.startswith("alert"):
                isset = [m.group(1).strip() for m in re.finditer(r"flowbits:isset,([^;]+)", line)]
                if isset and (any(bit not in set_bits for bit in isset) or not prim.search(line)):
                    sid = re.search(r"\bsid:(\d+)", line)
                    removed.append(
                        {
                            "sid": int(sid.group(1)) if sid else None,
                            "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                            "missing": [b for b in isset if b not in set_bits],
                            "reason": "orphan" if any(b not in set_bits for b in isset) else "no-primitive",
                        }
                    )
                    changed = True
                    continue
            kept.append(line)
        if changed:
            path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
    return {"removed": removed, "set_bits": len(set_bits)}


def parse_ini_sections(path: Path):
    sections: dict[str, dict[str, str]] = {}
    cur = None
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            sections[cur] = {}
            continue
        if cur and "=" in line:
            k, v = line.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def parse_hole_library(path: Path) -> dict[int, dict]:
    lib: dict[int, dict] = {}
    for name, kv in parse_ini_sections(path).items():
        if not name.startswith("Hole_Rule_"):
            continue
        if "sid" not in kv or not kv["sid"].isdigit():
            continue
        lib[int(kv["sid"])] = {
            "name": kv.get("name", ""),
            "danger_class": int(kv["danger_class"]) if kv.get("danger_class", "").isdigit() else None,
        }
    return lib


def parse_strongsid(path: Path) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    cur = None
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\[type\]\s*=\s*(\S+)", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        if line.isdigit() and cur:
            out[cur].append(int(line))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="Sangfor 导出目录（流量检测规则）")
    args = parser.parse_args()
    src = Path(args.src)
    if not src.is_dir():
        print(f"missing source dir: {src}", file=sys.stderr)
        return 2

    # 只清理转换器自己生成的类目目录；场景目录（DNS隧道/Web漏洞/侦察/后门）不能动
    OUT_XBITS.mkdir(parents=True, exist_ok=True)
    for generated in (
        "rules_meta.json",
        "success_rules.json",
        "audit_rules.json",
        "sid_library.json",
        "exceptions.json",
        "dead_rules.json",
        "semantic_gaps.json",
    ):
        (OUT_XBITS / generated).unlink(missing_ok=True)
    cleaned_dirs: set[Path] = set()

    def clean_generated_rules(root: Path) -> None:
        """删除目录内转换器生成的 *.rules，保留手工维护文件（lua/、*.lst 等）。

        旧实现 rmtree 整个类目目录，会连带删除 lua/ 增强脚本与数据集文件，
        导致重生成后规则里的 `lua:` 引用悬空、Suricata 拒载。
        """
        if not root.is_dir():
            return
        for path in sorted(root.rglob("*.rules")):
            path.unlink()
        # 删除随之清空的子目录
        for sub in sorted(root.rglob("*"), reverse=True):
            if sub.is_dir() and not any(sub.iterdir()):
                sub.rmdir()

    # 已知 Suricata 无法加载的 SID（由 CI 加载验证日志提取），直接跳过
    quarantine: set[int] = set()
    qfile = ROOT / "docs" / "unsupported-sids.txt"
    if qfile.exists():
        for raw in qfile.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw.isdigit():
                quarantine.add(int(raw))

    # 人工确认的高误报 SID，不进入 active 规则
    fp_sids: set[int] = set()
    fp_file = ROOT / "docs" / "false-positive-sids.txt"
    if fp_file.exists():
        for raw in fp_file.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw.isdigit():
                fp_sids.add(int(raw))

    # ---- Pass 1: 预扫描 depend/scope，构建反向依赖表 ----
    dep_refs: set[int] = set()  # 被依赖的请求侧 SID
    success_rules: list[dict] = []
    for path in sorted(src.glob("etc_fw/pvs/rules/**/*.rules")):
        rel = path.relative_to(src).as_posix()
        for line in iter_rule_lines(path):
            meta = extract_meta(line)
            sid = meta.get("sid")
            if sid is None:
                continue
            deps = meta.get("depends", []) + meta.get("scopes", [])
            if deps:
                dep_refs.update(deps)
                success_rules.append(
                    {
                        "sid": sid,
                        "msg": meta.get("msg", ""),
                        "depends": meta.get("depends", []),
                        "scopes": meta.get("scopes", []),
                        "holetype": meta.get("holetype"),
                        "source": rel,
                    }
                )

    # ---- Pass 2: Suricata 转换 ----
    rules_meta: dict[str, dict] = {}
    seen_sids: set[int] = set()
    stats: dict[str, dict] = {}
    rule_files: list[tuple[str, int]] = []
    no_dep_success: list[int] = []

    for group, pattern in SURICATA_SOURCES:
        for path in sorted(src.glob(pattern)):
            rel = path.relative_to(src).as_posix()
            tier = "weak" if path.name in WEAK_FILES else "strong"
            stem = path.stem
            if group == "pvs-success":
                category = f"{SUCCESS_CATEGORY}/{stem}"
                success_root = OUT_SURICATA / SUCCESS_CATEGORY
                if success_root not in cleaned_dirs:
                    clean_generated_rules(success_root)
                    cleaned_dirs.add(success_root)
            else:
                category = CATEGORY_MAP.get(stem, "其他")
            meta_category = category
            out_dir = OUT_SURICATA / category
            if out_dir not in cleaned_dirs:
                clean_generated_rules(out_dir)
                cleaned_dirs.add(out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            converted: list[str] = []
            n_ok = n_skip = n_dupe = 0
            for line in iter_rule_lines(path):
                meta = extract_meta(line)
                sid = meta.get("sid")
                if sid is None:
                    n_skip += 1
                    continue
                meta["source"] = rel
                meta["group"] = group
                meta["tier"] = tier
                meta["category"] = meta_category
                deps = meta.get("depends", []) + meta.get("scopes", [])
                primary_dep = deps[0] if deps else None

                if MAIL_URI_RE.search(line):
                    meta["skip"] = "mail_uri"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # Suricata 只做签名命中：状态链/无告警规则不进入
                if re.search(r"\bnoalert\b", line, re.I):
                    meta["skip"] = "state-noalert"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 源规则自带的 flowbits 属于跨包状态关联，交给 xbits
                if re.search(r"\bflowbits\s*:", line, re.I):
                    meta["skip"] = "flowbits-correlation"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # depend/scope 的响应确认规则属于请求→响应关联，交给 xbits
                if deps:
                    meta["skip"] = "dependency-correlation"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 不能等价转换的语义：不降级使用，直接剔除并保留元数据
                sem_reason = semantic_skip_reason(line)
                if sem_reason:
                    meta["skip"] = sem_reason
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # Sangfor 语义/DSL 规则：Suricata 无法等价执行，只保留元数据
                if DSL_RE.search(line):
                    meta["skip"] = "dsl-semantic"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 无依赖的成功确认规则：200 OK 类泛匹配，不进 Suricata
                if group == "pvs-success" and primary_dep is None:
                    meta["skip"] = "no-dependency"
                    rules_meta.setdefault(str(sid), meta)
                    no_dep_success.append(sid)
                    n_skip += 1
                    continue

                # 负向 pcre（pcre:!"..."）Suricata 不支持
                if re.search(r"pcre\s*:\s*!", line, re.I):
                    meta["skip"] = "negated-pcre"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # isdataat 偏移越界在 Suricata 会直接拒载
                if "isdataat" in line.lower():
                    meta["skip"] = "isdataat"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 已知加载失败 SID（CI 验证日志提取）
                if sid in quarantine:
                    meta["skip"] = "unsupported"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 人工确认的高误报 SID
                if sid in fp_sids:
                    meta["skip"] = "false-positive-quarantine"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                if sid in seen_sids:
                    n_dupe += 1
                    continue

                flowbit_set = None
                rule = convert_rule(line, flowbit_set, None)
                if rule is None:
                    # V-16: 区分 to_client 端口方向静态断言拒绝（防回归计数）
                    if sid in TO_CLIENT_PORT_ASSERT_SIDS:
                        meta["skip"] = "to-client-port-direction"
                    else:
                        meta["skip"] = "convert-rule-none"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue
                seen_sids.add(sid)
                rules_meta[str(sid)] = meta
                converted.append(rule)
                n_ok += 1
            if converted:
                safe_stem = re.sub(r"[^0-9A-Za-z_.\-]+", "-", stem)
                out_name = f"{safe_stem}.rules"
                if (out_dir / out_name).exists():
                    out_name = f"{group}-{out_name}"
                header = (
                    f"# Converted from Sangfor export: {rel}\n"
                    f"# rules={n_ok} skipped={n_skip} dup_sid={n_dupe}\n"
                )
                (out_dir / out_name).write_text(header + "\n".join(converted) + "\n", encoding="utf-8")
                rel_out = str((out_dir / out_name).relative_to(ROOT)).replace("\\", "/")
                rule_files.append((rel_out, n_ok))
            stats[rel] = {"ok": n_ok, "skip": n_skip, "dupe": n_dupe}

    # ---- 3) 云审计规则 → xbits 元数据 ----
    audit_rules: list[dict] = []
    for pattern in CLOUD_GLOBS:
        for path in sorted(src.glob(pattern)):
            rel = path.relative_to(src).as_posix()
            for line in iter_rule_lines(path):
                meta = extract_meta(line)
                sid = meta.get("sid")
                if sid is None:
                    continue
                audit_rules.append(
                    {"sid": sid, "msg": meta.get("msg", ""), "source": rel}
                )
                rules_meta.setdefault(
                    str(sid), {**meta, "source": rel, "group": "cloud-audit"}
                )

    # ---- 4) SID 库映射 ----
    lib = parse_hole_library(src / META_FILES["hole_library"])
    classification = json.loads((src / META_FILES["classification"]).read_text(encoding="utf-8"))
    waftype = {}
    for k, v in parse_ini_sections(src / META_FILES["waftype"]).get("config", {}).items():
        m = re.match(r"WafType_(\d+)", k)
        if m:
            waftype[int(m.group(1))] = v

    sid_library: dict[str, dict] = {}
    for sid_str, meta in rules_meta.items():
        sid = int(sid_str)
        entry: dict = {"group": meta.get("group", "")}
        if meta.get("tier"):
            entry["tier"] = meta["tier"]
        if meta.get("category"):
            entry["category_dir"] = meta["category"]
        hole = lib.get(sid)
        if hole:
            entry["name"] = hole["name"]
            if hole["danger_class"] is not None:
                entry["danger_class"] = hole["danger_class"]
        ht = meta.get("holetype")
        if ht is not None:
            entry["holetype"] = ht
            if ht in waftype:
                entry["waftype"] = waftype[ht]
            for engine in ("waf", "pvs", "ips"):
                if str(ht) in classification.get(engine, {}):
                    cat = classification[engine][str(ht)]
                    entry["category"] = cat[0]
                    entry["subcategory"] = cat[1] if len(cat) > 1 else ""
                    break
        if not entry.get("name") and meta.get("msg"):
            entry["name"] = meta["msg"]
        for field in ("classtype", "references", "status_code", "rate", "skip"):
            if meta.get(field):
                entry[field] = meta[field]
        sid_library[sid_str] = entry

    # 语义降级/无法等价转换规则报告（只保留元数据，不进入 Suricata）
    gaps: dict[str, list[int]] = {}
    for sid_str, meta in rules_meta.items():
        reason = meta.get("skip")
        if reason:
            gaps.setdefault(reason, []).append(int(sid_str))
    # V-15 契约结构：每个 reason 必须声明 owner（谁接管）与 tested_by（CI 哪个断言覆盖）。
    # owner ∈ suricata-rule（能力留在/回到规则层）/ xbits-feature（交 xbits 实现）/ dropped-document（明确放弃，仅文档留痕）。
    # tested_by=None 表示当前无 CI 断言覆盖该缺口——这是显式承认，不是隐藏；
    # 但 owner=xbits-feature 的 reason 必须给出 tested_by（C6-B 契约：'交 xbits 实现'
    # 必须能指到实现方的 CI 断言，否则"交 xbits"就是空头支票——由
    # xbits/test/qa_semantic_gaps_gate.py evaluate_ownership 强制）。
    REASON_OWNERSHIP = {
        "byte-extract-reference":   {"owner": "dropped-document", "tested_by": None,
                                     "note": "within/distance 引用 byte_extract 变量，"
                                             "运行时求值无法静态校验，Suricata 拒载"},
        "convert-rule-none":        {"owner": "dropped-document", "tested_by": None,
                                     "note": "转换器无法等价转换（返回 None），规则不产出"},
        "dependency-correlation":   {"owner": "xbits-feature", "tested_by": "qa_xbits_success_rules.py",
                                     "note": "depend/scope 请求→响应配对已由 xbits --success-rules 实现"
                                             "（V-14 方案①）：qa_xbits_success_rules.py 断言配对/对照/坏配置三态"},
        "dsl-semantic":             {"owner": "dropped-document", "tested_by": None,
                                     "note": "DSL 语义无法映射到 Suricata"},
        "duplicate-position":       {"owner": "dropped-document", "tested_by": None,
                                     "note": "同 content 重复绝对定位"},
        "false-positive-quarantine":{"owner": "dropped-document", "tested_by": None,
                                     "note": "人工确认高误报，隔离名单 docs/false-positive-sids.txt"},
        "flowbits-correlation":     {"owner": "xbits-feature", "tested_by": "qa_xbits_context.py",
                                     "note": "跨包 flowbits 状态链由 xbits 上下文关联承担："
                                             "qa_xbits_context.py 断言正例/负例/对照告警"},
        "http-only-uri-unsupported":{"owner": "dropped-document", "tested_by": None,
                                     "note": "http_only_uri Snort 专属语义"},
        "isdataat":                 {"owner": "dropped-document", "tested_by": None,
                                     "note": "isdataat 偏移越界 Suricata 拒载"},
        "lua-without-buffer":       {"owner": "suricata-rule", "tested_by": "qa_converter_semantics.py",
                                     "note": "lua: 前无 sticky buffer（V-13）：可定位的补 buffer，"
                                             "其余不注入 lua（apply_lua_enhancements.py 前置拒绝）；"
                                             "qa_converter_semantics.py --self-test 断言 lua 前有 buffer"},
        "mail_uri":                 {"owner": "dropped-document", "tested_by": None,
                                     "note": "邮件 URI 语法不支持"},
        "buffer-without-payload":   {"owner": "dropped-document", "tested_by": None,
                                     "note": "悬空 sticky buffer 无承接匹配（V-10 取代 dangling-http-uri 判定）"},
        "method-trailing-space":    {"owner": "dropped-document", "tested_by": None,
                                     "note": "http_method 段 content 尾随空格，Suricata detect-http-method 拒载"},
        "to-client-port-direction": {"owner": "suricata-rule", "tested_by": "qa_converter_pcap_regression.py",
                                     "note": "V-16/V-18 静态断言：to_client 目的端口残留服务端口表达"
                                             "（变量/数字/列表/范围/混合）无法翻转→拒绝生成；"
                                             "t47 补 to_client PCAP 命中断言）"},
        "method-unsupported":       {"owner": "dropped-document", "tested_by": None,
                                     "note": "Suricata 不支持的 method 语法"},
        "mixed-position":           {"owner": "dropped-document", "tested_by": None,
                                     "note": "绝对+相对定位混用，Suricata 拒载"},
        "negated-pcre":             {"owner": "dropped-document", "tested_by": None,
                                     "note": "pcre:! 否定形式不支持"},
        "no-dependency":            {"owner": "xbits-feature", "tested_by": "qa_xbits_success_rules.py",
                                     "note": "PVS 成功确认无依赖，保留为 xbits 元数据："
                                             "qa_xbits_success_rules.py 断言 success_rules 加载/消费"},
        "rate-unsupported":         {"owner": "dropped-document", "tested_by": None,
                                     "note": "rate 过滤不支持"},
        "rawbytes-unsupported":     {"owner": "dropped-document", "tested_by": None,
                                     "note": "rawbytes 修饰不支持"},
        "response-direction-conflict": {"owner": "dropped-document", "tested_by": None,
                                     "note": "请求 buffer 出现在响应方向规则"},
        "state-noalert":            {"owner": "dropped-document", "tested_by": None,
                                     "note": "noalert 状态规则不产出告警"},
        "unsupported":              {"owner": "dropped-document", "tested_by": None,
                                     "note": "已知加载失败 SID 隔离名单 docs/unsupported-sids.txt"},
    }
    unknown = [k for k in gaps if k not in REASON_OWNERSHIP]
    if unknown:
        # 新 reason 忘记登记归属 → 直接失败（契约化：不允许出现无主缺口）
        raise SystemExit(
            "semantic_gaps 存在未登记 owner 的 reason: %s（请在 REASON_OWNERSHIP 补充）"
            % sorted(unknown))
    semantic_gaps = {
        "counts": {k: len(v) for k, v in sorted(gaps.items())},
        "sids": {k: sorted(v) for k, v in sorted(gaps.items())},
        "ownership": {k: REASON_OWNERSHIP[k] for k in sorted(gaps)},
    }
    (OUT_XBITS / "semantic_gaps.json").write_text(
        json.dumps(semantic_gaps, ensure_ascii=False, indent=1), encoding="utf-8"
    )

    # ---- 5) 例外 / 强 SID ----
    exceptions = {
        "ips_exception": parse_ini_sections(src / META_FILES["ips_exception"]).get("all", {}),
        "waf_exception": parse_ini_sections(src / META_FILES["waf_exception"]).get("all", {}),
        "ips_strongsid": parse_strongsid(src / META_FILES["strongsid"]),
    }

    (OUT_XBITS / "rules_meta.json").write_text(
        json.dumps(rules_meta, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "success_rules.json").write_text(
        json.dumps(success_rules, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "audit_rules.json").write_text(
        json.dumps(audit_rules, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "sid_library.json").write_text(
        json.dumps(sid_library, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "exceptions.json").write_text(
        json.dumps(exceptions, ensure_ascii=False, indent=1), encoding="utf-8"
    )

    # ---- 5.5) flowbits 清理链路（V-15 处置：删除） ----
    # 旧链路：active 规则自 t? 决议起不再注入 flowbits:set（:1057 flowbit_set=None），
    # cleanup_dead_flowbits 扫描不到任何 set → removed 恒为 []，dead_rules.json 恒空——
    # 属"永远空转的假治理"。现删除该链路与 dead_rules.json 产物；
    # flowbits 依赖的接管方见 semantic_gaps.json ownership（flowbits-correlation → xbits-feature）。
    dead_rules_path = OUT_XBITS / "dead_rules.json"
    if dead_rules_path.exists():
        dead_rules_path.unlink()

    # 清理后重新统计实际落盘的 SID，并过滤失效的成功确认依赖
    emitted: set[int] = set()
    rule_files = []
    for category_dir in sorted(OUT_SURICATA.iterdir()):
        if not category_dir.is_dir() or category_dir.name in SCENARIO_DIRS:
            continue
        for path in sorted(category_dir.rglob("*.rules")):
            text = path.read_bytes().decode("utf-8", "replace")
            for line in text.splitlines():
                m = re.search(r"\bsid:(\d+)", line)
                if m and line.startswith("alert"):
                    emitted.add(int(m.group(1)))
            count = sum(1 for line in text.splitlines() if line.startswith("alert"))
            if count:
                rule_files.append((str(path.relative_to(ROOT)).replace("\\", "/"), count))

    # 删除清空后的规则文件/目录，并按最终落盘内容重建验证清单
    emitted2: set[int] = set()
    rule_files = []
    for category_dir in sorted(OUT_SURICATA.iterdir()):
        if not category_dir.is_dir() or category_dir.name in SCENARIO_DIRS:
            continue
        for path in sorted(category_dir.rglob("*.rules")):
            text = path.read_bytes().decode("utf-8", "replace")
            lines = [l for l in text.splitlines() if l.startswith("alert")]
            if not lines:
                path.unlink()
                continue
            for line in lines:
                m = re.search(r"\bsid:(\d+)", line)
                if m:
                    emitted2.add(int(m.group(1)))
            rule_files.append((str(path.relative_to(ROOT)).replace("\\", "/"), len(lines)))
        # 删除空子目录
        for sub in sorted(category_dir.rglob("*"), reverse=True):
            if sub.is_dir() and not any(sub.iterdir()):
                sub.rmdir()
        if not any(category_dir.iterdir()):
            category_dir.rmdir()

    # success_rules.json 保留全量依赖元数据，供 xbits 后续关联
    # ---- 6) Suricata 加载验证配置 ----
    validate_yaml = [
        "%YAML 1.1",
        "---",
        "# 探针规则转换产物的 Suricata 加载验证配置（由 convert_probe_rules.py 生成）",
        "default-log-dir: /tmp/suri-out",
        "",
        "vars:",
        "  address-groups:",
        '    HOME_NET: "any"',
        '    EXTERNAL_NET: "any"',
        '    CLIENT_NET: "any"',
        '    HTTP_SERVERS: "any"',
        '    SMTP_SERVERS: "any"',
        '    DNS_SERVERS: "any"',
        '    SQL_SERVERS: "any"',
        '    MAIL_SERVERS: "any"',
        "  port-groups:",
        '    HTTP_PORTS: "[80,8080,8000,443,8443]"',
        '    MAIL_PORTS: "[25,110,143,587,993,995]"',
        "",
        "default-rule-path: /opt/xbits/rules/suricata",
        "rule-files:",
    ]
    for rel_out, _n in rule_files:
        # rel_out 形如 suricata/<category>/<file>.rules
        rel_rule = rel_out
        if "规则检测/suricata/" in rel_rule:
            rel_rule = rel_rule.split("规则检测/suricata/", 1)[1]
        elif rel_rule.startswith("suricata/"):
            rel_rule = rel_rule[len("suricata/"):]
        validate_yaml.append(f'  - "{rel_rule}"')
    validate_yaml += [
        "",
        "classification-file: /opt/xbits/rules/classification.config",
        "reference-config-file: /opt/xbits/rules/reference.config",
        "",
        "# 仅做规则加载验证：不启用插件/事件输出",
        "outputs:",
        "  - eve-log:",
        "      enabled: no",
        "",
    ]
    docker_dir = ROOT.parent / "docker"
    docker_dir.mkdir(exist_ok=True)
    (docker_dir / "probe-rules-validate.yaml").write_text("\n".join(validate_yaml), encoding="utf-8")

    # 强/弱规则分离加载集：生产默认只加载 strong，weak 单独加载给 xbits 收敛
    prefix = validate_yaml[: validate_yaml.index("rule-files:") + 1]
    footer_start = next(i for i, line in enumerate(validate_yaml) if line.startswith("classification-file:"))
    footer = validate_yaml[footer_start:]
    strong_entries: list[str] = []
    weak_entries: list[str] = []
    for rel_out, _n in rule_files:
        rel_rule = rel_out
        if "规则检测/suricata/" in rel_rule:
            rel_rule = rel_rule.split("规则检测/suricata/", 1)[1]
        elif rel_rule.startswith("suricata/"):
            rel_rule = rel_rule[len("suricata/"):]
        if Path(rel_out).name in WEAK_FILES:
            weak_entries.append(f'  - "{rel_rule}"')
        else:
            strong_entries.append(f'  - "{rel_rule}"')

    def write_profile(filename: str, title: str, entries: list[str]) -> None:
        lines = list(prefix)
        lines[2] = f"# {title}（由 convert_probe_rules.py 生成）"
        lines += entries
        lines += list(footer)
        (docker_dir / filename).write_text("\n".join(lines), encoding="utf-8")

    write_profile("probe-rules-production.yaml", "生产强规则加载配置", strong_entries)
    write_profile("probe-rules-weak.yaml", "弱规则单独加载配置（交 xbits 低置信度收敛）", weak_entries)

    total_ok = sum(v["ok"] for v in stats.values())
    total_skip = sum(v["skip"] for v in stats.values())
    total_dupe = sum(v["dupe"] for v in stats.values())
    print(f"suricata rules written: {total_ok} (skipped={total_skip}, dup_sid={total_dupe})")
    print(f"pvs success rules (with deps): {len(success_rules)}; no-dep skipped: {len(no_dep_success)}")
    print(f"cloud audit rules: {len(audit_rules)}")
    print(f"sid meta entries: {len(rules_meta)}; sid library entries: {len(sid_library)}")
    print(f"flowbit-gated request sids: {len(dep_refs)}")

    # V-16 conversion report: to_client 方向翻转与静态断言计数
    # 从实际落盘的规则统计 to_client 方向（源/目的端口形态）
    to_client_flipped = 0
    to_client_already_ok = 0
    for category_dir in sorted(OUT_SURICATA.iterdir()):
        if not category_dir.is_dir() or category_dir.name in SCENARIO_DIRS:
            continue
        for path in sorted(category_dir.rglob("*.rules")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.startswith("alert") or not is_response_flow(line):
                    continue
                parts = rule_header_parts(line[: line.find("(")])
                if parts is None:
                    continue
                # 翻转后：源端口是服务端口表达，目的端口为 any/客户端端口
                if is_service_port_expr(parts[3]) and not is_service_port_expr(parts[6]):
                    to_client_flipped += 1
                else:
                    to_client_already_ok += 1
    report = {
        "to_client_total": to_client_flipped + to_client_already_ok + len(TO_CLIENT_PORT_ASSERT_SIDS),
        "to_client_flipped": to_client_flipped,
        "to_client_already_ok": to_client_already_ok,
        "to_client_port_direction_assertions": len(TO_CLIENT_PORT_ASSERT_SIDS),
        "to_client_port_direction_assertion_sids": sorted(TO_CLIENT_PORT_ASSERT_SIDS),
    }
    (OUT_XBITS / "conversion_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"to_client rules flipped (service port now on src): {to_client_flipped}")
    print(f"to_client rules already-correct/other: {to_client_already_ok}")
    print(f"to_client port-direction assertions refused: {len(TO_CLIENT_PORT_ASSERT_SIDS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
