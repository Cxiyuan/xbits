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
  * uricontent → content + http_uri；
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


def split_options(opts: str) -> list[str]:
    """按分号拆分规则选项，尊重双引号与反斜杠转义。"""
    tokens, cur = [], []
    inq = esc = False
    for ch in opts:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if ch == '"':
            inq = not inq
            cur.append(ch)
            continue
        if ch == ";" and not inq:
            tokens.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        tokens.append(tail)
    return tokens


REQUEST_BUFFERS = {
    "http_client_body", "http_uri", "http_raw_uri", "http_method", "http_host",
    "http_cookie", "http_user_agent", "http_only_uri", "http_uri_only",
}


def rule_option_tokens(line: str) -> list[str]:
    if "(" not in line or ")" not in line:
        return []
    body = line[line.find("(") + 1 : line.rfind(")")]
    return [t.strip() for t in split_options(body) if t.strip()]


def semantic_skip_reason(line: str) -> str | None:
    """识别无法等价转换的语义；这些规则不进入 Suricata，避免降级使用。"""
    tokens = rule_option_tokens(line)
    flow_token = next((t for t in tokens if t.lower().startswith("flow:")), "")
    to_client = "to_client" in flow_token.lower()

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

    prev = ""
    for t in tokens:
        tl = t.lower()
        if tl == "http_uri" and not prev.lower().startswith("content:"):
            return "dangling-http-uri"
        prev = t

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


def convert_rule(line: str, flowbit_set: int | None, flowbit_is: int | None) -> str | None:
    """Return cleaned Suricata rule text or None (if unconvertible)."""
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

    injections = []
    if flowbit_set is not None:
        injections.append(f"flowbits:set,xb_dep_{flowbit_set}")
    if flowbit_is is not None:
        injections.append(f"flowbits:isset,xb_dep_{flowbit_is}")

    # 规整：折叠 "; )" 与多余空白
    out = out.strip()
    out = re.sub(r";\s+\)", ";)", out)
    out = re.sub(r";\s+", "; ", out)
    out = re.sub(r"\(\s*;", "(", out)
    # 取出选项体（去掉结尾的 ')'），按分号拆分后做最后清理
    body = out[:-1].rstrip() if out.endswith(")") else out
    tokens = split_options(body)
    to_client = bool(re.search(r"flow:[^;]*to_client", body, re.I))
    cleaned: list[str] = []
    prev = ""
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        tl = t.lower()
        # 无法等价转换的语义一律返回 None（由主流程记入 semantic_gaps）
        if tl in ("http_only_uri", "http_uri_only", "rawbytes"):
            return None
        if tl.startswith(("rate:", "method:", "resp:", "logto:")):
            return None
        # status_code:N → Suricata HTTP 响应状态码约束
        if tl.startswith("status_code:"):
            value = t.split(":", 1)[1].strip().strip('"')
            if not re.fullmatch(r"\d{3}", value):
                return None
            cleaned.append(f'content:"{value}"')
            cleaned.append("http_stat_code")
            prev = "http_stat_code"
            continue
        if to_client and tl in REQUEST_BUFFERS:
            return None
        # 悬空的 http_uri（前面不是 content）→ 规则语义不完整，不使用
        if tl == "http_uri" and not prev.lower().startswith("content:"):
            return None
        # pcre 后重复的 nocase（Snort 允许，Suricata 报错）
        if tl == "nocase" and prev.lower().startswith("pcre:"):
            continue
        if tl == "nocase" and prev.lower() == "nocase":
            continue
        # PCRE 兼容性：Python re 编译不过 / 含 P 修饰符的规则跳过，避免 Suricata 拒载
        if tl.startswith("pcre:"):
            m = re.match(r'pcre\s*:\s*"(.*)"$', t, re.S)
            if m:
                s = m.group(1)
                last = s.rfind("/")
                if s.startswith("/") and last > 1:
                    pat, flags = s[1:last], s[last + 1:]
                    # R/P/B 在 Suricata 中语义/前置条件不同，直接跳过
                    if any(c in flags for c in "RPB"):
                        return None
                    if sum(flags.count(c) for c in "UBP") > 1:
                        return None
                    try:
                        re.compile(pat)
                    except Exception:
                        return None
        cleaned.append(t)
        prev = t
    if injections:
        cleaned.extend(injections)
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
        # 绝对/相对定位混用或重复的原始约束无法等价表达，直接不使用该规则
        if has_rel and abs_keys:
            return None
        if len(abs_keys) != len(set(abs_keys)):
            return None
        fixed.extend(g)
    cleaned = fixed
    body = "; ".join(cleaned).rstrip()
    body = body.rstrip(";").rstrip()
    body = re.sub(r";\s*;", ";", body)
    return body + ";)"


def cleanup_dead_flowbits(out_suricata: Path) -> dict:
    """删除永远不会触发或没有检测原语的 flowbits:isset 规则，并返回清理统计。"""
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
                    shutil.rmtree(success_root, ignore_errors=True)
                    cleaned_dirs.add(success_root)
            else:
                category = CATEGORY_MAP.get(stem, "其他")
            meta_category = category
            out_dir = OUT_SURICATA / category
            if out_dir not in cleaned_dirs:
                shutil.rmtree(out_dir, ignore_errors=True)
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
    semantic_gaps = {
        "counts": {k: len(v) for k, v in sorted(gaps.items())},
        "sids": {k: sorted(v) for k, v in sorted(gaps.items())},
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

    # ---- 5.5) 清理永远不会触发的 flowbits:isset 规则 ----
    cleanup = cleanup_dead_flowbits(OUT_SURICATA)
    (OUT_XBITS / "dead_rules.json").write_text(
        json.dumps(cleanup["removed"], ensure_ascii=False, indent=1), encoding="utf-8"
    )

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

    # 成功确认依赖保留为 xbits 元数据（active 规则不再注入 flowbits）
    # 二次清理，确保清理阶段新写入/遗漏的 isset 规则也被处理
    cleanup2 = cleanup_dead_flowbits(OUT_SURICATA)
    if cleanup2["removed"]:
        cleanup["removed"].extend(cleanup2["removed"])
        (OUT_XBITS / "dead_rules.json").write_text(
            json.dumps(cleanup["removed"], ensure_ascii=False, indent=1), encoding="utf-8"
        )

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
    print(f"dead flowbits rules removed: {len(cleanup['removed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
