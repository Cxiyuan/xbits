#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按 SID 生成 Suricata 规则匹配 buffer 元数据。

输出:
  规则检测/xbits/规则库元数据/match_buffers.json

每个 SID:
  {
    "buffers": ["http.uri"],
    "primary": "http.uri",
    "has_payload": false
  }

xbits 用这份元数据决定白名单 key 应该取哪个事件字段，
避免把所有规则都错误地按 EVE packet payload 做抑制。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUR = ROOT / "suricata"
OUT = ROOT / "xbits" / "规则库元数据" / "match_buffers.json"

# Suricata 旧式 buffer 名称 -> 统一名称
ALIASES = {
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_method": "http.method",
    "http_cookie": "http.cookie",
    "http_raw_cookie": "http.cookie",
    "http_client_body": "http.request_body",
    "http_server_body": "http.response_body",
    "http_header": "http.header",
    "http_raw_header": "http.header",
    "http_host": "http.host",
    "http_raw_host": "http.host",
    "http_user_agent": "http.user_agent",
    "http_stat_code": "http.status",
    "http_stat_msg": "http.status_msg",
    "file_data": "file.data",
    "dns_query": "dns.query",
}

# dotted（Suricata 8 原生 sticky buffer）名 -> 统一名：**精确整串匹配**，不做前缀塌缩。
# V-12（R-03 根治）：旧版 `n.startswith("http.uri")` 把 http.uri.raw 塌缩成 http.uri，
# 让"raw vs 归一化"这一安全相关语义被静默近似（xbits 对 http.uri.raw 明令禁止归一化兜底）。
# 新名字出现时必须在这里登记，未登记的 dotted 名 → None + warning，不再静默放行。
# 本表与 xbits/src/analysis.rs 的 canonical_buffer_name 共享真源：
# 规则检测/xbits/规则库元数据/buffer_aliases.json（由 write_shared_aliases 落盘）。
DOTTED = {
    "http.uri": "http.uri",
    "http.uri.raw": "http.uri.raw",
    "http.uri.query": "http.uri.query",
    "http.method": "http.method",
    "http.cookie": "http.cookie",
    "http.request_body": "http.request_body",
    "http.response_body": "http.response_body",
    "http.header": "http.header",
    "http.host": "http.host",
    "http.user_agent": "http.user_agent",
    "http.stat_code": "http.status",
    "http.stat_msg": "http.status_msg",
    "http.request_header": "http.header",
    "http.response_header": "http.header",
    "http.headers": "http.header",
    "http.header.raw": "http.header",
    "http.host.raw": "http.host",
    "file.data": "file.data",
    "dns.query": "dns.query",
    "dns.queries.rrname": "dns.query",
    "dns.rrtype": "dns.rrtype",
    "tls.sni": "tls.sni",
    "tls.alpn": "tls.alpn",
    "tls.subject": "tls.subject",
    "tls.issuer": "tls.issuer",
    "ssh.proto": "ssh.proto",
    "ssh.software": "ssh.software",
    "smb.share": "smb.share",
    "smb.filename": "smb.filename",
    "ftp.command": "ftp.command",
    "ftp.reply": "ftp.reply",
    "smtp.helo": "smtp.helo",
    "smtp.mail_from": "smtp.mail_from",
    "smtp.rcpt_to": "smtp.rcpt_to",
    "http2.headers": "http2.headers",
    "http2.body": "http2.body",
    "websocket.payload": "websocket.payload",
    "quic.data": "quic.data",
}

PREFIXES = (
    "http.",
    "dns.",
    "tls.",
    "file.",
    "smb.",
    "ssh.",
    "ftp.",
    "sip.",
    "dnp3.",
    "enip.",
    "modbus.",
    "dcerpc.",
    "mqtt.",
    "quic.",
    "http2.",
    "websocket.",
    "nfs.",
    "krb5.",
    "snmp.",
    "rfb.",
    "ike.",
    "dhcp.",
    "smtp.",
    "pop3.",
    "imap.",
)

MATCH_KEYWORDS = {
    "content", "pcre", "byte_test", "byte_jump", "byte_extract", "byte_math",
    "isdataat", "dsize", "urilen", "filemagic", "filename", "fileext",
}


def split_options(opts: str) -> list[str]:
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
    return [t for t in tokens if t]


def iter_rules(path: Path):
    text = path.read_bytes().decode("utf-8", "replace")
    buf = ""
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if not buf:
            if not re.match(r"^(alert|log|pass|drop|reject|sdrop)\b", s, re.I):
                continue
            buf = s
        else:
            buf += " " + s
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip()
            continue
        yield buf
        buf = ""
    if buf:
        yield buf


def canonical_buffer(name: str) -> str | None:
    """旧式下划线名 / 保留名 → 统一名；dotted 名**精确整串**查表（V-12）。

    返回 None 的两种情况：
    - 非 buffer 关键词（content/pcre/msg 等）——调用方据此不当作 buffer；
    - dotted 的 Suricata buffer 名但未在 DOTTED 登记——这是"未知名"，调用方必须
      记 warning（未知名静默放行=旧的塌缩路径换了个入口回归）。
    """
    n = name.strip().lower()
    if n in ALIASES:
        return ALIASES[n]
    if n in {"payload", "stream", "lua"}:
        return n
    if n in DOTTED:
        return DOTTED[n]
    return None


def unknown_dotted_warning(name: str) -> None:
    """未登记的 dotted 名：显式 warning（V-12：不再静默放行）。

    供 classify/调用方在 token 头部带 `.` 且不在任何映射里时调用；
    纯匹配关键词（content/pcre）不会走到这里（它们不是 dotted 形态）。
    """
    n = name.strip().lower()
    if "." in n and n not in DOTTED and n not in ALIASES and n not in {"payload", "stream", "lua"}:
        print(f"warning: unknown dotted buffer name {name!r} not in DOTTED registry "
              f"(规则检测/build_match_buffers.py); refusing to guess — register it "
              f"in DOTTED or fix the rule", file=sys.stderr)


def classify(rule: str) -> dict:
    body = rule[rule.find("(") + 1 : rule.rfind(")")]
    tokens = split_options(body)
    buffers: list[str] = []
    has_content_match = False
    for token in tokens:
        head = token.split(":", 1)[0].strip().lower()
        # lua 不是数据 buffer：它是脚本挂载点，绝不能当作匹配 buffer 参与 key。
        # 关键：若不跳过 lua，它会在下面先占位 buffers，导致同一规则里
        # content/pcre 默认匹配的 payload 被丢弃，规则被误判为纯 lua。
        if head == "lua":
            continue
        if head in MATCH_KEYWORDS:
            has_content_match = True
        b = canonical_buffer(token if ":" not in token else head)
        if b is None and head not in MATCH_KEYWORDS:
            # 未登记的 dotted 名 → 显式 warning（V-12：不再静默放行）。
            unknown_dotted_warning(head)
        if b and b != "lua" and b not in buffers:
            buffers.append(b)

    # 有 content/pcre 等、但没有具体 sticky buffer => 匹配的是报文 payload。
    if not buffers and has_content_match:
        buffers.append("payload")
    lua_refs = re.findall(r"\blua\s*:\s*([^\s;]+)", body, re.I)

    buffers = sorted(set(buffers))
    concrete = [b for b in buffers if b != "lua"]
    # 仅当规则既无具体 buffer、也无 content/pcre、只挂了 lua 时，才是真正的
    # 纯 app-tx Lua 规则：C 层没有单一精确 buffer 可导出，xbits 对其明确不做
    # 抑制（app_tx_lua=true，判定仍走 validator）。绝不近似。
    app_tx_lua = False
    if concrete:
        buffers = concrete
    elif not buffers and lua_refs:
        buffers = ["lua"]
        app_tx_lua = True
    primary = next((b for b in buffers if b not in {"payload", "stream", "lua"}), None)
    if primary is None and buffers:
        primary = buffers[0]

    # has_payload 表示规则是否以 packet payload 为匹配信号（用于诊断 EVE
    # payload 未开启导致无法建 key 的情况）；纯 lua 规则不算 payload。
    has_payload = any(b in {"payload", "stream", "file.data"} for b in buffers)
    return {
        "buffers": buffers,
        "primary": primary,
        "has_payload": has_payload,
        "app_tx_lua": app_tx_lua,
    }


def write_shared_aliases(path: Path) -> None:
    """把"名→规范名"映射落盘成共享 JSON（单一真源，V-12）。

    xbits/src/analysis.rs 的 canonical_buffer_name 在测试里读这份文件做集合相等断言，
    消除"两个组件各写一份映射表却无一致性测试"的结构性漂移（R-03 的根因）。
    """
    merged: dict[str, str] = {}
    merged.update(ALIASES)
    merged.update(DOTTED)
    # 保留名（payload/stream/lua）不是映射语义，不进共享表；
    # Rust 侧对未知名的处理（原样返回）与 dotted 未登记 → None+warning 的差异
    # 属于"内部名 vs 规则文本名"职责差异，由各自测试覆盖。
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "_comment": "canonical buffer-name mapping; shared by "
                "规则检测/build_match_buffers.py (canonical_buffer) and "
                "xbits/src/analysis.rs (canonical_buffer_name, test-only). "
                "Generated by build_match_buffers.py — do not hand-edit.",
                "aliases": dict(sorted(merged.items())),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    out: dict[str, dict] = {}
    files = sorted(SUR.rglob("*.rules"))
    total = 0
    for path in files:
        for line in iter_rules(path):
            m = re.search(r"\bsid\s*:\s*(\d+)", line[line.find("(") + 1 : line.rfind(")")])
            if not m:
                continue
            sid = m.group(1)
            info = classify(line)
            info["source"] = str(path.relative_to(ROOT))
            out[sid] = info
            total += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_shared_aliases(ROOT.parent / "xbits" / "testdata" / "buffer_aliases.json")

    counts: dict[str, int] = {}
    for info in out.values():
        for b in info["buffers"] or ["<none>"]:
            counts[b] = counts.get(b, 0) + 1
    print(f"rules={total} sids={len(out)} -> {OUT}")
    for b, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        print(f"  {b}: {n}")


if __name__ == "__main__":
    main()