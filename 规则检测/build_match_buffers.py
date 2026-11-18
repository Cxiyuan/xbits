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
    "isdataat", "dsize", "urilen", "filemagic", "filename", "fileext", "lua",
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
    n = name.strip().lower()
    if n in ALIASES:
        return ALIASES[n]
    if n in {"payload", "stream", "lua"}:
        return n
    if n.startswith(PREFIXES):
        # 统一部分 dotted 名称
        if n.startswith("http.request_header") or n.startswith("http.response_header"):
            return "http.header"
        if n.startswith("http.uri"):
            return "http.uri"
        if n.startswith("http.host"):
            return "http.host"
        if n.startswith("http.cookie"):
            return "http.cookie"
        if n in {"http.stat_code", "http.stat_msg"}:
            return "http.status"
        if n.startswith("dns.queries."):
            return "dns.query"
        if n.startswith("dns.query"):
            return "dns.query"
        return n
    return None


def classify(rule: str) -> dict:
    body = rule[rule.find("(") + 1 : rule.rfind(")")]
    tokens = split_options(body)
    buffers: list[str] = []
    has_match = False
    for token in tokens:
        head = token.split(":", 1)[0].strip().lower()
        if head in MATCH_KEYWORDS:
            has_match = True
        b = canonical_buffer(token if ":" not in token else head)
        if b and b not in buffers:
            buffers.append(b)

    if not buffers and has_match:
        buffers.append("payload")
    if not buffers and re.search(r"\blua\s*:", body, re.I):
        buffers.append("lua")

    # 稳定性：按名称排序；primary 选择最具体的应用层 buffer
    buffers = sorted(set(buffers))
    # Lua app-tx 脚本可能通过 API 检查多个 buffer，C 层没有单一精确 buffer 可导出。
    # 当规则同时声明了具体 sticky buffer 时，只用这些可导出的 buffer 做精确 key；
    # 保留裸 "lua" 会迫使 xbits 用 p->payload 等近似值，属于兜底，禁止。
    concrete = [b for b in buffers if b != "lua"]
    # 纯 app-tx Lua 规则（除 lua 外没有任何具体 buffer）：无精确导出，
    # 显式标记 app_tx_lua=true，xbits 对其不做抑制（判定仍走 validator）。
    app_tx_lua = False
    if concrete:
        buffers = concrete
    elif buffers == ["lua"]:
        app_tx_lua = True
    primary = next((b for b in buffers if b not in {"payload", "stream", "lua"}), None)
    if primary is None and buffers:
        primary = buffers[0]

    has_payload = any(b in {"payload", "stream", "file.data", "lua"} for b in buffers)
    return {
        "buffers": buffers,
        "primary": primary,
        "has_payload": has_payload,
        "app_tx_lua": app_tx_lua,
    }


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

    counts: dict[str, int] = {}
    for info in out.values():
        for b in info["buffers"] or ["<none>"]:
            counts[b] = counts.get(b, 0) + 1
    print(f"rules={total} sids={len(out)} -> {OUT}")
    for b, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        print(f"  {b}: {n}")


if __name__ == "__main__":
    main()