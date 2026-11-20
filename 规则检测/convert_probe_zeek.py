#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部探针规则导出 → Zeek 行为/情报脚本转换器。

Snort/WAF/PVS 的 content/pcre 规则不适合 Zeek；历史上本转换器曾把明文
情报与白名单转成 Zeek 数据脚本（white_domains/public_dns_servers/botnet_apps）。

注意：随「Zeek 纯行为分析」的架构决策，这些数据脚本已全部移除——
白名单/基线统一由根目录 allowlist/ 子模块提供（custom/ 自定义 + data/ 快照
+ tools/{add,refresh,query}.py），威胁情报由 threat-intel/ 子模块提供，
xbits 在 hook 到的事件上统一查询。本转换器现仅保留解析工具函数供历史
转译参考；不再向 规则检测/zeek/ 输出任何数据脚本。

输入：桌面 `流量检测规则` 导出目录。
无法转换的内容（哈希化 UA 名单、SLS 加密黑名单、Snort 内容规则、
Public Suffix List、需要 DGA 算法的 Conficker 参数）在 README 中说明。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "zeek"


def parse_sections(path: Path) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    cur = None
    for raw in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections[cur] = {}
            continue
        if cur and "=" in line:
            k, v = line.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def zeek_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_crawler_whitelist(src: Path, out: Path) -> None:
    sec = parse_sections(src)
    hosts = [v for v in sec.get("spider_ip", {}).values() if re.match(r"^\d+\.", v)]
    segs = [v for v in sec.get("spider_seg", {}).values() if re.match(r"^\d+\.", v)]
    uas = [v for v in sec.get("spider_ua", {}).values() if v]
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "##! 搜索引擎爬虫白名单（由 convert_probe_zeek.py 生成）。",
        "##! UA 命中爬虫特征但源 IP 不在爬虫网段 → 伪造爬虫告警。",
        "##! 与自研脚本一致使用 Log 框架，便于 -b 模式加载与 xbits 消费。",
        "",
        "@load base/frameworks/logging",
        "@load base/protocols/conn",
        "@load base/protocols/http",
        "",
        "module XbitsCrawler;",
        "",
        "export {",
        "    redef enum Log::ID += { LOG };",
        "",
        "    type Info: record {",
        "        ts: time &log;",
        "        orig_h: addr &log;",
        "        host: string &log;",
        "        uri: string &log;",
        "        ua: string &log;",
        "        msg: string &log;",
        "    };",
        "",
        "    global spider_hosts: set[addr] = {",
    ]
    for h in hosts:
        lines.append(f"        {h},")
    lines += ["    };", "", "    global spider_nets: set[subnet] = {"]
    for s in segs:
        lines.append(f"        {s}/24,")
    lines += ["    };", "", "    global spider_ua_patterns: set[string] = {"]
    for ua in uas:
        lines.append(f"        {zeek_str(ua)},")
    lines += [
        "    };",
        "",
        "    global is_spider_ua: function(ua: string): bool;",
        "    global is_spider_addr: function(a: addr): bool;",
        "}",
        "",
        "function is_spider_ua(ua: string): bool",
        "    {",
        '    if ( ua == "" )',
        "        return F;",
        "    for ( p in spider_ua_patterns )",
        "        if ( p in ua )",
        "            return T;",
        "    return F;",
        "    }",
        "",
        "function is_spider_addr(a: addr): bool",
        "    {",
        "    if ( a in spider_hosts )",
        "        return T;",
        "    for ( n in spider_nets )",
        "        if ( a in n )",
        "            return T;",
        "    return F;",
        "    }",
        "",
        "event zeek_init()",
        "    {",
        "    Log::create_stream(XbitsCrawler::LOG, [$columns=XbitsCrawler::Info,",
        '                                          $path="crawler_impersonation"]);',
        "    }",
        "",
        "event http_request(c: connection, method: string, original_URI: string,",
        "                   unescaped_URI: string, version: string)",
        "    {",
        "    if ( ! c$http?$user_agent )",
        "        return;",
        "    local ua = c$http$user_agent;",
        "    if ( is_spider_ua(ua) && ! is_spider_addr(c$id$orig_h) )",
        "        Log::write(XbitsCrawler::LOG, [$ts=network_time(),",
        "                                       $orig_h=c$id$orig_h,",
        "                                       $host=c$http$host,",
        "                                       $uri=unescaped_URI,",
        "                                       $ua=ua,",
        '                                       $msg=fmt("crawler UA from non-crawler host: %s", c$id$orig_h)]);',
        "    }",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


def write_white_domains(src: Path, out: Path) -> None:
    sec = parse_sections(src)
    domains = [v for v in sec.get("white_domain", {}).values() if v]
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "##! 业务白域名（由 convert_probe_zeek.py 生成），供 xbits/Zeek 误报抑制。",
        "module XbitsAllowlist;",
        "",
        "export {",
        "    global white_domains: set[string] = {",
    ]
    for d in domains:
        lines.append(f"        {zeek_str(d)},")
    lines += [
        "    };",
        "",
        "    global is_white_domain: function(d: string): bool;",
        "}",
        "",
        "function is_white_domain(d: string): bool",
        "    {",
        "    for ( w in white_domains )",
        '        if ( d == w || ( |d| > |w| && sub_bytes(d, |d| - |w| - 1, |w| + 1) == "." + w ) )',
        "            return T;",
        "    return F;",
        "    }",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


def write_public_dns(src: Path, out: Path) -> None:
    sec = parse_sections(src)
    ips = [v.split()[0] for v in sec.get("dns_ip", {}).values() if v]
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "##! 公共 DNS 服务器清单（由 convert_probe_zeek.py 生成）。",
        "module XbitsDNS;",
        "",
        "export {",
        "    global public_dns_servers: set[addr] = {",
    ]
    for ip in ips:
        lines.append(f"        {ip},")
    lines += ["    };", "}", ""]
    out.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="外部探针导出目录（流量检测规则）")
    args = parser.parse_args()
    src = Path(args.src) / "etc_fw" / "utm"
    if not src.is_dir():
        print(f"missing UTM dir: {src}", file=sys.stderr)
        return 2

    # Zeek 只做纯行为分析：不生成任何数据/情报脚本。
    # - 爬虫 UA 匹配属于 Suricata 签名（crawler_whitelist 不生成）；
    # - botnet_apps 无检测引擎消费（孤儿数据），不生成；
    # - 白域名/公共 DNS 白名单已迁至根目录 allowlist/ 子模块（custom/ 自定义 + tools/ 查询），
    #   由 xbits 在 hook 到的事件上统一查询。
    print("nothing to generate: zeek is behavior-analysis only; allowlists live in allowlist/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())