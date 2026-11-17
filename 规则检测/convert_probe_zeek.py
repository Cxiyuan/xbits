#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部探针规则导出 → Zeek 行为/情报脚本转换器。

Snort/WAF/PVS 的 content/pcre 规则不适合 Zeek；本转换器只提取
真正适合 Zeek 的**明文情报与白名单**，生成可直接加载的 Zeek 脚本：

  规则检测/zeek/Web行为/crawler_whitelist.zeek   搜索引擎爬虫 IP/网段/UA 校验
  规则检测/zeek/威胁情报/white_domains.zeek      业务白域名（减少 DNS/HTTP 误报）
  规则检测/zeek/威胁情报/public_dns_servers.zeek 公共 DNS 服务器清单
  规则检测/zeek/威胁情报/botnet_apps.zeek        僵尸网络/挖矿应用元数据

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


def write_botnet_apps(src: Path, out: Path) -> None:
    sections = parse_sections(src)
    entries = []
    for name, kv in sections.items():
        if not name.isdigit() or "name" not in kv:
            continue
        entries.append(
            (
                kv["name"],
                int(kv.get("danger_class", "0") or 0),
                kv.get("drop", "0") in ("1", "yes", "true"),
                kv.get("desc", kv.get("Desc", "")),
            )
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "##! 僵尸网络/挖矿应用元数据（由 convert_probe_zeek.py 生成）。",
        "##! 仅用于告警名称/危险等级归一化，检测依赖 Zeek 协议/行为事件。",
        "module XbitsBotnet;",
        "",
        "export {",
        "    type AppInfo: record {",
        "        danger_class: count;",
        "        drop: bool;",
        "        desc: string;",
        "    };",
        "",
        "    global botnet_apps: table[string] of AppInfo = {",
    ]
    for name, danger, drop, desc in entries:
        lines.append(
            f"        [{zeek_str(name)}] = AppInfo($danger_class={danger}, "
            f"$drop={'T' if drop else 'F'}, $desc={zeek_str(desc)}),"
        )
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

    write_crawler_whitelist(src / "search_spider.ini", OUT / "Web行为" / "crawler_whitelist.zeek")
    write_white_domains(src / "top100_white_domain.ini", OUT / "威胁情报" / "white_domains.zeek")
    write_public_dns(src / "common_dns_server.ini", OUT / "威胁情报" / "public_dns_servers.zeek")
    write_botnet_apps(src / "utm_app_botnet.ini", OUT / "威胁情报" / "botnet_apps.zeek")
    print("zeek scripts written under 规则检测/zeek/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())