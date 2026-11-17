#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 app-id/扫描工具 检出率/误报率 测试用 PCAP（scapy）。
输出到 app-id/tests/pcaps/，并写 manifest.json 描述每条用例的期望。
在 Zeek 9.0.1 容器内运行：python3 app-id/tests/gen_pcaps.py
"""
import os, json
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pcaps")
os.makedirs(OUT, exist_ok=True)

SERVER = "10.0.0.1"
DPORT = 80
MANIFEST = []


def tcp_stream(cip, sport, req, resp, dport=DPORT, t0=1700000000.0):
    """构造一条完整 TCP 会话（三次握手+请求/响应+四次挥手）。"""
    pkts = []
    isn_c = 1000 + sport * 7
    isn_s = 900000 + sport * 7
    t = t0

    def C(flags, seq, ack):
        return Ether()/IP(src=cip, dst=SERVER)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)

    def S(flags, seq, ack):
        return Ether()/IP(src=SERVER, dst=cip)/TCP(sport=dport, dport=sport, flags=flags, seq=seq, ack=ack)

    def add(p):
        nonlocal t
        p.time = t
        pkts.append(p)
        t += 0.002

    add(C('S', isn_c, 0))
    add(S('SA', isn_s, isn_c + 1))
    add(C('A', isn_c + 1, isn_s + 1))
    cseq, sseq = isn_c + 1, isn_s + 1
    if req:
        add(C('PA', cseq, sseq)/Raw(load=req)); cseq += len(req)
    if resp:
        add(S('PA', sseq, cseq)/Raw(load=resp)); sseq += len(resp)
        add(C('A', cseq, sseq))
    add(C('FA', cseq, sseq)); cseq += 1
    add(S('FA', sseq, cseq)); sseq += 1
    add(C('A', cseq, sseq))
    return pkts


def req_bytes(uri, ua, host="target.local", ver="HTTP/1.1"):
    h = f"GET {uri} {ver}\r\n"
    if host is not None:
        h += f"Host: {host}\r\n"
    if ua is not None:
        h += f"User-Agent: {ua}\r\n"
    h += "Accept: */*\r\nConnection: close\r\n\r\n"
    return h.encode()


def resp_bytes(code=404):
    return {
        200: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        403: b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        404: b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    }.get(code, b"HTTP/1.1 500 Err\r\nContent-Length: 0\r\n\r\n")


def emit(name, pkts, expect, tool=None, extra=None):
    wrpcap(os.path.join(OUT, name + ".pcap"), pkts)
    client = pkts[0][IP].src
    MANIFEST.append({"pcap": name + ".pcap", "client": client, "expect": expect,
                     "tool": tool, "extra": extra or []})


# ---- 品牌 UA 工具（单请求，B+ 字面自证）----
UA_CASES = [
    ("ffuf", "Fuzz Faster U Fool v2.1.0"),
    ("gobuster", "gobuster/3.6.0"),
    ("feroxbuster", "feroxbuster/2.10.0"),
    ("dirbuster", "DirBuster-1.0-RC1"),
    ("sqlmap", "sqlmap/1.7.2#stable"),
    ("nuclei", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"),
    ("nikto", "Nikto/2.5.0"),
    ("wpscan", "WPScan v3.8.22 (https://wpscan.com)"),
    ("acunetix", "Acunetix"),
    ("nessus", "Nessus"),
    ("openvas", "OpenVAS"),
    ("whatweb", "WhatWeb/0.5.5"),
    ("httpx", "httpx/1.3.7"),
    ("arjun", "Arjun/2.2.2"),
    ("wafw00f", "wafw00f"),
    ("commix", "commix/3.9"),
    ("xsstrike", "XSStrike/3.1.5"),
    ("shodan", "Mozilla/5.0 (compatible; Shodan/1.0)"),
    ("censys", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"),
    ("expanse", "Mozilla/5.0 (compatible; Expanse/1.0)"),
    ("l9explore", "l9explore/1.0"),
    ("zgrab", "zgrab/0.x"),
    ("zmeu", "ZmEu"),
    ("morfeus", "Morfeus"),
    # 本轮新增 18
    ("w3af", "w3af"),
    ("wapiti", "Wapiti/3.1.6"),
    ("arachni", "Arachni/1.6.2"),
    ("skipfish", "Skipfish/2.10b"),
    ("wfuzz", "Wfuzz/3.1.0"),
    ("netsparker", "Netsparker"),
    ("appscan", "AppScan"),
    ("webinspect", "HP WebInspect"),
    ("qualys", "Qualys"),
    ("nexpose", "Nexpose"),
    ("appspider", "AppSpider"),
    ("dalfox", "Dalfox"),
    ("kiterunner", "kiterunner/1.0"),
    ("joomscan", "JoomScan"),
    ("droopescan", "Droopescan"),
    ("cmseek", "CMSeek"),
    ("testssl", "testssl.sh"),
    ("sslscan", "sslscan"),
]

ip_i = 10
for tool, ua in UA_CASES:
    cip = f"10.1.0.{ip_i}"; ip_i += 1
    pk = tcp_stream(cip, 40000 + ip_i, req_bytes("/", ua), resp_bytes(404))
    emit(f"ua_{tool}", pk, "tool", tool)

# ---- nmap NSE UA（strong）----
pk = tcp_stream("10.2.0.1", 41001,
                req_bytes("/", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"),
                resp_bytes(200))
emit("nmap_nse_ua", pk, "tool", "nmap")

# ---- nmap TierA 探针（FourOhFourRequest，无 UA）----
four = b"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n"
pk = tcp_stream("10.2.0.2", 41002, four, resp_bytes(404))
emit("nmap_fourohfour", pk, "tool", "nmap")

# ---- nmap 探针序列（TierB x2 => probe_sequence）----
pk = []
pk += tcp_stream("10.2.0.3", 41003, b"GET / HTTP/1.0\r\n\r\n", resp_bytes(200))
pk += tcp_stream("10.2.0.3", 41004, b"OPTIONS / HTTP/1.0\r\n\r\n", resp_bytes(200), t0=1700000005.0)
emit("nmap_probe_seq", pk, "tool", "nmap")

# ---- 目录爆破：25 个不同 URI 全 404（generic UA）----
brute_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
pk = []
for k in range(25):
    pk += tcp_stream("10.3.0.1", 42000 + k, req_bytes(f"/admin{k}/", brute_ua), resp_bytes(404),
                     t0=1700000010.0 + k)
emit("dir_brute", pk, "unknown")

# ---- 端口扫描：SYN-only 到 12 个端口（无载荷）----
pk = []
sport = 43000
for p in range(20, 32):
    pkt = Ether()/IP(src="10.4.0.1", dst="10.4.0.2")/TCP(sport=sport, dport=p, flags='S', seq=1000)
    pkt.time = 1700000100.0 + (p - 20) * 0.01
    pk.append(pkt)
    sport += 1
emit("port_scan", pk, "unknown")

# ---- DNS PTR 反查扫描：25 个不同 PTR 查询 ----
pk = []
for k in range(25):
    q = f"{k}.0.0.10.in-addr.arpa"
    qp = Ether()/IP(src="10.5.0.1", dst="10.5.0.2")/UDP(sport=53000 + k, dport=53)/DNS(rd=1, qd=DNSQR(qname=q, qtype="PTR"))
    qp.time = 1700000150.0 + k * 0.05
    pk.append(qp)
emit("dns_ptr_recon", pk, "unknown")

# ---- 低速慢扫：100 个不同 URI 全 404，间隔 30s 跨 ~50 分钟（避开短窗目录爆破）----
pk = []
brute2 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
for k in range(100):
    pk += tcp_stream("10.6.0.1", 46000 + k, req_bytes(f"/slow{k}/", brute2), resp_bytes(404),
                     t0=1700001000.0 + k * 30)
emit("slow_scan", pk, "unknown")

# ---- TLS ClientHello 指纹（JA3-lite）：版本 0x0303 + ciphers [0x1301,0x1302,0x1303] ----
def tls_client_hello():
    version = 0x0303
    suites = (0x1301, 0x1302, 0x1303)
    body = version.to_bytes(2, 'big') + b"\x11" * 32 + b"\x00"
    cs = b"".join(s.to_bytes(2, 'big') for s in suites)
    body += len(cs).to_bytes(2, 'big') + cs + b"\x01\x00" + b"\x00\x00"
    hs = b"\x01" + len(body).to_bytes(3, 'big') + body
    return b"\x16" + b"\x03\x01" + len(hs).to_bytes(2, 'big') + hs

pk = tcp_stream("10.7.0.1", 47001, tls_client_hello(), None)
emit("tls_clienthello", pk, "tool", "go-tls", extra=["app-id/tests/redefs/tls_test_map.zeek"])

# ---- 负样本 ----
# 浏览器：30 个不同 URI，均 200，含静态资源
browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
pk = []
for k in range(30):
    uri = f"/page{k}.html" if k % 3 else f"/static/app{k}.js"
    pk += tcp_stream("10.9.0.1", 44000 + k, req_bytes(uri, browser_ua), resp_bytes(200),
                     t0=1700000200.0 + k)
emit("neg_browser", pk, "negative")

# curl 单请求
pk = tcp_stream("10.9.0.2", 45001, req_bytes("/", "curl/8.4.0"), resp_bytes(200))
emit("neg_curl", pk, "negative")

# python-requests 正常（5 个请求）
pk = []
for k in range(5):
    pk += tcp_stream("10.9.0.3", 45010 + k, req_bytes(f"/api/v1/item/{k}", "python-requests/2.31.0"),
                     resp_bytes(200), t0=1700000300.0 + k)
emit("neg_requests", pk, "negative")

# 健康检查（无 UA，单请求）
pk = tcp_stream("10.9.0.4", 45020, req_bytes("/healthz", None), resp_bytes(200))
emit("neg_health", pk, "negative")

# Go 客户端正常
pk = []
for k in range(3):
    pk += tcp_stream("10.9.0.5", 45030 + k, req_bytes(f"/v1/ping/{k}", "Go-http-client/1.1"),
                     resp_bytes(200), t0=1700000400.0 + k)
emit("neg_go", pk, "negative")

# app-identity test PCAPs (not part of scanner manifest)
p = []
p.extend(tcp_stream("10.2.0.1", 42001,
                    req_bytes("/", "Mozilla/5.0", host="facebook.com"),
                    resp_bytes(200)))
wrpcap(os.path.join(OUT, "app_identity_http_host.pcap"), p)

p = []
p.extend(tcp_stream("10.2.0.2", 42002,
                    req_bytes("/", "Dropbox/1.0", host="unknown.local"),
                    resp_bytes(200)))
wrpcap(os.path.join(OUT, "app_identity_http_ua.pcap"), p)

p = []
p.extend(tcp_stream("10.2.0.3", 42003,
                    req_bytes("/", "Mozilla/5.0", host="unknown.local"),
                    resp_bytes(200)))
wrpcap(os.path.join(OUT, "app_identity_negative.pcap"), p)

with open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(MANIFEST, f, ensure_ascii=False, indent=2)

print(f"generated {len(MANIFEST)} pcaps -> {OUT}")
