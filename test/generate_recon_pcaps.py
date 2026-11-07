#!/usr/bin/env python3
"""Generate deterministic HTTP PCAPs for the recon-tool scenario.

Only used by tests; not part of detection. Requires scapy==2.6.1.
"""

from __future__ import annotations

import argparse
import os
from typing import List, Optional

from scapy.all import Ether, IP, Raw, TCP, wrpcap

BASE_TIME = 1700000000.0

# RFC 5737 / RFC 1918 only; no real customer data.
EXTERNAL_CLIENT_IP = "203.0.113.9"
EXTERNAL_CLIENT_MAC = "02:00:00:00:00:09"
EXTERNAL_SERVER_IP = "203.0.113.80"
EXTERNAL_SERVER_MAC = "02:00:00:00:00:80"
INTERNAL_CLIENT_IP = "10.0.0.5"
INTERNAL_CLIENT_MAC = "02:00:00:00:00:05"
INTERNAL_SERVER_IP = "10.0.0.80"
INTERNAL_SERVER_MAC = "02:00:00:00:00:80"

HTTP_PORT = 80


def http_request(
    path: str,
    user_agent: Optional[str],
    host: str = "app.example.test",
    method: str = "GET",
) -> bytes:
    lines = [
        "%s %s HTTP/1.1" % (method, path),
        "Host: %s" % host,
        "Accept: */*",
    ]
    if user_agent is not None:
        lines.append("User-Agent: %s" % user_agent)
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def http_response(status: int = 404) -> bytes:
    reasons = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}
    reason = reasons.get(status, "Response")
    return (
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, reason)
    ).encode("ascii")


def http_exchange(
    packets: List,
    client_ip: str,
    client_mac: str,
    server_ip: str,
    server_mac: str,
    sport: int,
    request: bytes,
    response: bytes,
    offset: float = 0.0,
) -> None:
    """Append one complete TCP/HTTP transaction to ``packets``."""

    cseq = 1000
    sseq = 5000
    dport = HTTP_PORT
    t0 = BASE_TIME + offset

    client_base = Ether(src=client_mac, dst=server_mac) / IP(
        src=client_ip, dst=server_ip
    )
    server_base = Ether(src=server_mac, dst=client_mac) / IP(
        src=server_ip, dst=client_ip
    )

    syn = client_base / TCP(sport=sport, dport=dport, flags="S", seq=cseq)
    syn.time = t0
    synack = server_base / TCP(
        sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1
    )
    synack.time = t0 + 0.001
    ack = client_base / TCP(
        sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1
    )
    ack.time = t0 + 0.002

    request_pkt = client_base / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=cseq + 1,
        ack=sseq + 1,
    ) / Raw(load=request)
    request_pkt.time = t0 + 0.003

    server_ack = server_base / TCP(
        sport=dport,
        dport=sport,
        flags="A",
        seq=sseq + 1,
        ack=cseq + 1 + len(request),
    )
    server_ack.time = t0 + 0.004

    response_pkt = server_base / TCP(
        sport=dport,
        dport=sport,
        flags="PA",
        seq=sseq + 1,
        ack=cseq + 1 + len(request),
    ) / Raw(load=response)
    response_pkt.time = t0 + 0.005

    client_ack = client_base / TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=cseq + 1 + len(request),
        ack=sseq + 1 + len(response),
    )
    client_ack.time = t0 + 0.006

    packets.extend(
        [syn, synack, ack, request_pkt, server_ack, response_pkt, client_ack]
    )


def add_external_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
) -> None:
    http_exchange(
        packets,
        EXTERNAL_CLIENT_IP,
        EXTERNAL_CLIENT_MAC,
        INTERNAL_SERVER_IP,
        INTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent),
        http_response(status),
        offset,
    )


def add_internal_to_external_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
) -> None:
    http_exchange(
        packets,
        INTERNAL_CLIENT_IP,
        INTERNAL_CLIENT_MAC,
        EXTERNAL_SERVER_IP,
        EXTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent),
        http_response(status),
        offset,
    )


def add_internal_to_internal_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
) -> None:
    http_exchange(
        packets,
        INTERNAL_CLIENT_IP,
        INTERNAL_CLIENT_MAC,
        INTERNAL_SERVER_IP,
        INTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent),
        http_response(status),
        offset,
    )


def write(name: str, packets: List, out_dir: str) -> None:
    path = os.path.join(out_dir, name + ".pcap")
    wrpcap(path, packets)


# 26 retained tool default UAs (9101017 Wappalyzer was removed: browser-only).
TOOL_CASES = [
    ("ffuf", "Fuzz Faster U Fool v2.1.0-dev"),
    ("gobuster", "gobuster/3.6"),
    ("feroxbuster", "feroxbuster/2.10.4"),
    ("sqlmap", "sqlmap/1.8.8#stable (https://sqlmap.org)"),
    (
        "nuclei",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    ),
    (
        "nmap",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; "
        "https://nmap.org/book/nse.html)",
    ),
    ("acunetix", "Acunetix"),
    ("dirbuster", "DirBuster-1.0-RC1"),
    ("nikto", "Nikto/2.5.0"),
    ("wpscan", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"),
    ("masscan", "masscan/1.3"),
    ("zmeu", "ZmEu"),
    ("morfeus", "Morfeus"),
    ("zgrab", "zgrab/0.2.0"),
    ("nessus", "Nessus"),
    ("openvas", "OpenVAS"),
    ("whatweb", "WhatWeb/0.5.5"),
    ("httpx", "httpx/1.6.0"),
    ("arjun", "Arjun/2.2.1"),
    ("wafw00f", "wafw00f/2.1.0"),
    ("commix", "commix/v1.0"),
    ("xsstrike", "XSStrike"),
    (
        "shodan",
        "Mozilla/5.0 (compatible; Shodan/1.0; +https://www.shodan.io/)",
    ),
    (
        "censys",
        "Mozilla/5.0 (compatible; CensysInspect/1.1; "
        "+https://about.censys.io/)",
    ),
    ("expanse", "Mozilla/5.0 (compatible; Expanse/1.0)"),
    ("l9explore", "l9explore"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out", default=os.path.join(os.path.dirname(__file__), "recon_pcap")
    )
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # 1. All retained tool default UAs, one request each. Path is benign, so the
    # sensitive-path context rules must not fire.
    p: List = []
    for index, (_name, ua) in enumerate(TOOL_CASES):
        add_external_case(
            p,
            40000 + index,
            "/",
            ua,
            status=404,
            offset=index * 0.1,
        )
    write("recon_tools_positive", p, args.out)

    # 2. sqlmap + sensitive path + HTTP 200: request context and response confirm.
    p = []
    add_external_case(
        p, 41000, "/.git/config", "sqlmap/1.8.8#stable (https://sqlmap.org)", 200
    )
    write("recon_sqlmap_sensitive", p, args.out)

    # 3. Nuclei + sensitive path + HTTP 403: protected but still probed.
    p = []
    add_external_case(
        p,
        41001,
        "/.env",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        403,
    )
    write("recon_nuclei_sensitive_403", p, args.out)

    # 4. Generic script client + sensitive path, 25 times: type both 20/60.
    p = []
    for i in range(25):
        add_external_case(
            p,
            42000 + i,
            "/.env",
            "python-requests/2.31.0",
            status=404,
            offset=i * 0.1,
        )
    write("recon_generic_path_rate", p, args.out)

    # 5. No UA at all + sensitive path, 25 times: proves the path rule is UA-free.
    p = []
    for i in range(25):
        add_external_case(
            p,
            43000 + i,
            "/.git/config",
            None,
            status=404,
            offset=i * 0.1,
        )
    write("recon_path_no_ua_rate", p, args.out)

    # 6. External curl, 60 requests: inbound telemetry rule type both 50/60.
    p = []
    for i in range(60):
        add_external_case(
            p,
            44000 + i,
            "/api",
            "curl/8.5.0",
            status=404,
            offset=i * 0.1,
        )
    write("recon_curl_rate", p, args.out)

    # 7. Internal host -> external server with a tool UA: outbound rule.
    p = []
    add_internal_to_external_case(
        p, 45000, "/", "sqlmap/1.8.8#stable (https://sqlmap.org)", 404
    )
    write("recon_outbound_tool", p, args.out)

    # 8. Internal host -> internal server with a tool UA: lateral rule.
    p = []
    add_internal_to_internal_case(p, 45001, "/", "gobuster/3.6", 404)
    write("recon_internal_tool", p, args.out)

    # 9. Negative: Python httpx library, not ProjectDiscovery httpx.
    p = []
    add_external_case(p, 46000, "/", "python-httpx/0.27.0", 200)
    write("recon_httpx_python_negative", p, args.out)

    # 10. Negative: normal browser.
    p = []
    add_external_case(
        p,
        46001,
        "/",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        200,
    )
    write("recon_browser_negative", p, args.out)

    # 11. Negative: empty User-Agent header.
    p = []
    add_external_case(p, 46002, "/", "", 200)
    write("recon_empty_ua_negative", p, args.out)

    # 12. Negative: no User-Agent header.
    p = []
    add_external_case(p, 46003, "/", None, 200)
    write("recon_no_ua_negative", p, args.out)

    # 13. Negative: Kubernetes health check, internal, benign path.
    p = []
    add_internal_to_internal_case(p, 46004, "/healthz", "kube-probe/1.29", 200)
    write("recon_healthcheck_negative", p, args.out)

    print("wrote recon PCAPs to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
