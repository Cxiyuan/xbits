#!/usr/bin/env python3
"""Generate deterministic HTTP PCAPs for the recon-tool scenario.

Only used by tests; not part of detection. Requires scapy==2.6.1.
"""

from __future__ import annotations

import argparse
import os
from typing import Dict, List, Optional

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
    extra_headers: Optional[Dict[str, str]] = None,
) -> bytes:
    lines = [
        "%s %s HTTP/1.1" % (method, path),
        "Host: %s" % host,
        "Accept: */*",
    ]
    if user_agent is not None:
        lines.append("User-Agent: %s" % user_agent)
    for name, value in (extra_headers or {}).items():
        lines.append("%s: %s" % (name, value))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def http_response(
    status: int = 404,
    body: bytes = b"",
    content_type: str = "text/plain",
) -> bytes:
    reasons = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
    }
    reason = reasons.get(status, "Response")
    return (
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, reason, content_type, len(body))
    ).encode("ascii") + body


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


def keep_alive_session(
    packets: List,
    client_ip: str,
    client_mac: str,
    server_ip: str,
    server_mac: str,
    sport: int,
    exchanges: List,
    start_offset: float = 0.0,
    step: float = 0.1,
) -> None:
    """One TCP connection carrying N HTTP request/response exchanges (keep-alive).

    Same 5-tuple for N transactions: Suricata and Zeek alerts/correlation land on
    the same connection, so community_id matches by construction (required for
    burst cases; per-transaction sport made the two engines pick different flows).
    """
    dport = HTTP_PORT
    client_base = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip)
    server_base = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip)

    cseq = 1000
    sseq = 5000
    t0 = BASE_TIME + start_offset

    syn = client_base / TCP(sport=sport, dport=dport, flags="S", seq=cseq)
    syn.time = t0
    synack = server_base / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    synack.time = t0 + 0.001
    ack = client_base / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1)
    ack.time = t0 + 0.002
    packets.extend([syn, synack, ack])

    for i, (request, response) in enumerate(exchanges):
        t = BASE_TIME + start_offset + i * step
        req = client_base / TCP(
            sport=sport, dport=dport, flags="PA", seq=cseq + 1, ack=sseq + 1
        ) / Raw(load=request)
        req.time = t + 0.003
        srv_ack = server_base / TCP(
            sport=dport, dport=sport, flags="A", seq=sseq + 1, ack=cseq + 1 + len(request)
        )
        srv_ack.time = t + 0.004
        resp = server_base / TCP(
            sport=dport, dport=sport, flags="PA", seq=sseq + 1, ack=cseq + 1 + len(request)
        ) / Raw(load=response)
        resp.time = t + 0.005
        cli_ack = client_base / TCP(
            sport=sport,
            dport=dport,
            flags="A",
            seq=cseq + 1 + len(request),
            ack=sseq + 1 + len(response),
        )
        cli_ack.time = t + 0.006
        packets.extend([req, srv_ack, resp, cli_ack])
        cseq += len(request)
        sseq += len(response)

    fin_c = client_base / TCP(sport=sport, dport=dport, flags="FA", seq=cseq + 1, ack=sseq + 1)
    fin_c.time = BASE_TIME + start_offset + len(exchanges) * step + 0.01
    fin_s = server_base / TCP(sport=dport, dport=sport, flags="FA", seq=sseq + 1, ack=cseq + 2)
    fin_s.time = BASE_TIME + start_offset + len(exchanges) * step + 0.012
    packets.extend([fin_c, fin_s])


def add_external_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
    body: bytes = b"",
    content_type: str = "text/plain",
    extra_headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    host: str = "app.example.test",
) -> None:
    http_exchange(
        packets,
        EXTERNAL_CLIENT_IP,
        EXTERNAL_CLIENT_MAC,
        INTERNAL_SERVER_IP,
        INTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent, host, method, extra_headers),
        http_response(status, body, content_type),
        offset,
    )


def add_internal_to_external_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
    body: bytes = b"",
    content_type: str = "text/plain",
    extra_headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    host: str = "app.example.test",
) -> None:
    http_exchange(
        packets,
        INTERNAL_CLIENT_IP,
        INTERNAL_CLIENT_MAC,
        EXTERNAL_SERVER_IP,
        EXTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent, host, method, extra_headers),
        http_response(status, body, content_type),
        offset,
    )


def add_internal_to_internal_case(
    packets: List,
    sport: int,
    path: str,
    user_agent: Optional[str],
    status: int = 404,
    offset: float = 0.0,
    body: bytes = b"",
    content_type: str = "text/plain",
    extra_headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    host: str = "app.example.test",
) -> None:
    http_exchange(
        packets,
        INTERNAL_CLIENT_IP,
        INTERNAL_CLIENT_MAC,
        INTERNAL_SERVER_IP,
        INTERNAL_SERVER_MAC,
        sport,
        http_request(path, user_agent, host, method, extra_headers),
        http_response(status, body, content_type),
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

    # 6b. Internal host -> external server, 60 curl requests: outbound telemetry.
    p = []
    for i in range(60):
        add_internal_to_external_case(
            p,
            44500 + i,
            "/api",
            "curl/8.5.0",
            status=404,
            offset=i * 0.1,
        )
    write("recon_outbound_curl_rate", p, args.out)

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

    # 14. Body-confirmed exposure: real .git/config content.
    p = []
    add_external_case(
        p,
        47000,
        "/.git/config",
        "sqlmap/1.8.8#stable (https://sqlmap.org)",
        200,
        body=b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
        content_type="text/plain",
    )
    write("recon_body_confirmed", p, args.out)

    # 15. Negative: SPA soft-404 with HTTP 200 must not be "success".
    p = []
    add_external_case(
        p,
        47001,
        "/.git/config",
        "sqlmap/1.8.8#stable (https://sqlmap.org)",
        200,
        body=b"<!doctype html><html><body>Page not found</body></html>",
        content_type="text/html",
    )
    write("recon_soft404_negative", p, args.out)

    # 16. Random-UA wordlist scanning: 60 non-sensitive paths -> 403/404 burst.
    # burst 必须走同一条 TCP 连接（keep-alive）：Suricata 与 Zeek 的告警/关联
    # 都落在同一 5 元组，community_id 两侧由构造保证一致。
    p = []
    exchanges = []
    for i in range(60):
        exchanges.append(
            (
                http_request(
                    "/wordlist-%03d" % i,
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "app.example.test",
                ),
                http_response(404, b"", "text/plain"),
            )
        )
    keep_alive_session(
        p,
        EXTERNAL_CLIENT_IP,
        EXTERNAL_CLIENT_MAC,
        INTERNAL_SERVER_IP,
        INTERNAL_SERVER_MAC,
        47100,
        exchanges,
        start_offset=0.0,
        step=0.1,
    )
    write("recon_404_burst", p, args.out)

    # 17. Negative: static asset 404s must not count as wordlist scanning.
    p = []
    for i in range(60):
        add_external_case(
            p,
            47200 + i,
            "/assets/img-%03d.png" % i,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            status=404,
            offset=i * 0.1,
        )
    write("recon_404_static_negative", p, args.out)

    # 18. Acunetix-specific header with a browser-like UA.
    p = []
    add_external_case(
        p,
        47300,
        "/",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        200,
        extra_headers={"Acunetix-Aspect": "1"},
    )
    write("recon_acunetix_header", p, args.out)

    # 19. Double percent-encoded sensitive path, no UA.
    p = []
    for i in range(25):
        add_external_case(
            p,
            47400 + i,
            "/%252e%2567%2569%2574/config",
            None,
            status=404,
            offset=i * 0.1,
        )
    write("recon_path_double_encoded", p, args.out)

    # 20. Dot-segment sensitive path, no UA.
    p = []
    for i in range(25):
        add_external_case(
            p,
            47500 + i,
            "/foo/%2e%2e/.git/config",
            None,
            status=404,
            offset=i * 0.1,
        )
    write("recon_path_dot_segment", p, args.out)

    # 21. Backslash-encoded sensitive path, no UA.
    p = []
    for i in range(25):
        add_external_case(
            p,
            47600 + i,
            "/.git%5cconfig",
            None,
            status=404,
            offset=i * 0.1,
        )
    write("recon_path_backslash", p, args.out)

    # 22. Wrapped tool UA: triage fallback, not the strict-start tool SID.
    p = []
    add_external_case(
        p,
        47700,
        "/",
        "Mozilla/5.0 (compatible; sqlmap/1.8.8)",
        404,
    )
    write("recon_wrapped_ua", p, args.out)

    # 23. Outbound internet-scanner UA: telemetry, not High attack tool.
    p = []
    add_internal_to_external_case(
        p,
        47701,
        "/",
        "Shodan/1.0",
        404,
    )
    write("recon_outbound_scanner_ua", p, args.out)

    # 24. Anomalous method: external TRACE.
    p = []
    add_external_case(
        p,
        47702,
        "/.git/config",
        None,
        status=404,
        method="TRACE",
    )
    write("recon_method_trace", p, args.out)

    # 25. Negative: normal external PUT to a non-sensitive API path.
    p = []
    add_external_case(
        p,
        47703,
        "/api",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        status=404,
        method="PUT",
    )
    write("recon_method_put_benign_negative", p, args.out)

    # 26. Context-side double-encoded sensitive path with a tool UA.
    p = []
    add_external_case(
        p,
        47800,
        "/%252e%2567%2569%2574/config",
        "sqlmap/1.8.8#stable (https://sqlmap.org)",
        404,
    )
    write("recon_context_double_encoded", p, args.out)

    # 27. 401/403 protected path with an HTML login page must still alert.
    p = []
    add_external_case(
        p,
        47801,
        "/.env",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        403,
        body=b"<!doctype html><html><body>Sign in</body></html>",
        content_type="text/html",
    )
    write("recon_nuclei_403_html", p, args.out)

    # 28. 201 Created with a real .git/config body: 2xx, not just 200.
    p = []
    add_external_case(
        p,
        47802,
        "/.git/config",
        "sqlmap/1.8.8#stable (https://sqlmap.org)",
        201,
        body=b"[core]\n\trepositoryformatversion = 0\n",
        content_type="text/plain",
    )
    write("recon_body_201", p, args.out)

    print("wrote recon PCAPs to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
