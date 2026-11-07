#!/usr/bin/env python3
"""Generate deterministic HTTP PCAPs for the backdoor/C2 scenario.

Only used by tests; not part of detection. Requires scapy==2.6.1.
"""

from __future__ import annotations

import argparse
import base64
import os
from typing import Dict, List, Optional

from scapy.all import Ether, IP, Raw, TCP, wrpcap

BASE_TIME = 1700000000.0
EXTERNAL_IP = "203.0.113.9"
EXTERNAL_MAC = "02:00:00:00:00:09"
INTERNAL_IP = "10.0.0.5"
INTERNAL_MAC = "02:00:00:00:00:05"
SERVER_IP = "10.0.0.80"
SERVER_MAC = "02:00:00:00:00:80"
C2_IP = "203.0.113.80"
C2_MAC = "02:00:00:00:00:80"
HTTP_PORT = 80

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "http://app.example.test/",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
}

MINIMAL_HEADERS = {"User-Agent": "Mozilla/5.0"}


def http_request(
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
) -> bytes:
    lines = [
        "%s %s HTTP/1.1" % (method, path),
        "Host: app.example.test",
    ]
    for name, value in (headers or {}).items():
        lines.append("%s: %s" % (name, value))
    if body and not any(k.lower() == "content-length" for k in (headers or {})):
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def http_response(status: int = 200, body: bytes = b"", content_type: str = "text/plain") -> bytes:
    reasons = {200: "OK", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}
    return (
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, reasons.get(status, "Response"), content_type, len(body))
    ).encode("ascii") + body


def exchange(
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
    cseq, sseq = 1000, 5000
    t0 = BASE_TIME + offset
    cb = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip)
    sb = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip)

    syn = cb / TCP(sport=sport, dport=HTTP_PORT, flags="S", seq=cseq)
    syn.time = t0
    synack = sb / TCP(sport=HTTP_PORT, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    synack.time = t0 + 0.001
    ack = cb / TCP(sport=sport, dport=HTTP_PORT, flags="A", seq=cseq + 1, ack=sseq + 1)
    ack.time = t0 + 0.002
    req = cb / TCP(sport=sport, dport=HTTP_PORT, flags="PA", seq=cseq + 1, ack=sseq + 1) / Raw(load=request)
    req.time = t0 + 0.003
    sack = sb / TCP(sport=HTTP_PORT, dport=sport, flags="A", seq=sseq + 1, ack=cseq + 1 + len(request))
    sack.time = t0 + 0.004
    resp = sb / TCP(sport=HTTP_PORT, dport=sport, flags="PA", seq=sseq + 1, ack=cseq + 1 + len(request)) / Raw(load=response)
    resp.time = t0 + 0.005
    cack = cb / TCP(sport=sport, dport=HTTP_PORT, flags="A", seq=cseq + 1 + len(request), ack=sseq + 1 + len(response))
    cack.time = t0 + 0.006
    packets.extend([syn, synack, ack, req, sack, resp, cack])


def add_webshell(
    packets: List,
    sport: int,
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    response_body: bytes = b"",
    offset: float = 0.0,
) -> None:
    exchange(
        packets, EXTERNAL_IP, EXTERNAL_MAC, SERVER_IP, SERVER_MAC, sport,
        http_request(path, method, headers, body),
        http_response(200, response_body),
        offset,
    )


def add_c2(
    packets: List,
    sport: int,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    response_body: bytes = b"",
    offset: float = 0.0,
) -> None:
    exchange(
        packets, INTERNAL_IP, INTERNAL_MAC, C2_IP, C2_MAC, sport,
        http_request(path, "GET", headers),
        http_response(200, response_body),
        offset,
    )


def write(name: str, packets: List, out_dir: str) -> None:
    wrpcap(os.path.join(out_dir, name + ".pcap"), packets)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "backdoor_pcap"))
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # --- WebShell ---
    p = []
    add_webshell(p, 40001, "/uploads/shell.php", headers=BROWSER_HEADERS, response_body=b"Welcome")
    write("ws_path_only", p, args.out)

    p = []
    add_webshell(
        p, 40002, "/uploads/shell.php?cmd=id", headers=BROWSER_HEADERS,
        response_body=b"uid=0(root) gid=0(root) groups=0(root)\n",
    )
    write("ws_cmd_query", p, args.out)

    p = []
    add_webshell(
        p, 40003, "/uploads/shell.php", "POST",
        {"Content-Type": "application/x-www-form-urlencoded", **BROWSER_HEADERS},
        b"cmd=whoami", b"www-data\n",
    )
    write("ws_cmd_post", p, args.out)

    p = []
    add_webshell(
        p, 40004, "/uploads/x.php?z0=" + b64(b"id"),
        headers=BROWSER_HEADERS, response_body=b"uid=0(root) gid=0(root)\n",
    )
    write("ws_z0_base64", p, args.out)

    p = []
    add_webshell(
        p, 40005, "/uploads/shell.php",
        headers={"Cookie": "pass=" + b64(b"id"), **BROWSER_HEADERS},
        response_body=b"uid=0(root) gid=0(root)\n",
    )
    write("ws_cookie", p, args.out)

    p = []
    add_webshell(p, 40006, "/index.php", headers={"User-Agent": "antSword/1.0", **BROWSER_HEADERS})
    write("ws_tool_ua", p, args.out)

    p = []
    add_webshell(p, 40007, "/index.php?cmd=config", headers=BROWSER_HEADERS, response_body=b"ok")
    write("ws_negative_param", p, args.out)

    p = []
    add_webshell(p, 40008, "/index.php", headers=BROWSER_HEADERS, response_body=b"ok")
    write("ws_negative_browser", p, args.out)

    # --- C2 ---
    c2_ua = "Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0"
    p = []
    add_c2(p, 41001, "/?a=&f=&t=&p=123", headers={**BROWSER_HEADERS, "User-Agent": c2_ua})
    write("c2_sample", p, args.out)

    p = []
    add_c2(p, 41002, "/?p=42&t=z&f=&a=", headers=BROWSER_HEADERS)
    write("c2_variant", p, args.out)

    p = []
    add_c2(p, 41003, "/?a=&f=&t=&p=42", headers=MINIMAL_HEADERS)
    write("c2_header_anomaly", p, args.out)

    p = []
    add_c2(p, 41004, "/api/beacon/task/list", headers=BROWSER_HEADERS)
    write("c2_panel", p, args.out)

    p = []
    add_c2(p, 41005, "/?a=&b=&c=", headers=MINIMAL_HEADERS)
    write("c2_singleletter", p, args.out)

    p = []
    add_c2(
        p, 41006, "/?a=&f=&t=&p=42", headers=MINIMAL_HEADERS,
        response_body=b'{"task":"exec","command":"whoami"}',
    )
    write("c2_response", p, args.out)

    p = []
    add_c2(p, 41007, "/", headers={**BROWSER_HEADERS, "User-Agent": c2_ua})
    write("c2_old_ua", p, args.out)

    p = []
    add_c2(p, 41008, "/?a=1&b=2&c=3", headers=BROWSER_HEADERS)
    write("c2_negative_analytics", p, args.out)

    p = []
    add_c2(p, 41009, "/api/file/upload", headers=BROWSER_HEADERS)
    write("c2_negative_panel", p, args.out)

    print("wrote backdoor/C2 PCAPs to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
