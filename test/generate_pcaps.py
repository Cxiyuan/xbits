#!/usr/bin/env python3
"""Generate deterministic DNS/TLS/HTTP PCAPs for the ips CI.

Only used by tests; not part of detection. Requires scapy==2.6.1.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from typing import Iterable, List, Optional

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap
from scapy.layers.tls.extensions import (
    ProtocolName,
    ServerName,
    TLS_Ext_ALPN,
    TLS_Ext_ServerName,
)
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

CLIENT_IP = "10.0.0.5"
DNS_IP = "10.0.0.53"
DOH_IP = "10.0.0.80"
CLIENT_MAC = "02:00:00:00:00:05"
DNS_MAC = "02:00:00:00:00:53"
DOH_MAC = "02:00:00:00:00:80"
BASE_TIME = 1700000000.0
BASE_PORT = 40000

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
HEX = "0123456789abcdef"


def deterministic_token(n: int, alphabet: str, step: int = 37, offset: int = 11) -> str:
    return "".join(alphabet[(i * step + offset) % len(alphabet)] for i in range(n))


def hex32(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def dns_answer(qname: str, rtype: str, rdata, ttl: int) -> DNSRR:
    return DNSRR(rrname=qname, type=rtype, ttl=ttl, rdata=rdata)


def dns_transaction(
    packets: List,
    qname: str,
    qtype: str,
    answers: Optional[DNSRR] = None,
    rcode: int = 0,
    offset: float = 0.0,
    ttl: int = 300,
) -> None:
    txid = (len(packets) // 2 + 1) & 0xFFFF
    sport = BASE_PORT + (len(packets) % 2000)
    q = (
        Ether(src=CLIENT_MAC, dst=DNS_MAC)
        / IP(src=CLIENT_IP, dst=DNS_IP)
        / UDP(sport=sport, dport=53)
        / DNS(id=txid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    q.time = BASE_TIME + offset
    r = (
        Ether(src=DNS_MAC, dst=CLIENT_MAC)
        / IP(src=DNS_IP, dst=CLIENT_IP)
        / UDP(sport=53, dport=sport)
        / DNS(
            id=txid,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            rcode=rcode,
            qd=DNSQR(qname=qname, qtype=qtype),
            an=answers if answers is not None else None,
        )
    )
    if answers is None:
        # Scapy needs an empty answer section, not None, for a clean response.
        r[DNS].an = None
        r[DNS].ancount = 0
    r.time = BASE_TIME + offset + 0.01
    packets.extend([q, r])


def tcp_session(
    packets: List,
    dst_ip: str,
    dst_mac: str,
    dst_port: int,
    payload: bytes,
    server_payload: bytes = b"",
    offset: float = 0.0,
) -> None:
    sport = BASE_PORT + 1000 + (len(packets) % 2000)
    cseq = 1000 + len(packets) * 100
    sseq = 5000 + len(packets) * 100
    base = base_packet = (
        Ether(src=CLIENT_MAC, dst=dst_mac) / IP(src=CLIENT_IP, dst=dst_ip)
    )
    server_base = (
        Ether(src=dst_mac, dst=CLIENT_MAC) / IP(src=dst_ip, dst=CLIENT_IP)
    )

    syn = base / TCP(sport=sport, dport=dst_port, flags="S", seq=cseq)
    syn.time = BASE_TIME + offset
    synack = server_base / TCP(
        sport=dst_port, dport=sport, flags="SA", seq=sseq, ack=cseq + 1
    )
    synack.time = BASE_TIME + offset + 0.01
    ack = base / TCP(sport=sport, dport=dst_port, flags="A", seq=cseq + 1, ack=sseq + 1)
    ack.time = BASE_TIME + offset + 0.02
    data = base / TCP(
        sport=sport, dport=dst_port, flags="PA", seq=cseq + 1, ack=sseq + 1
    ) / Raw(load=payload)
    data.time = BASE_TIME + offset + 0.03
    packets.extend([syn, synack, ack, data])

    # Pure ACK from the server before any server data. Some protocol
    # parsers only advance the stream once the client data is acknowledged.
    sack = server_base / TCP(
        sport=dst_port,
        dport=sport,
        flags="A",
        seq=sseq + 1,
        ack=cseq + 1 + len(payload),
    )
    sack.time = BASE_TIME + offset + 0.04
    packets.append(sack)

    if server_payload:
        sdata = server_base / TCP(
            sport=dst_port,
            dport=sport,
            flags="PA",
            seq=sseq + 1,
            ack=cseq + 1 + len(payload),
        ) / Raw(load=server_payload)
        sdata.time = BASE_TIME + offset + 0.05
        packets.append(sdata)


def build_tls_client_hello(sni: str, alpn: Optional[str]) -> bytes:
    ext = [TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())])]
    if alpn:
        ext.append(TLS_Ext_ALPN(protocols=[ProtocolName(protocol=alpn.encode())]))
    ch = TLSClientHello(ext=ext)
    return bytes(TLS(type=22, version=0x0301, msg=[ch]))


def build_tls_server_hello(alpn: Optional[str] = None) -> bytes:
    ext = []
    if alpn:
        ext.append(TLS_Ext_ALPN(protocols=[ProtocolName(protocol=alpn.encode())]))
    sh = TLSServerHello(ext=ext) if ext else TLSServerHello()
    return bytes(TLS(type=22, version=0x0303, msg=[sh]))


def build_doh_request(path: str) -> bytes:
    qname = "example.com"
    dns_body = bytes(DNS(id=1, rd=1, qd=DNSQR(qname=qname, qtype="A")))
    headers = (
        "POST %s HTTP/1.1\r\n"
        "Host: dns.google\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
    ) % (path, len(dns_body))
    return headers.encode() + dns_body


def write(name: str, packets: List, out_dir: str) -> None:
    path = os.path.join(out_dir, name + ".pcap")
    wrpcap(path, packets)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "pcap"))
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # P0 positive: 32hex + TXT payload + request/response confirmation.
    p = []
    q = "0123456789abcdef0123456789abcdef.evil.example"
    dns_transaction(p, q, "TXT", dns_answer(q, "TXT", deterministic_token(220, B64URL), 1))
    write("tunnel_32hex", p, args.out)

    # P0 positive: base32 label, normal A response (request-side triage only).
    p = []
    q = "mfrggzdfmztwq2lknh2e.evil.example"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("tunnel_base32_normal_a", p, args.out)

    # P0 negative: SPF TXT is human-readable; must not count as payload.
    p = []
    q = "random.evil.example"
    dns_transaction(p, q, "TXT", dns_answer(q, "TXT", "v=spf1 include:_spf.example.com ~all", 300))
    write("spf_txt", p, args.out)

    # P0 negative: domain verification TXT.
    p = []
    q = "random.evil.example"
    dns_transaction(p, q, "TXT", dns_answer(q, "TXT", "google-site-verification=abc123def456", 300))
    write("verify_txt", p, args.out)

    # P0 negative: DMARC.
    p = []
    q = "_dmarc.example.com"
    dns_transaction(p, q, "TXT", dns_answer(q, "TXT", "v=DMARC1; p=none;", 300))
    write("dmarc_txt", p, args.out)

    # P1 positive: CNAME tunnel target.
    p = []
    q = hex32("cname-seed") + ".evil.example"
    dns_transaction(
        p,
        q,
        "A",
        dns_answer(q, "CNAME", "kmzxq7v3pl2n8t4r6w9y1b5c0d.evil2.example", 30),
    )
    write("cname_tunnel", p, args.out)

    # UUID valid / invalid.
    p = []
    q = "550e8400-e29b-41d4-a716-446655440000.evil.example"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("uuid_valid", p, args.out)

    p = []
    q = "550e8400-e29b-91d4-c716-446655440000.evil.example"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("uuid_invalid", p, args.out)

    # Compact single-char labels: positive and hierarchy false positive.
    p = []
    q = "3.f.a.9.1.c.8.e.b.2.d.7.example.com"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("compact_positive", p, args.out)

    p = []
    q = "a.b.c.d.e.f.g.example.com"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("compact_negative", p, args.out)

    # Long label: random alnum (positive) vs hyphenated (negative).
    p = []
    q = deterministic_token(61, ALNUM) + ".evil.example"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("long_positive", p, args.out)

    p = []
    q = deterministic_token(61, ALNUM) + ".abc.def.co.uk"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("long_multilevel", p, args.out)

    p = []
    q = "xn--" + ("-" * 30) + ("a" * 27) + ".evil.example"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 300))
    write("long_negative", p, args.out)

    # OOB positive/negative.
    p = []
    q = "abc123.oast.pro"
    dns_transaction(p, q, "A", dns_answer(q, "A", "10.0.0.1", 60))
    write("oob_positive", p, args.out)

    p = []
    dns_transaction(p, "x.oast.pro", "A", dns_answer("x.oast.pro", "A", "10.0.0.1", 60))
    dns_transaction(p, "oast.pro", "A", dns_answer("oast.pro", "A", "10.0.0.1", 60))
    dns_transaction(p, "abc123.oast.pro", "MX", None)
    write("oob_negative", p, args.out)

    # TXT burst: positive (subdomain) vs negative (mail authentication).
    p = []
    for i in range(50):
        dns_transaction(
            p,
            "abc.example.com",
            "TXT",
            dns_answer("abc.example.com", "TXT", "ok", 300),
            offset=i * 1.0,
        )
    write("txt_burst_positive", p, args.out)

    p = []
    for i in range(50):
        dns_transaction(
            p,
            "_dmarc.example.com",
            "TXT",
            dns_answer("_dmarc.example.com", "TXT", "v=DMARC1; p=none;", 300),
            offset=i * 1.0,
        )
    write("txt_burst_negative", p, args.out)

    # DoT: positive (ALPN dot, DNS SNI) and negative (no ALPN, non-DNS SNI).
    p = []
    tcp_session(
        p,
        DNS_IP,
        DNS_MAC,
        853,
        build_tls_client_hello("dns.google", "dot"),
        build_tls_server_hello("dot"),
    )
    write("dot_positive", p, args.out)

    p = []
    tcp_session(
        p,
        DNS_IP,
        DNS_MAC,
        853,
        build_tls_client_hello("www.example.com", None),
        build_tls_server_hello(),
    )
    write("dot_negative", p, args.out)

    # DoH: positive /dns-query vs negative /api, both with the DoH content type.
    p = []
    tcp_session(
        p,
        DOH_IP,
        DOH_MAC,
        443,
        build_doh_request("/dns-query"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    write("doh_positive", p, args.out)

    p = []
    tcp_session(
        p,
        DOH_IP,
        DOH_MAC,
        443,
        build_doh_request("/api"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    write("doh_negative", p, args.out)

    print("wrote PCAPs to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
