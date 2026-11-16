#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smoke test for xbits --hook-socket central engine path.

Starts xbits, connects to its Unix hook socket, sends a Suricata alert and a
Zeek event, and verifies the engine emits the expected matched alert JSONL.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time


def wait_socket(path, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path) and stat_is_socket(path):
            return True
        time.sleep(0.05)
    return False


def stat_is_socket(path):
    try:
        import stat
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xbits", required=True)
    ap.add_argument("--rules", required=True)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="xbits-hook-") as td:
        sock = os.path.join(td, "hook.sock")
        proc = subprocess.Popen(
            [args.xbits, "--hook-socket", sock, "--rules", args.rules],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            if not wait_socket(sock):
                err = proc.stderr.read() if proc.stderr else ""
                raise SystemExit(f"hook socket not ready: {err}")
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(sock)
            events = [
                {
                    "source": "suricata",
                    "kind": "alert",
                    "sid": 9103001,
                    "signature": "[Web漏洞利用] SQL 注入",
                    "src": "203.0.113.9",
                    "dst": "10.0.0.80",
                    "sport": 40001,
                    "dport": 80,
                    "proto": "TCP",
                },
                {
                    "source": "zeek",
                    "kind": "event",
                    "event": "http_request",
                },
            ]
            for ev in events:
                c.sendall((json.dumps(ev, ensure_ascii=False) + "\n").encode())
            c.close()

            line = proc.stdout.readline().strip()
            assert line, "engine produced no output"
            got = json.loads(line)
            assert got.get("signature_id") == 9103001, got
            assert got.get("rule_id") == "xb-suricata-web-sqli", got
            print("PASS hook engine:", line)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
