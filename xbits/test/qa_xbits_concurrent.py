#!/usr/bin/env python3
"""Concurrent Suricata + Zeek -> xbits correlation test.

Runs the real xbits-suricata and xbits-zeek images against the same PCAP at
the same time.  The Suricata alert must wait for the matching Zeek HTTP
metadata, then be emitted once with high confidence/evidence.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def wait_socket(path: Path, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"xbits socket not created: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-suricata", default="xbits-suricata")
    parser.add_argument("--image-zeek", default="xbits-zeek")
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--rules", default=str(ROOT / "xbits" / "rules" / "analysis.json"))
    parser.add_argument("--pcap", default=str(ROOT / "测试用例" / "web_pcap" / "web_sqli_uri_union.pcap"))
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"missing pcap: {pcap}", file=sys.stderr)
        return 2
    work = Path(tempfile.mkdtemp(prefix="xbits-concurrent-"))
    engine = None
    try:
        sock = work / "hook.sock"
        alerts = work / "alerts.jsonl"
        (work / "suri").mkdir(parents=True, exist_ok=True)
        engine = subprocess.Popen(
            [str(args.xbits), "--hook-socket", str(sock), "--rules", str(args.rules),
             "--alert-file", str(alerts)],
            stdout=subprocess.DEVNULL,
            stderr=open(work / "engine.err", "w", encoding="utf-8"),
            text=True,
        )
        wait_socket(sock)

        common = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{work.resolve()}:/qa",
            "-v", f"{pcap.parent.resolve()}:/pcap:ro",
        ]
        suri = subprocess.Popen(
            common + [
                "-e", "XBITS_HOOK_SOCKET=/qa/hook.sock",
                "--entrypoint", "suricata", args.image_suricata,
                "-r", f"/pcap/{pcap.name}", "-c", "/opt/xbits/suricata-test.yaml", "-l", "/qa/suri",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        zeek = subprocess.Popen(
            common + [
                "-e", "ZEEK_PLUGIN_PATH=/opt/xbits/zeek-plugin",
                "-e", "ZEEK_PLUGIN_ACTIVATE=Xbits::Hook",
                "-e", "XBITS_HOOK_SOCKET=/qa/hook.sock",
                "--entrypoint", "/usr/local/zeek/bin/zeek", args.image_zeek,
                "-Cr", f"/pcap/{pcap.name}",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )

        s_out, s_err = suri.communicate(timeout=120)
        z_out, z_err = zeek.communicate(timeout=120)
        if suri.returncode != 0:
            print(f"suricata failed rc={suri.returncode}\n{s_err[-3000:]}", file=sys.stderr)
            return 1
        if zeek.returncode != 0:
            print(f"zeek failed rc={zeek.returncode}\n{z_err[-3000:]}", file=sys.stderr)
            return 1
        time.sleep(0.3)
    finally:
        if engine is not None:
            engine.terminate()
            try:
                engine.wait(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()
        # read before cleanup
        if alerts.exists():
            got = [json.loads(x) for x in alerts.read_text(encoding="utf-8").splitlines() if x.strip()]
        else:
            got = []
        shutil.rmtree(work, ignore_errors=True)

    print("=== xbits concurrent alerts ===")
    for ev in got:
        print(json.dumps(ev, ensure_ascii=False))
    matched = [
        ev for ev in got
        if ev.get("rule_id") == "xb-suricata-web-sqli"
        and int(ev.get("confidence", 0)) >= 80
        and "host=" in ev.get("evidence", "")
        and "uri=" in ev.get("evidence", "")
    ]
    if len(matched) != 1:
        print(f"CONCURRENT CONTEXT: FAIL expected exactly one high-confidence correlated alert, got {len(matched)}", file=sys.stderr)
        return 1
    if any(ev.get("rule_id") == "xb-zeek-appid-scanner" for ev in got):
        print("CONCURRENT CONTEXT: FAIL unexpected app-id alert in this isolated test", file=sys.stderr)
        return 1
    print("CONCURRENT CONTEXT: PASS (Suricata alert + Zeek metadata correlated exactly once)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
