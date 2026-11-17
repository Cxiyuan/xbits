#!/usr/bin/env python3
"""Verify app-id scanner alerts reach xbits through the Zeek thin hook.

This is intentionally separate from `app-id/tests/run_tests.py`:
  * run_tests.py proves app-id's scan_report/xbits_alert behavior inside Zeek;
  * this script proves the same app-id `XbitsAlert::alert` event is actually
    forwarded by the Zeek hook plugin into the xbits central engine.
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
    raise RuntimeError(f"socket not created: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="xbits-zeek")
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--rules", default=str(ROOT / "xbits" / "rules" / "qa-all.json"))
    parser.add_argument("--pcap", default=str(ROOT / "app-id" / "tests" / "pcaps" / "ua_gobuster.pcap"))
    parser.add_argument("--redefs", default=str(ROOT / "app-id" / "tests" / "redefs"))
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"missing pcap: {pcap}", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="xbits-appid-hook-"))
    try:
        sock = work / "hook.sock"
        out = work / "engine.out"
        err = work / "engine.err"
        engine = subprocess.Popen(
            [str(args.xbits), "--hook-socket", str(sock), "--rules", str(args.rules)],
            stdout=open(out, "w", encoding="utf-8"),
            stderr=open(err, "w", encoding="utf-8"),
            text=True,
        )
        try:
            wait_socket(sock)
            cmd = [
                "docker", "run", "--rm", "--network", "none",
                "-v", f"{work.resolve()}:/qa",
                "-v", f"{pcap.parent.resolve()}:/pcap:ro",
                "-v", f"{Path(args.redefs).resolve()}:/redefs:ro",
                "-e", "XBITS_HOOK_SOCKET=/qa/hook.sock",
                "-e", "ZEEK_PLUGIN_PATH=/opt/xbits/zeek-plugin",
                "-e", "ZEEK_PLUGIN_ACTIVATE=Xbits::Hook",
                "--entrypoint", "/usr/local/zeek/bin/zeek",
                args.image,
                "-Cr", f"/pcap/{pcap.name}",
                "/opt/xbits/app-id/scripts/__load__.zeek",
                "/redefs/xbits_alert_reg.zeek",
            ]
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            print("=== zeek stdout ===")
            print(p.stdout[-4000:])
            print("=== zeek stderr ===")
            print(p.stderr[-8000:])
            if p.returncode != 0:
                print("zeek/app-id hook run failed", file=sys.stderr)
                print(p.stdout[-2000:], file=sys.stderr)
                print(p.stderr[-4000:], file=sys.stderr)
                return 1
            time.sleep(0.3)
        finally:
            engine.terminate()
            try:
                engine.wait(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()

        lines = []
        for raw in out.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if raw:
                try:
                    lines.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass

        print("=== xbits central engine events from app-id hook ===")
        for ev in lines:
            print(json.dumps(ev, ensure_ascii=False))
        if err.read_text(encoding="utf-8", errors="replace").strip():
            print("=== engine stderr ===")
            print(err.read_text(encoding="utf-8", errors="replace"))

        # Exact assertion: app-id's XbitsAlert::alert event must be in the engine,
        # with the expected tool name, and must not be duplicated.
        appid_alerts = [
            ev for ev in lines
            if ev.get("event") == "XbitsAlert::alert"
            and (ev.get("signature") == "gobuster" or ev.get("desc", "").find("gobuster") >= 0)
        ]
        if len(appid_alerts) != 1:
            print(
                f"APP-ID HOOK: FAIL expected exactly one XbitsAlert::alert(gobuster), "
                f"got {len(appid_alerts)}",
                file=sys.stderr,
            )
            return 1
        ev = appid_alerts[0]
        if ev.get("rule_id") != "qa-zeek-all" or ev.get("event") != "XbitsAlert::alert":
            print(f"APP-ID HOOK: FAIL wrong engine record: {ev}", file=sys.stderr)
            return 1
        print("APP-ID HOOK: PASS (XbitsAlert::alert/gobuster reached xbits central engine exactly once)")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
