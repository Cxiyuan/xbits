#!/usr/bin/env python3
"""Strict app-identity test inside xbits-zeek.

This asserts the app-id `main.zeek` application mapping path:
  Host facebook.com  -> Facebook/social
  UA dropbox         -> Dropbox/cloud
  unknown host/UA    -> no app_identity record

The xbits hook plugin is intentionally disabled here; this isolates app-id
application identification from hook forwarding.  `qa_appid_hook.py` separately
proves scanner alerts are forwarded through the Zeek hook into xbits.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "xbits-zeek"
PCAP_DIR = ROOT / "app-id" / "tests" / "pcaps"
REDEFS = ROOT / "app-id" / "tests" / "redefs" / "app_identity_map.zeek"


def parse_tsv(path: Path):
    fields = None
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if fields:
            rows.append(dict(zip(fields, line.split("\t"))))
    return rows


def run_case(pcap: Path, expected: dict | None, mapping: str) -> tuple[bool, str]:
    work = Path(tempfile.mkdtemp(prefix="xbits-appid-identity-"))
    try:
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{PCAP_DIR.resolve()}:/pcap:ro",
            "-v", f"{REDEFS.parent.resolve()}:/redefs:ro",
            "-v", f"{work.resolve()}:/work",
            "-w", "/work",
            "-e", "PATH=/usr/local/zeek/bin:/usr/local/bin:/usr/bin:/bin",
            "-e", "ZEEK_PLUGIN_PATH=",
            "-e", "ZEEK_PLUGIN_ACTIVATE=",
            "--entrypoint", "/usr/local/zeek/bin/zeek",
            IMAGE,
            "-Cr", f"/pcap/{pcap.name}",
            "/opt/xbits/app-id/scripts/__load__.zeek",
            f"/redefs/{mapping}",
        ]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        if p.returncode != 0:
            return False, f"{pcap.name}: zeek rc={p.returncode}\n{p.stderr[-2000:]}"
        rows = parse_tsv(work / "app_identity.log")
        if expected is None:
            if rows:
                return False, f"{pcap.name}: expected no app_identity, got {rows}"
            return True, f"{pcap.name}: OK no app_identity"
        for row in rows:
            if (
                row.get("orig_h") == expected["src"]
                and row.get("app") == expected["app"]
                and row.get("category") == expected["category"]
            ):
                return True, f"{pcap.name}: OK {row}"
        return False, f"{pcap.name}: expected {expected}, got {rows}"
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    cases = [
        ("app_identity_http_host.pcap", {"src": "10.2.0.1", "app": "Facebook", "category": "social"}, "app_identity_host_map.zeek"),
        ("app_identity_http_ua.pcap", {"src": "10.2.0.2", "app": "Dropbox", "category": "cloud"}, "app_identity_ua_map.zeek"),
        ("app_identity_negative.pcap", None, "app_identity_host_map.zeek"),
    ]
    failed = []
    for name, expected, mapping in cases:
        pcap = PCAP_DIR / name
        if not pcap.is_file():
            failed.append(f"missing pcap: {pcap}")
            continue
        ok, msg = run_case(pcap, expected, mapping)
        print(("PASS " if ok else "FAIL ") + msg)
        if not ok:
            failed.append(msg)
    if failed:
        print("APP-ID IDENTITY: FAIL", file=sys.stderr)
        for f in failed:
            print(" -", f, file=sys.stderr)
        return 1
    print("APP-ID IDENTITY: PASS (host/UA mappings exact, negative empty)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
