#!/usr/bin/env python3
"""Strict app-id image + scanner test assertions.

`app-id/tests/run_tests.py` is the authoritative app-id behavior test.  This
wrapper only exists so CI can run it *inside* the xbits-zeek image and capture
its exit code/artifacts consistently.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{(ROOT / 'app-id' / 'tests').resolve()}:/opt/xbits/app-id/tests:ro",
        "-e", "PATH=/usr/local/zeek/bin:/usr/local/bin:/usr/bin:/bin",
        "--entrypoint", "python3",
        "xbits-zeek",
        "/opt/xbits/app-id/tests/run_tests.py",
    ]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
    sys.stdout.write(p.stdout)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        print(f"APP-ID IMAGE TEST: FAIL rc={p.returncode}", file=sys.stderr)
        return 1
    print("APP-ID IMAGE TEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
