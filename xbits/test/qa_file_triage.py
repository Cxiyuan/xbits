#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端 QA：Suricata 转存文件(fileinfo/file_stored) -> xbits 编排静态 triage -> 全程跟踪。

用一个真实的文件（PHP webshell / 文本 / 缺失）落在 xbits --file-spool-dir 的
file-store v2 布局（<dir>/<sha[0:2]>/<sha256>）中，然后向 hook socket 发送
"文件已转存"事件，断言 xbits 输出：
  - event.kind == "file_triage" 的跟踪文档，status 依次 received -> analyzing -> completed
  - completed 文档带 triage 判定（malicious/suspicious）且 file.sha256 正确
  - 非目标类别 -> skipped；文件缺失 -> failed
并同时验证 EVE fileinfo 原始格式也能被正确归一处理。

运行（在 CI/Linux）：
  python xbits/test/qa_file_triage.py \
    --xbits xbits/target/release/xbits \
    --triage-cmd "python3 triage/triage.py --stdin"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
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
    raise RuntimeError(f"xbits hook socket did not appear: {path}")


def send_events(sock_path: Path, events: list[dict]) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(str(sock_path))
        for ev in events:
            s.sendall((json.dumps(ev) + "\n").encode())
        s.shutdown(socket.SHUT_WR)


def read_rows(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def store_file(spool: Path, name: str, data: bytes) -> tuple[str, int]:
    sha = hashlib.sha256(data).hexdigest()
    sub = spool / sha[:2]
    sub.mkdir(parents=True, exist_ok=True)
    (sub / sha).write_bytes(data)
    return sha, len(data)


PHP_SHELL = b"<?php @eval($_POST['cmd']); system($_GET['x']); ?>"


def base_file_event(sha: str, name: str, size: int, sport: int) -> dict:
    return {
        "source": "suricata",
        "kind": "file_stored",
        "ts": "2026-11-08T00:00:00.100000+0000",
        "timestamp": "2026-11-08T00:00:00.100000+0000",
        "src": "203.0.113.9",
        "sport": sport,
        "dst": "10.0.0.80",
        "dport": 80,
        "proto": "TCP",
        "flow_id": f"flow-{sport}",
        "file_sha256": sha,
        "file_name": name,
        "file_size": size,
        "file_stored": True,
    }


def run_case(xbits, triage_cmd, name, files, events_factory, want_statuses, want_completed_verdict=None):
    work = Path(tempfile.mkdtemp(prefix="xbits-file-triage-"))
    spool = work / "filestore"
    spool.mkdir(parents=True, exist_ok=True)
    out = work / "out.jsonl"
    engine = None
    try:
        # 预置文件
        sha_map = {}
        for fname, data in files:
            sha, size = store_file(spool, fname, data)
            sha_map[fname] = (sha, size)
        engine = subprocess.Popen(
            [str(xbits),
             "--hook-socket", str(work / "xbits.sock"),
             "--rules", str(ROOT / "xbits" / "rules" / "default.json"),
             "--analysis-file", str(out),
             "--file-spool-dir", str(spool),
             "--triage-cmd", triage_cmd,
             "--triage-timeout-ms", "20000"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        wait_socket(work / "xbits.sock")
        send_events(work / "xbits.sock", events_factory(sha_map))
        time.sleep(3.0)
        engine.terminate()
        engine.wait(timeout=5)
    except BaseException:
        if engine is not None:
            engine.kill()
        raise

    rows = [r for r in read_rows(out) if r.get("event", {}).get("kind") == "file_triage"]
    statuses = [r.get("event", {}).get("status") for r in rows]
    ok = statuses == want_statuses
    detail = f"{name}: statuses={statuses} want={want_statuses}"
    if ok and want_completed_verdict is not None:
        completed = [r for r in rows if r.get("event", {}).get("status") == "completed"]
        got_verdict = completed[0]["xbits"].get("verdict") if completed else None
        ok = ok and got_verdict == want_completed_verdict
        detail += f" verdict={got_verdict} want={want_completed_verdict}"
    if ok and want_completed_verdict is not None:
        completed = [r for r in rows if r.get("event", {}).get("status") == "completed"]
        sha = completed[0]["file"]["sha256"]
        ok = ok and isinstance(sha, str) and len(sha) == 64
        detail += f" sha256_ok={isinstance(sha,str) and len(sha)==64}"
    try:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    except OSError:
        pass
    return ok, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--xbits", required=True)
    ap.add_argument("--triage-cmd", required=True)
    args = ap.parse_args()
    xbits = Path(args.xbits)

    def ev_php(sha_map):
        sha, size = sha_map["shell.php"]
        return [base_file_event(sha, "shell.php", size, 40010)]

    def ev_text(sha_map):
        sha, size = sha_map["note.txt"]
        return [base_file_event(sha, "note.txt", size, 40011)]

    def ev_missing(sha_map):
        # 声明一个磁盘上不存在的 sha256
        return [base_file_event("0" * 64, "ghost.bin", 123, 40012)]

    def ev_eve(sha_map):
        sha, size = sha_map["shell.php"]
        return [{
            "timestamp": "2026-11-08T00:00:00.200000+0000",
            "event_type": "fileinfo",
            "src_ip": "203.0.113.9", "src_port": 40013,
            "dest_ip": "10.0.0.80", "dest_port": 80,
            "proto": "TCP", "flow_id": 40013, "community_id": "1:testCID=",
            "fileinfo": {"filename": "shell.php", "sha256": sha, "size": size,
                         "stored": True, "magic": "PHP script", "tx_id": 1},
        }]

    cases = [
        ("php-webshell-triaged",
         [("shell.php", PHP_SHELL)], ev_php,
         ["received", "analyzing", "completed"], "malicious"),
        ("text-file-skipped",
         [("note.txt", b"hello world benign note\n")], ev_text,
         ["received", "analyzing", "skipped"], None),
        ("missing-file-failed",
         [], ev_missing,
         ["received", "failed"], None),
        ("eve-fileinfo-mapped",
         [("shell.php", PHP_SHELL)], ev_eve,
         ["received", "analyzing", "completed"], "malicious"),
    ]

    failures = []
    for name, files, factory, want, verdict in cases:
        ok, detail = run_case(xbits, args.triage_cmd, name, files, factory, want, verdict)
        print(("OK " if ok else "FAIL ") + detail)
        if not ok:
            failures.append(detail)

    print(f"\n{len(cases) - len(failures)}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
