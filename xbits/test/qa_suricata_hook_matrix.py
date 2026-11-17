#!/usr/bin/env python3
"""End-to-end Suricata thin-hook completeness / rule matrix.

For every generated PCAP/case this does two independent runs through the
official-image-based `xbits-suricata` container:

  1. normal Suricata EVE file output (ground truth)
  2. the xbits Suricata EVE-filetype hook -> xbits central engine

Assertions are intentionally strict:
  * engine SID multiset == EVE SID multiset (no lost / duplicated alerts)
  * engine SID set == case.require (no unexpected extra rule)
  * engine SID set is disjoint from case.forbid

The rule coverage gate (`qa_rule_coverage.py`) separately proves every SID in
every .rules file is named by at least one case.  Together these two checks
remove the usual blind spots: a rule that never fires, a rule that fires but
is not forwarded, and an alert that is forwarded twice.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CATEGORIES = [
    {
        "name": "dns",
        "cases": ROOT / "测试用例" / "cases.json",
        "pcap_dir": ROOT / "测试用例" / "pcap",
    },
    {
        "name": "recon",
        "cases": ROOT / "测试用例" / "recon_cases.json",
        "pcap_dir": ROOT / "测试用例" / "recon_pcap",
    },
    {
        "name": "web",
        "cases": ROOT / "测试用例" / "web_cases.json",
        "pcap_dir": ROOT / "测试用例" / "web_pcap",
    },
    {
        "name": "backdoor",
        "cases": ROOT / "测试用例" / "backdoor_cases.json",
        "pcap_dir": ROOT / "测试用例" / "backdoor_pcap",
    },
]


def wait_for_socket(path: Path, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"xbits hook socket did not appear: {path}")


def run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def read_engine_sids(path: Path) -> Counter:
    sids: Counter = Counter()
    if not path.exists():
        return sids
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if "signature_id" in ev:
            sids[int(ev["signature_id"])] += 1
    return sids


def read_eve_sids(path: Path) -> Counter:
    sids: Counter = Counter()
    if not path.exists():
        return sids
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        sid = ev.get("alert", {}).get("signature_id")
        if isinstance(sid, int):
            sids[sid] += 1
    return sids


def run_case(
    image: str,
    xbits: Path,
    rules: Path,
    case: str,
    pcap: Path,
    work: Path,
) -> tuple[bool, str]:
    hook_dir = work / "hook"
    eve_dir = work / "eve"
    hook_dir.mkdir(parents=True, exist_ok=True)
    eve_dir.mkdir(parents=True, exist_ok=True)
    sock = work / "hook.sock"
    engine_out = work / "engine.out"
    engine_err = work / "engine.err"

    engine = subprocess.Popen(
        [str(xbits), "--hook-socket", str(sock), "--rules", str(rules)],
        stdout=open(engine_out, "w", encoding="utf-8"),
        stderr=open(engine_err, "w", encoding="utf-8"),
        text=True,
    )
    try:
        wait_for_socket(sock)
        common = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{work.resolve()}:/qa",
            "-v",
            f"{pcap.parent.resolve()}:/pcap:ro",
        ]

        # 1) Ground truth: normal EVE JSON file.
        eve = run(
            common
            + [
                "--entrypoint",
                "suricata",
                image,
                "-r",
                f"/pcap/{pcap.name}",
                "-c",
                "/opt/xbits/suricata-qa-eve.yaml",
                "-l",
                "/qa/eve",
            ]
        )
        if eve.returncode != 0:
            return False, f"{case}: EVE run failed rc={eve.returncode}\n{eve.stderr[-2000:]}"

        # 2) Hook path: EVE filetype -> xbits central engine.
        hook = run(
            common
            + [
                "-e",
                "XBITS_HOOK_SOCKET=/qa/hook.sock",
                "--entrypoint",
                "suricata",
                image,
                "-r",
                f"/pcap/{pcap.name}",
                "-c",
                "/opt/xbits/suricata-qa.yaml",
                "-l",
                "/qa/hook",
            ]
        )
        if hook.returncode != 0:
            return False, f"{case}: hook run failed rc={hook.returncode}\n{hook.stderr[-2000:]}"

        # Give the listener a moment to drain the final records.
        time.sleep(0.1)
    finally:
        engine.terminate()
        try:
            engine.wait(timeout=5)
        except subprocess.TimeoutExpired:
            engine.kill()

    eve_sids = read_eve_sids(eve_dir / "eve.json")
    engine_sids = read_engine_sids(engine_out)

    return True, json.dumps(
        {
            "eve": dict(eve_sids),
            "engine": dict(engine_sids),
            "engine_err": engine_err.read_text(encoding="utf-8", errors="replace")[-2000:],
        },
        ensure_ascii=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="xbits-suricata")
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--rules", default=str(ROOT / "xbits" / "rules" / "qa-all.json"))
    parser.add_argument("--categories", default="dns,recon,web,backdoor")
    args = parser.parse_args()

    image = args.image
    xbits = Path(args.xbits)
    rules = Path(args.rules)
    wanted = {x.strip() for x in args.categories.split(",") if x.strip()}

    failures: list[str] = []
    total_cases = 0
    for cat in CATEGORIES:
        if cat["name"] not in wanted:
            continue
        cases = json.loads(Path(cat["cases"]).read_text(encoding="utf-8-sig"))
        pcap_dir = Path(cat["pcap_dir"])
        for case, spec in sorted(cases.items()):
            total_cases += 1
            pcap = pcap_dir / f"{case}.pcap"
            if not pcap.is_file():
                failures.append(f"{cat['name']}/{case}: missing pcap {pcap}")
                continue
            work = Path(tempfile.mkdtemp(prefix=f"xbits-qa-{cat['name']}-"))
            try:
                ok, detail = run_case(image, xbits, rules, case, pcap, work)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            if not ok:
                failures.append(detail)
                print(f"{cat['name']}/{case}: FAIL {detail}", file=sys.stderr)
                continue

            observed = json.loads(detail)
            eve = Counter({int(k): v for k, v in observed["eve"].items()})
            engine = Counter({int(k): v for k, v in observed["engine"].items()})
            require = {int(x) for x in spec.get("require", [])}
            forbid = {int(x) for x in spec.get("forbid", [])}

            problems = []
            if eve != engine:
                problems.append(f"hook lost/duplicated alerts: EVE={dict(eve)} engine={dict(engine)}")
            if not require <= set(engine):
                problems.append(f"missing required sids: missing={sorted(require - set(engine))}")
            if forbid & set(engine):
                problems.append(f"forbidden sids fired: {sorted(forbid & set(engine))}")
            bad_err = observed["engine_err"]
            if "bad hook event" in bad_err or "hook accept error" in bad_err or "hook read error" in bad_err:
                problems.append(f"engine stderr: {bad_err[-500:]}")

            if problems:
                failures.append(f"{cat['name']}/{case}: " + "; ".join(problems))
                print(f"{cat['name']}/{case}: FAIL " + "; ".join(problems), file=sys.stderr)
            else:
                extra = sorted(set(engine) - require)
                extra_text = f" extra={extra}" if extra else ""
                print(
                    f"{cat['name']}/{case}: OK eve={sorted(eve)} engine={sorted(engine)}{extra_text}"
                )

    if failures:
        print(f"\nSURICATA HOOK MATRIX: FAIL ({len(failures)} failures, {total_cases} cases)", file=sys.stderr)
        for f in failures:
            print(" -", f, file=sys.stderr)
        return 1
    print(f"\nSURICATA HOOK MATRIX: PASS ({total_cases} cases, EVE == engine exactly)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
