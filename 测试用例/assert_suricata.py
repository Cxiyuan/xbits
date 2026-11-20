#!/usr/bin/env python3
"""Assert Suricata EVE alerts for the generated PCAP corpus.

每个用例必须是"有态度"的断言：
  * require 非空 → 这些 SID 必须出现；
  * forbid 非空 → 这些 SID 不得出现；
  * require 与 forbid **都为空 → 直接失败并点名用例**（既不断言命中也不断言不命中，
    等于恒真。qa/QA_REPORT.md V-18：18 个用例里 c2_periodic 曾是这样）。

R8-2：forbid-only 负例必须有"必中对照"。
  负例只断言"不命中"，如果整条规则根本没加载/没生效，负例照样通过 —— 假绿。
  因此本脚本维护一条对照不变式：

    一个用例的 forbid 里的每个 SID，必须在本 cases 文件**其它非 pending 用例的
    require** 中出现过（证明"这条规则确实会命中"，只是不该在这条流上命中）。
    否则 FAIL 并点名 case + 缺对照的 SID。

  无法建立对照的用例必须显式 `"pending": true` 并写 `note` 说明原因（跳过但有可见
  输出）。pending 用例的 require 不进入对照池（它本身不被断言，不能当证据）。

用例可带 `note` 说明设计意图，note 会被打印，便于 review 时看到。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Set, Tuple


def read_alerts(eve_path: str) -> Set[int]:
    sids: Set[int] = set()
    with open(eve_path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            sid = event.get("alert", {}).get("signature_id")
            if isinstance(sid, int):
                sids.add(sid)
    return sids


def analyze_cases(cases: Dict[str, dict]) -> Tuple[List[str], List[str], Set[int]]:
    """纯函数：返回 (failures, pending_lines, control_pool)。

    failures 覆盖：双空断言、pending 缺 note、forbid SID 无必中对照。
    """
    failures: List[str] = []
    pending_lines: List[str] = []
    control_pool: Set[int] = set()

    for name, spec in cases.items():
        if spec.get("pending"):
            note = str(spec.get("note") or "").strip()
            if not note:
                failures.append(f"{name}: pending=true 但缺少 note（必须说明为什么无法建立对照）")
            pending_lines.append(f"{name}: SKIP (pending) note={note or '<missing>'}")
            continue
        control_pool |= {int(x) for x in spec.get("require", [])}

    for name, spec in cases.items():
        if spec.get("pending"):
            continue
        require = {int(x) for x in spec.get("require", [])}
        forbid = {int(x) for x in spec.get("forbid", [])}
        if not require and not forbid:
            failures.append(
                "%s: 空断言（require 与 forbid 均为空）—— 既不断言命中也不断言不命中，恒真；"
                "请补 require/forbid，或标 pending+note 说明" % name
            )
            continue
        if require:
            continue  # 自带必中证据
        missing_control = sorted(forbid - control_pool)
        if missing_control:
            failures.append(
                "%s: forbid-only 负例缺少必中对照 —— 这些 SID 没有在本文件的任何非 pending 用例 "
                "require 中出现过，规则未加载时该负例也会通过: %s" % (name, missing_control)
            )
    return failures, pending_lines, control_pool


def self_test() -> int:
    """本地验证对照门禁语义（不需要 eve/docker）。"""
    checks: List[Tuple[str, bool]] = []

    ok_cases = {
        "pos": {"require": [9103001]},
        "neg": {"require": [], "forbid": [9103001]},
    }
    f, p, pool = analyze_cases(ok_cases)
    checks.append(("负例有必中对照 → 通过", not f and not p and 9103001 in pool))

    bad_cases = {
        "pos": {"require": [9103001]},
        "neg": {"require": [], "forbid": [9109999]},
    }
    f, _, _ = analyze_cases(bad_cases)
    checks.append(("负例 SID 无对照 → FAIL", any("缺少必中对照" in x and "9109999" in x for x in f)))

    only_neg = {"neg": {"require": [], "forbid": [9103001]}}
    f, _, _ = analyze_cases(only_neg)
    checks.append(("整文件只有负例（无对照）→ FAIL", any("缺少必中对照" in x for x in f)))

    empty = {"e": {"require": [], "forbid": []}}
    f, _, _ = analyze_cases(empty)
    checks.append(("双空 → FAIL", any("空断言" in x for x in f)))

    pending_ok = {
        "pos": {"require": [9103001]},
        "neg": {"require": [], "forbid": [9109999], "pending": True, "note": "规则未上线，暂无法建立对照"},
    }
    f, p, _ = analyze_cases(pending_ok)
    checks.append(("pending + note → 跳过且可见", not f and len(p) == 1 and "SKIP (pending)" in p[0]))

    pending_no_note = {"neg": {"require": [], "forbid": [9109999], "pending": True}}
    f, _, _ = analyze_cases(pending_no_note)
    checks.append(("pending 缺 note → FAIL", any("缺少 note" in x for x in f)))

    pending_not_control = {
        "neg1": {"require": [], "forbid": [9109999], "pending": True, "note": "x"},
        "neg2": {"require": [], "forbid": [9109999]},
    }
    f, _, _ = analyze_cases(pending_not_control)
    checks.append(
        ("pending 用例的 require 不得当对照池（本例 require 为空，仍 FAIL）",
         any("缺少必中对照" in x for x in f))
    )

    bad = 0
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
        bad += 0 if ok else 1
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve-root", default=None)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--cases-only", action="store_true", help="只跑用例自洽性检查（双空/对照），不读 eve")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    with open(args.cases, "r", encoding="utf-8-sig") as fp:
        cases: Dict[str, dict] = json.load(fp)

    case_failures, pending_lines, control_pool = analyze_cases(cases)
    for line in pending_lines:
        print(line)
    if case_failures:
        print("\nCASE CONSISTENCY: FAIL", file=sys.stderr)
        for item in case_failures:
            print(" -", item, file=sys.stderr)
        return 1
    if args.cases_only:
        print(
            "\nCASE CONSISTENCY: PASS (%d cases, %d pending, %d control SIDs)"
            % (len(cases), len(pending_lines), len(control_pool))
        )
        return 0

    if not args.eve_root:
        print("FAIL: --eve-root is required unless --cases-only/--self-test", file=sys.stderr)
        return 2

    failures = []
    asserted = 0
    for name, spec in sorted(cases.items()):
        note = str(spec.get("note") or "").strip()
        if spec.get("pending"):
            print("%-28s %-4s reason=pending note=%s" % (name, "SKIP", note))
            continue

        eve_path = os.path.join(args.eve_root, name, "eve.json")
        if not os.path.isfile(eve_path):
            failures.append("%s: missing %s" % (name, eve_path))
            print("%-28s %-4s reason=%s" % (name, "FAIL", "missing eve.json"))
            continue

        actual = read_alerts(eve_path)
        asserted += 1
        require = {int(sid) for sid in spec.get("require", [])}
        forbid = {int(sid) for sid in spec.get("forbid", [])}
        missing = sorted(require - actual)
        unexpected = sorted(forbid & actual)
        status = "OK"
        if missing or unexpected:
            status = "FAIL"
            failures.append(name)
        print(
            "%-28s %-4s alerts=%s missing=%s forbidden=%s%s"
            % (
                name,
                status,
                sorted(actual),
                missing,
                unexpected,
                (" note=" + note) if note else "",
            )
        )

    if failures:
        print("\nFAILED cases: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print(
        "\nall %d Suricata cases passed (%d asserted, %d pending skipped)"
        % (len(cases), asserted, len(pending_lines))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
