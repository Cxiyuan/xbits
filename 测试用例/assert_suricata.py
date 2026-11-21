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

R9-4：静态对照之上补**运行时对照**（读同一次 `--eve-root`）。
  对每个 forbid-only 负例的每个 forbid SID，在本次实跑的 EVE 目录里找到"require 了
  该 SID 的对照用例"，断言对照用例**确实命中**该 SID；对照用例全都没命中
  → FAIL 并点名"对照未命中，可能规则未加载"（静态门禁只能证明 cases 文本里有人
  require 它，不能证明规则真的加载并命中）。

  若某对照正例属于别的场景目录、不在同次运行（例如 DNS 用例的 forbid SID 只在
  web 场景里被 require），用例可写
  `"control_in_other_scenario": {"<sid>": "<理由>"}` 显式登记——静态门禁放行、
  运行时跳过，并打印 `EXCUSED` 行；理由为空即 FAIL。

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
        excused = spec.get("control_in_other_scenario") or {}
        if not isinstance(excused, dict):
            failures.append(
                "%s: control_in_other_scenario 必须是 {sid: reason} 映射" % name
            )
            excused = {}
        excused_sids = set()
        for raw_sid, reason in excused.items():
            try:
                sid = int(raw_sid)
            except (TypeError, ValueError):
                failures.append("%s: control_in_other_scenario 的 key 不是 SID: %r" % (name, raw_sid))
                continue
            if not str(reason or "").strip():
                failures.append(
                    "%s: control_in_other_scenario[%s] 必须写明理由（跨场景对照的依据）" % (name, sid)
                )
                continue
            excused_sids.add(sid)
            pending_lines.append(
                "%s: EXCUSED sid=%s（对照正例在其它场景目录，不在本次运行）reason=%s"
                % (name, sid, reason)
            )
        missing_control = sorted(forbid - control_pool - excused_sids)
        if missing_control:
            failures.append(
                "%s: forbid-only 负例缺少必中对照 —— 这些 SID 没有在本文件的任何非 pending 用例 "
                "require 中出现过，也未用 control_in_other_scenario 登记理由，规则未加载时该负例也会通过: %s"
                % (name, missing_control)
            )
    return failures, pending_lines, control_pool


def control_map(cases: Dict[str, dict]) -> Dict[int, List[str]]:
    """SID → 在本文件中 require 它的非 pending 用例名列表（运行时对照候选）。"""
    controls: Dict[int, List[str]] = {}
    for name, spec in cases.items():
        if spec.get("pending"):
            continue
        for sid in spec.get("require", []):
            controls.setdefault(int(sid), []).append(name)
    return controls


def runtime_control_failures(
    cases: Dict[str, dict], actual_by_case: Dict[str, Set[int]]
) -> Tuple[List[str], int]:
    """R9-4：forbid-only 负例的 forbid SID，其对照正例必须在**本次实跑**里命中。

    返回 (failures, checked)。对照用例缺失（没有任何 require 者）交给静态门禁，
    这里只对"有对照候选"的 SID 断言运行时证据。
    """
    failures: List[str] = []
    controls = control_map(cases)
    checked = 0
    for name, spec in cases.items():
        if spec.get("pending"):
            continue
        require = {int(x) for x in spec.get("require", [])}
        forbid = {int(x) for x in spec.get("forbid", [])}
        if require or not forbid:
            continue  # 只对 forbid-only 负例做运行时对照
        excused = set()
        for raw_sid in (spec.get("control_in_other_scenario") or {}):
            try:
                excused.add(int(raw_sid))
            except (TypeError, ValueError):
                continue
        for sid in sorted(forbid - excused):
            ctrl_cases = controls.get(sid) or []
            if not ctrl_cases:
                continue  # 静态门禁负责报"缺少必中对照"
            checked += 1
            observed = {c: actual_by_case.get(c) for c in ctrl_cases}
            if all(v is None for v in observed.values()):
                failures.append(
                    "%s: sid=%s 的对照用例 %s 都没有 EVE 数据，无法证明规则已加载"
                    % (name, sid, sorted(ctrl_cases))
                )
                continue
            if not any(v is not None and sid in v for v in observed.values()):
                failures.append(
                    "%s: sid=%s 的对照用例 %s 本次实跑均未命中——对照未命中，可能规则未加载"
                    % (name, sid, sorted(ctrl_cases))
                )
    return failures, checked


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

    # R9-4：跨场景对照可显式登记理由（静态放行 + 可见 EXCUSED），缺理由即 FAIL。
    excused_ok = {
        "neg": {
            "require": [],
            "forbid": [9109999],
            "control_in_other_scenario": {"9109999": "对照正例在 web 场景目录，本次运行不含"},
        }
    }
    f, lines, _ = analyze_cases(excused_ok)
    checks.append(
        (
            "R9-4：control_in_other_scenario 有理由 → 静态放行且打印 EXCUSED",
            not f and any("EXCUSED" in x and "9109999" in x for x in lines),
        )
    )
    excused_no_reason = {
        "neg": {"require": [], "forbid": [9109999], "control_in_other_scenario": {"9109999": "  "}}
    }
    f, _, _ = analyze_cases(excused_no_reason)
    checks.append(
        ("R9-4：control_in_other_scenario 缺理由 → FAIL", any("必须写明理由" in x for x in f))
    )

    # R9-4：运行时对照——对照用例实跑命中才通过；全不命中必须 FAIL 点名"可能规则未加载"。
    rt_cases = {
        "pos": {"require": [9103001]},
        "neg": {"require": [], "forbid": [9103001]},
    }
    rt_ok, rt_checked = runtime_control_failures(rt_cases, {"pos": {9103001}})
    checks.append(
        ("R9-4：对照用例本次命中 → 运行时对照通过", not rt_ok and rt_checked == 1, str(rt_ok))
    )
    rt_bad, _ = runtime_control_failures(rt_cases, {"pos": set()})
    checks.append(
        (
            "R9-4：对照用例本次未命中 → FAIL 点名对照未命中/可能规则未加载",
            any("对照未命中" in x and "可能规则未加载" in x for x in rt_bad),
            str(rt_bad),
        )
    )
    rt_missing, _ = runtime_control_failures(rt_cases, {})
    checks.append(
        ("R9-4：对照用例没有 EVE 数据 → FAIL（不能默认通过）", any("没有 EVE 数据" in x for x in rt_missing))
    )
    rt_excused, rt_checked2 = runtime_control_failures(
        {"neg": {"require": [], "forbid": [9109999], "control_in_other_scenario": {"9109999": "web 场景"}}},
        {},
    )
    checks.append(
        ("R9-4：跨场景已登记的 SID 不做运行时对照", not rt_excused and rt_checked2 == 0, str(rt_excused))
    )

    bad = 0
    for item in checks:
        name, ok = item[0], item[1]
        detail = item[2] if len(item) > 2 else ""
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  [{detail[:160]}]"))
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
    actual_by_case: Dict[str, Set[int]] = {}
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
        actual_by_case[name] = actual
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

    # R9-4：forbid-only 负例的对照正例必须在本次实跑里命中，否则"规则根本没加载"也会绿。
    rt_failures, rt_checked = runtime_control_failures(cases, actual_by_case)
    for item in rt_failures:
        print("%-28s %-4s reason=control-not-hit %s" % (item.split(":", 1)[0], "FAIL", item), file=sys.stderr)
        failures.append(item)
    print(
        "\nRUNTIME CONTROL: %d 个 forbid SID 的对照正例已实跑核验（%d 处未命中）"
        % (rt_checked, len(rt_failures))
    )

    if failures:
        print("\nFAILED cases: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    print(
        "\nall %d Suricata cases passed (%d asserted, %d pending/excused lines, %d runtime controls)"
        % (len(cases), asserted, len(pending_lines), rt_checked)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
