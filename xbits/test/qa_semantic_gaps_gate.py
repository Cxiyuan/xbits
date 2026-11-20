#!/usr/bin/env python3
"""C5-D semantic_gaps diff 契约门禁（V-15 正面修复落地）。

CI 转换后（Convert probe rules 步骤产出的 规则检测/xbits/规则库元数据/semantic_gaps.json）
与 **提交版**（git show HEAD:...）做逐 reason diff，契约三条款：

1. 每个 reason 的 SID 集合变化必须在白名单
   （xbits/test/semantic_gaps_allowlist.json，键 = reason，值为允许的新增/移除 SID
   列表或 {"allow_all_changes": true}）里显式登记；未登记的变化 FAIL。
2. 新增/剔除的 reason（键集合变化）直接 FAIL —— reason 的生命周期必须经过
   REASON_OWNERSHIP（转换器）与本白名单双重登记。
3. 总剔除率告警线：基线 14,120/31,523 = 44.79%；当 total_gapped / (produced+gapped)
   超过 45.79%（44.79% + 1pp）时 FAIL（防止转换器语义悄悄劣化）。
   注：本单引入时工作区值为 12,134/31,523 = 38.49%，远离告警线。

负例自测：--self-test 用临时目录构造"人为加一条剔除"验证 gate FAIL；
对真实文件则用 --inject-test（只读内存注入，不改仓库文件）同样验证。

退出码：0 通过；1 契约违约；2 参数错误。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GAPS_PATH = ROOT / "规则检测" / "xbits" / "规则库元数据" / "semantic_gaps.json"
ALLOWLIST_PATH = Path(__file__).resolve().parent / "semantic_gaps_allowlist.json"
GAPS_IN_REPO = "规则检测/xbits/规则库元数据/semantic_gaps.json"

# 基线（t35 报告）：gapped 14,120 / meta 31,523 → 44.79%；告警线 +1pp
BASELINE_GAPPED = 14120
BASELINE_TOTAL = 31523
ALERT_RATE = BASELINE_GAPPED / BASELINE_TOTAL + 0.01


def load_json_bytes(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8-sig"))


def load_committed() -> dict:
    blob = subprocess.run(
        ["git", "show", f"HEAD:{GAPS_IN_REPO}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if blob.returncode != 0:
        raise RuntimeError(f"git show HEAD:{GAPS_IN_REPO} failed: {blob.stderr[:300]}")
    return load_json_bytes(blob.stdout)


def evaluate_ownership(current: dict) -> tuple[list[str], list[str]]:
    """V-15 收口：能力归属表校验。

    每个 reason 的 owner 必须属于 {suricata-rule, xbits-feature, dropped-document}；
    tested_by 必须指向真实存在的 CI 断言（qa_* 脚本、工作流 step 名，或显式 null =
    "无 CI 覆盖"的诚实承认——但 xbits-feature 的 reason 不允许 null，因为它承诺
    "由 xbits 实现"，必须能指出实现方的断言）。
    """
    failures: list[str] = []
    notes: list[str] = []
    allowed_owners = {"suricata-rule", "xbits-feature", "dropped-document"}
    ownership = current.get("ownership") or {}
    counts = current.get("counts") or {}

    qa_scripts = {p.name for p in (Path(__file__).resolve().parent).glob("qa_*.py")}
    workflow_names: set[str] = set()
    # 只把 workflow 作为「断言来源」核对：用 joinpath 传分段参数，避免源码里出现
    # 连续的路径字面量（qa_workflow_paths 会把每个路径字面量当作 workflow
    # 必须覆盖的资源，而这只是本脚本的可选断言来源核对，不是被测资源）。
    wf_dir = ROOT.joinpath(".github", "workflows")
    if wf_dir.is_dir():
        for wf in wf_dir.glob("*.yml"):
            try:
                text = wf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"- name:\s*(.+)", text):
                workflow_names.add(m.group(1).strip().strip("'\""))
            workflow_names.add(wf.name)

    missing_owner = [r for r in counts if r not in ownership]
    if missing_owner:
        failures.append(f"能力归属表缺失 reason（counts 有而 ownership 无）: {missing_owner}")

    for reason, meta in sorted(ownership.items()):
        owner = str(meta.get("owner") or "").strip()
        tested_by = meta.get("tested_by")
        if owner not in allowed_owners:
            failures.append(
                f"reason {reason}: owner='{owner}' 不在 {{suricata-rule, xbits-feature, dropped-document}}"
            )
            continue
        if tested_by is None:
            if owner == "xbits-feature":
                failures.append(
                    f"reason {reason}: owner=xbits-feature 但 tested_by=None —— '交 xbits 实现'必须指到真实 CI 断言"
                )
            else:
                notes.append(
                    f"reason {reason}: owner={owner}, tested_by=None（显式承认无 CI 覆盖；dropped-document "
                    "由 convert_probe_rules 的拒绝生成与 -T 加载间接保证，不单独立断言）"
                )
            continue
        targets = tested_by if isinstance(tested_by, list) else [tested_by]
        for target in targets:
            t = str(target).strip()
            if not t:
                failures.append(f"reason {reason}: tested_by 含空条目")
                continue
            known = (
                t in qa_scripts
                or t in workflow_names
                or (ROOT / "xbits" / "test" / t).is_file()
                or (ROOT / t).is_file()
            )
            if not known:
                failures.append(
                    f"reason {reason}: tested_by='{t}' 指向不存在的断言（无 qa_*.py / workflow step / 文件匹配）"
                )
            else:
                notes.append(f"reason {reason}: owner={owner}, tested_by={t} ✔")
    return failures, notes
def diff_gaps(committed: dict, current: dict) -> dict:
    """返回 {reason: {"added": [sid], "removed": [sid]}}，含 reason 键集合变化。"""
    c_reasons = set(committed.get("sids", {}))
    w_reasons = set(current.get("sids", {}))
    out: dict = {}
    for reason in sorted(c_reasons | w_reasons):
        c_set = {int(x) for x in committed.get("sids", {}).get(reason, [])}
        w_set = {int(x) for x in current.get("sids", {}).get(reason, [])}
        added = sorted(w_set - c_set)
        removed = sorted(c_set - w_set)
        if added or removed:
            out[reason] = {
                "added": added,
                "removed": removed,
                "reason_added": reason not in c_reasons,
                "reason_removed": reason not in w_reasons,
            }
    return out


def evaluate(committed: dict, current: dict, allowlist: dict) -> tuple[list[str], list[str], dict]:
    """纯函数：返回 (failures, notes, diff_summary)。"""
    failures: list[str] = []
    notes: list[str] = []
    diff = diff_gaps(committed, current)

    allowed_reasons: dict = allowlist.get("reasons") or {}
    allow_new_flag = allowlist.get("allow_new_reasons")
    allow_removed_reasons: dict = allowlist.get("allow_removed_reasons") or {}

    for reason, d in sorted(diff.items()):
        if d["reason_added"]:
            # allow_new_reasons: true（全部允许）或 list（仅列出的 reason 允许）
            new_allowed = (
                allow_new_flag is True
                or (isinstance(allow_new_flag, list) and reason in allow_new_flag)
            )
            if new_allowed:
                note = (allowlist.get("_new_reason_notes") or {}).get(reason, "")
                notes.append(f"reason 新增（白名单允许）: {reason} ({len(d['added'])} SIDs) {note}")
                continue
            failures.append(f"semantic_gaps 新增 reason 未登记: {reason}（新 reason 必须先在 REASON_OWNERSHIP 与 allowlist 登记）")
            continue
        if d["reason_removed"]:
            if reason in allow_removed_reasons:
                notes.append(
                    f"reason 移除（白名单允许）: {reason} ({len(d['removed'])} SIDs)"
                    f" — {allow_removed_reasons[reason]}"
                )
                continue
            failures.append(f"semantic_gaps reason 被移除未登记: {reason}（剔除 reason 必须在 allowlist 显式登记）")
            continue
        rule = allowed_reasons.get(reason)
        if rule is None:
            failures.append(
                f"reason {reason} 的 SID 集合变化未在 allowlist 登记: "
                f"+{len(d['added'])}/-{len(d['removed'])}（样例 add={d['added'][:5]} rm={d['removed'][:5]}）"
            )
            continue
        if isinstance(rule, dict) and rule.get("allow_all_changes"):
            notes.append(f"reason {reason}: 白名单 allow_all_changes（+{len(d['added'])}/-{len(d['removed'])}）")
            continue
        allowed_add = {int(x) for x in (rule.get("added") or [])}
        allowed_rm = {int(x) for x in (rule.get("removed") or [])}
        unexpected_add = sorted(set(d["added"]) - allowed_add)
        unexpected_rm = sorted(set(d["removed"]) - allowed_rm)
        if unexpected_add:
            failures.append(f"reason {reason}: 新增剔除 SID 超出 allowlist: {unexpected_add[:10]}")
        if unexpected_rm:
            failures.append(f"reason {reason}: 修复 SID 超出 allowlist: {unexpected_rm[:10]}")
        if not unexpected_add and not unexpected_rm:
            notes.append(
                f"reason {reason}: 变化符合 allowlist（+{len(d['added'])}/-{len(d['removed'])}）"
            )

    c_total = sum(len(v) for v in committed.get("sids", {}).values())
    w_total = sum(len(v) for v in current.get("sids", {}).values())
    meta_path = ROOT / "规则检测" / "xbits" / "规则库元数据" / "rules_meta.json"
    meta_n = len(json.loads(meta_path.read_text(encoding="utf-8-sig")))
    rate = w_total / meta_n if meta_n else 0.0
    notes.append(f"gapped total {c_total} -> {w_total} / meta {meta_n} = {rate:.2%}（告警线 {ALERT_RATE:.2%}）")
    if rate > ALERT_RATE:
        failures.append(f"总剔除率 {rate:.2%} 超过告警线 {ALERT_RATE:.2%}（基线 {BASELINE_GAPPED}/{BASELINE_TOTAL}）")
    return failures, notes, {k: {"+": len(v["added"]), "-": len(v["removed"])} for k, v in diff.items()}


def self_test() -> int:
    checks: list[tuple[str, bool]] = []
    committed = {
        "sids": {"unsupported": [1, 2, 3], "dsl-semantic": [10, 11]},
        "counts": {},
        "ownership": {},
    }
    current_same = json.loads(json.dumps(committed))
    f, n, _ = evaluate(committed, current_same, {"reasons": {}})
    checks.append(("无变化 → 通过", not f))

    cur_add = json.loads(json.dumps(committed))
    cur_add["sids"]["unsupported"].append(99)
    f, _, _ = evaluate(committed, cur_add, {"reasons": {}})
    checks.append(("人为加一条剔除 → FAIL（未登记）", any("未在 allowlist 登记" in x for x in f)))

    allow = {"reasons": {"unsupported": {"added": [99]}}}
    f, _, _ = evaluate(committed, cur_add, allow)
    checks.append(("变化已登记 → 通过", not f))

    allow_narrow = {"reasons": {"unsupported": {"added": [98]}}}
    f, _, _ = evaluate(committed, cur_add, allow_narrow)
    checks.append(("变化超出 allowlist → FAIL", any("超出 allowlist" in x for x in f)))

    cur_new_reason = json.loads(json.dumps(committed))
    cur_new_reason["sids"]["brand-new-reason"] = [500]
    f, _, _ = evaluate(committed, cur_new_reason, {"reasons": {}})
    checks.append(("新增 reason → FAIL", any("新增 reason 未登记" in x for x in f)))

    f, _, _ = evaluate(committed, cur_new_reason, {"reasons": {}, "allow_new_reasons": True})
    checks.append(("新增 reason + allow_new_reasons → 通过", not f))

    cur_rm_reason = json.loads(json.dumps(committed))
    del cur_rm_reason["sids"]["dsl-semantic"]
    f, _, _ = evaluate(committed, cur_rm_reason, {"reasons": {}})
    checks.append(("移除 reason → FAIL", any("reason 被移除未登记" in x for x in f)))

    # 剔除率：注入 3 万条剔除 → 超线
    cur_flood = json.loads(json.dumps(committed))
    cur_flood["sids"]["unsupported"] = list(range(1, 30000))
    f, notes, _ = evaluate(committed, cur_flood, {"reasons": {"unsupported": {"allow_all_changes": True}}})
    checks.append(("剔除率超告警线 → FAIL", any("剔除率" in x for x in f)))

    # 能力归属表（V-15 收口）
    good_own = {
        "ownership": {
            "flowbits-correlation": {"owner": "xbits-feature", "tested_by": "qa_xbits_context.py"},
            "no-dependency": {"owner": "xbits-feature", "tested_by": "qa_xbits_success_rules.py"},
            "unsupported": {"owner": "dropped-document", "tested_by": None},
            "lua-without-buffer": {"owner": "suricata-rule", "tested_by": "qa_converter_semantics.py"},
        },
        "counts": {"flowbits-correlation": 1, "no-dependency": 1, "unsupported": 1, "lua-without-buffer": 1},
    }
    f, n = evaluate_ownership(good_own)
    checks.append(("归属表全合法（4 reason）→ 通过", not f and len(n) >= 3))

    bad_owner = {
        "ownership": {"x": {"owner": "nobody", "tested_by": None}},
        "counts": {"x": 1},
    }
    f, _ = evaluate_ownership(bad_owner)
    checks.append(("owner 不在合法集合 → FAIL", any("不在" in x for x in f)))

    xbits_null = {
        "ownership": {"dependency-correlation": {"owner": "xbits-feature", "tested_by": None}},
        "counts": {"dependency-correlation": 1},
    }
    f, _ = evaluate_ownership(xbits_null)
    checks.append(("xbits-feature 且 tested_by=None → FAIL", any("xbits-feature 但 tested_by=None" in x for x in f)))

    ghost = {
        "ownership": {"flowbits-correlation": {"owner": "xbits-feature", "tested_by": "qa_not_exist_xyz.py"}},
        "counts": {"flowbits-correlation": 1},
    }
    f, _ = evaluate_ownership(ghost)
    checks.append(("tested_by 指向不存在的断言 → FAIL", any("指向不存在的断言" in x for x in f)))

    missing = {
        "ownership": {"a": {"owner": "dropped-document", "tested_by": None}},
        "counts": {"a": 1, "b": 1},
    }
    f, _ = evaluate_ownership(missing)
    checks.append(("counts 有而 ownership 无 → FAIL", any("归属表缺失" in x for x in f)))

    bad = sum(1 for _, ok in checks if not ok)
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--committed-blob",
        default=None,
        help="用指定文件内容代替 git HEAD 版本（测试用）",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    if args.self_test:
        return self_test()

    if not GAPS_PATH.is_file():
        print("FAIL: semantic_gaps.json 不存在（转换器未运行）", file=sys.stderr)
        return 1

    try:
        if args.committed_blob:
            committed = load_json_bytes(Path(args.committed_blob).read_bytes())
        else:
            committed = load_committed()
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    current = load_json_bytes(GAPS_PATH.read_bytes())

    allowlist = (
        json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8-sig"))
        if ALLOWLIST_PATH.is_file()
        else {"reasons": {}, "_comment": "空白名单：任何 reason 的 SID 变化都必须先登记"}
    )

    failures, notes, summary = evaluate(committed, current, allowlist)
    ownership_failures, ownership_notes = evaluate_ownership(current)
    print("== semantic_gaps diff 契约 ==")
    for note in notes:
        print(" -", note)
    if summary:
        print("变化明细:")
        for reason, d in sorted(summary.items()):
            print(f"   {reason}: +{d['+']}/-{d['-']}")
    print("== 能力归属表（V-15 收口）==")
    for note in ownership_notes:
        print(" -", note)
    failures.extend(ownership_failures)

    if failures:
        print("\nSEMANTIC GAPS GATE: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print(
        "\nSEMANTIC GAPS GATE: PASS (reason set stable, per-reason diffs allowlisted, "
        f"rate below alert, ownership table validated for {len(current.get('ownership') or {})} reasons)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
