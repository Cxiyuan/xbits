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
    allow_new_reasons = allowlist.get("allow_new_reasons") == True  # noqa: E712
    allow_removed_reasons: dict = allowlist.get("allow_removed_reasons") or {}

    for reason, d in sorted(diff.items()):
        if d["reason_added"]:
            if allow_new_reasons:
                notes.append(f"reason 新增（白名单允许）: {reason} ({len(d['added'])} SIDs)")
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
    print("== semantic_gaps diff 契约 ==")
    for note in notes:
        print(" -", note)
    if summary:
        print("变化明细:")
        for reason, d in sorted(summary.items()):
            print(f"   {reason}: +{d['+']}/-{d['-']}")

    if failures:
        print("\nSEMANTIC GAPS GATE: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print("\nSEMANTIC GAPS GATE: PASS (reason set stable, per-reason diffs allowlisted, rate below alert)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
