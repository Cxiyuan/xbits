#!/usr/bin/env python3
"""End-to-end Suricata thin-hook completeness / rule matrix.

For every generated PCAP/case this does two independent runs through the
official-image-based `xbits-suricata` container:

  1. normal Suricata EVE file output (ground truth)
  2. the xbits Suricata EVE-filetype hook -> xbits central engine

断言分三层（都必须是真语义断言，不接受"能加载/出现子串"）：

  * 转发完整性：engine SID multiset == EVE SID multiset（丢/重复都失败）。
  * 用例断言：require ⊆ engine、forbid ∩ engine = ∅。
  * 范围断言（本文件修复 V-17 的核心）：
      - `match: exact` 的用例：**本场景规则集内**的命中必须精确等于 require
        （`set(engine) & cat_sids == require`）。负例（require 为空）与 web 全量用例
        使用该模式。
      - 其余用例：require 之外、forbid 之外的"场景内未声明命中"必须打印
        `::warning::`，不得只拼进 OK 文案。
      - 跨场景命中（命中别的规则目录的 SID，如 web 用例命中后门命令参数规则）
        一律打印 `::warning::`；若用例用 `known_extra` + `known_extra_reason`
        显式登记，则视为已知重叠，不再重复告警（但仍会打印）。
      - R9-2 收紧：`known_extra` 只允许抵扣**跨场景**命中；场景内未声明命中
        不允许用 known_extra 抵扣——要么补进 require（真实命中变断言）、
        要么补进 forbid（误报）、要么保持 warning（strict 下失败）。
  * `--strict-warnings` 把上述 warning 升级为失败；CI 用 warning 模式收集一轮
    真实数据后再开（TODO 见 qa/QA_REPORT.md C8 跟踪项）。

The rule coverage gate (`qa_rule_coverage.py`) separately covers the 4 scenario
rule dirs and prints its own honest covered/excluded numbers.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")

CATEGORIES = [
    {
        "name": "dns",
        "rule_dir": ROOT / "规则检测" / "suricata" / "DNS隧道与带外检测",
        "cases": ROOT / "测试用例" / "cases.json",
        "pcap_dir": ROOT / "测试用例" / "pcap",
    },
    {
        "name": "recon",
        "rule_dir": ROOT / "规则检测" / "suricata" / "侦察与攻击工具指纹",
        "cases": ROOT / "测试用例" / "recon_cases.json",
        "pcap_dir": ROOT / "测试用例" / "recon_pcap",
    },
    {
        "name": "web",
        "rule_dir": ROOT / "规则检测" / "suricata" / "Web漏洞利用",
        "cases": ROOT / "测试用例" / "web_cases.json",
        "pcap_dir": ROOT / "测试用例" / "web_pcap",
    },
    {
        "name": "backdoor",
        "rule_dir": ROOT / "规则检测" / "suricata" / "后门通信",
        "cases": ROOT / "测试用例" / "backdoor_cases.json",
        "pcap_dir": ROOT / "测试用例" / "backdoor_pcap",
    },
]


def category_sids(rule_dir: Path) -> set[int]:
    sids: set[int] = set()
    for path in sorted(rule_dir.rglob("*.rules")):
        text = path.read_text(encoding="utf-8", errors="replace")
        sids.update(int(x) for x in SID_RE.findall(text))
    return sids


def wait_for_socket(path: Path, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"xbits hook socket did not appear: {path}")


def wait_drain(path: Path, stable: float = 0.3, timeout: float = 5.0) -> None:
    """等 engine 输出不再增长（替代固定 sleep）。

    hook 端是异步写盘：进程 terminate 之前必须确认最后一次收割已经落盘，
    否则会把"还没来得及写"误判成"丢告警"。
    """
    deadline = time.time() + timeout
    last = -1
    last_change = time.time()
    while time.time() < deadline:
        size = path.stat().st_size if path.exists() else 0
        if size != last:
            last = size
            last_change = time.time()
        elif time.time() - last_change >= stable:
            return
        time.sleep(0.05)


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


def evaluate_case(
    case: str,
    spec: dict,
    cat_sids: set[int],
    eve: Counter,
    engine: Counter,
    engine_err: str,
    default_exact: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    """纯函数：返回 (failures, warnings, notes)。便于本地无 docker 自测。

    exact 的默认值由 main() 按用例语义给出：负例（require 为空）与 web 全量用例
    默认 exact；用例 JSON 里显式写 `match: exact|subset` 可覆盖默认值。
    """
    failures: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []

    require = {int(x) for x in spec.get("require", [])}
    forbid = {int(x) for x in spec.get("forbid", [])}
    known_extra = {int(x) for x in spec.get("known_extra", [])}
    exact = spec["match"] == "exact" if "match" in spec else default_exact

    if eve != engine:
        failures.append(f"hook lost/duplicated alerts: EVE={dict(eve)} engine={dict(engine)}")
    if not require <= set(engine):
        failures.append(f"missing required sids: {sorted(require - set(engine))}")
    if forbid & set(engine):
        failures.append(f"forbidden sids fired: {sorted(forbid & set(engine))}")
    if known_extra and not (spec.get("known_extra_reason") or "").strip():
        failures.append("known_extra 必须同时提供 known_extra_reason（登记已知重叠的理由）")

    hits = set(engine)
    in_scope = hits & cat_sids
    out_scope = hits - cat_sids

    if exact:
        if in_scope != require:
            failures.append(
                "exact-in-scope mismatch: "
                f"scope_hits={sorted(in_scope)} require={sorted(require)}"
            )
    else:
        # 场景内未声明命中：真实命中就补进 require（把"会命中"变成断言），
        # 误报才补进 forbid。R9-2：known_extra **不再**抵扣场景内未声明命中
        # （它只允许登记跨场景重叠——场景内的多规则命中必须被断言，否则给
        # "漏断言"留了免检通道）；未处理的升为 warning（strict 模式下失败）。
        unasserted_in_scope = in_scope - require - forbid
        if unasserted_in_scope:
            hint = ""
            in_registered = in_scope & known_extra
            if in_registered:
                hint = (
                    f"（known_extra 里登记的 {sorted(in_registered)} 属于本场景 SID，"
                    "R9-2 起不再抵扣场景内命中——请补 require/forbid，或移出 known_extra）"
                )
            warnings.append(
                "本场景内未声明命中（未在 require/forbid 里）: "
                f"{sorted(unasserted_in_scope)}{hint}"
            )

    unexplained_out = out_scope - known_extra
    if unexplained_out:
        warnings.append(
            "跨场景命中（属于其它规则目录，用 known_extra+reason 登记或修掉）: "
            f"{sorted(unexplained_out)}"
        )
    if known_extra:
        explained_in = known_extra & in_scope
        explained_out = known_extra & out_scope
        notes.append(
            f"known_extra={sorted(known_extra)} "
            f"(cross-scenario={sorted(explained_out)}"
            + (f"; in-scope={sorted(explained_in)} 不抵扣（R9-2）" if explained_in else "")
            + f") reason={spec.get('known_extra_reason')}"
        )
        stale = known_extra - hits
        if stale:
            warnings.append(f"known_extra 登记项未再出现（需清理或规则已变）: {sorted(stale)}")

    if any(tag in engine_err for tag in ("bad hook event", "hook accept error", "hook read error")):
        failures.append(f"engine stderr: {engine_err[-500:]}")
    return failures, warnings, notes


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

        # 轮询到 engine 输出稳定，而不是固定 sleep。
        wait_drain(engine_out)
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


def pass_summary(total_cases: int, exact_cases: int, warnings: list[str], strict: bool) -> str:
    """PASS 行文案（R9-5）：strict 下必须显示 enabled，非 strict 才提示如何开启。

    旧文案在 strict 模式也打印 "run with --strict-warnings to gate"，读者会误以为
    strict 没生效（实际已生效，只是恰好 0 warning）。
    """
    if strict:
        gate = "strict-warnings: enabled (0 warnings)"
    else:
        gate = (
            f"{len(warnings)} warnings not asserted as failures — "
            "run with --strict-warnings to gate"
        )
    return (
        f"SURICATA HOOK MATRIX: PASS ({total_cases} cases, EVE == engine exactly; "
        f"{exact_cases} cases use in-scope exact equality; {gate})"
    )


def self_test() -> int:
    """本地（无 docker）验证 evaluate_case 的判定语义。"""
    cat = {9103001, 9103008, 9103013, 9103015, 9103018, 9103101, 9103102, 9103103, 9103104}
    web_exact = {"require": [9103015], "forbid": [9103001, 9103008, 9103013, 9103018], "match": "exact"}
    ok_engine = Counter({9103015: 1})
    checks: list[tuple[str, bool]] = []

    f, w, _ = evaluate_case("c", web_exact, cat, ok_engine, ok_engine, "")
    checks.append(("exact 命中恰好等于 require → 无失败", not f and not w))

    extra_in = Counter({9103015: 1, 9103101: 1})
    f, w, _ = evaluate_case("c", web_exact, cat, extra_in, extra_in, "")
    checks.append(("exact 场景内多命中 → 失败", bool(f) and any("exact-in-scope" in x for x in f)))

    subset = {"require": [9103015]}
    f, w, _ = evaluate_case("c", subset, cat, extra_in, extra_in, "")
    checks.append(
        ("subset 场景内未声明命中 → warning 而非失败", not f and any("未声明命中" in x for x in w))
    )

    cross = Counter({9103015: 1, 9104002: 1})
    f, w, _ = evaluate_case("c", subset, cat, cross, cross, "")
    checks.append(("跨场景命中 → warning", not f and any("跨场景" in x for x in w)))

    known = {"require": [9103015], "known_extra": [9104002], "known_extra_reason": "web_cmdi 与后门命令参数规则真实重叠"}
    f, w, _ = evaluate_case("c", known, cat, cross, cross, "")
    checks.append(("已登记 known_extra → 不再告警", not f and not any("跨场景" in x for x in w)))

    no_reason = {"require": [9103015], "known_extra": [9104002]}
    f, _, _ = evaluate_case("c", no_reason, cat, cross, cross, "")
    checks.append(("known_extra 缺 reason → 失败", any("known_extra_reason" in x for x in f)))

    lost = Counter({9103015: 1})
    f, _, _ = evaluate_case("c", subset, cat, Counter({9103015: 2}), lost, "")
    checks.append(("丢告警（EVE 2 engine 1）→ 失败", any("lost/duplicated" in x for x in f)))

    f, _, _ = evaluate_case("c", subset, cat, ok_engine, ok_engine, "bad hook event: x")
    checks.append(("engine stderr 异常 → 失败", any("stderr" in x for x in f)))

    neg = {"require": [], "forbid": [9103001]}
    neg_hit = Counter({9103101: 1})
    f, _, _ = evaluate_case("c", neg, cat, neg_hit, neg_hit, "", default_exact=True)
    checks.append(("负例默认 exact：本场景内任何命中 → 失败", bool(f)))

    f, _, _ = evaluate_case("c", neg, cat, Counter(), Counter(), "", default_exact=True)
    checks.append(("负例默认 exact：零命中 → 通过", not f))

    known_in = {"require": [9103015], "known_extra": [9103101], "known_extra_reason": "旧用法：同场景多规则命中"}
    f, w, _ = evaluate_case("c", known_in, cat, extra_in, extra_in, "")
    checks.append(
        ("R9-2 负例：场景内命中用 known_extra+reason 登记 → 仍 warning（不得抵扣）",
         not f and any("未声明命中" in x and "R9-2" in x and "9103101" in x for x in w))
    )

    stale = {"require": [9103015], "known_extra": [9103102], "known_extra_reason": "x"}
    f, w, _ = evaluate_case("c", stale, cat, ok_engine, ok_engine, "")
    checks.append(("known_extra 未再出现 → warning（strict 下失败）", any("未再出现" in x for x in w)))

    # R9-2 正例：跨场景 known_extra 仍然抵扣跨场景 warning（语义未变）；
    cross_ok = {"require": [9103015], "known_extra": [9104002], "known_extra_reason": "web_cmdi 与后门规则真实重叠"}
    f, w, _ = evaluate_case("c", cross_ok, cat, cross, cross, "")
    checks.append(
        ("R9-2 正例：跨场景 known_extra 仍抵扣 → 无跨场景 warning",
         not f and not any("跨场景" in x for x in w))
    )

    # R9-5：strict 模式的 PASS 行不得再提示"用 --strict-warnings 开启"（会误导成没启用）。
    strict_line = pass_summary(18, 9, [], strict=True)
    non_strict_line = pass_summary(18, 9, [f"w{i}" for i in range(2)], strict=False)
    checks.append(
        (
            "R9-5 正例：strict 下 PASS 行含 strict-warnings: enabled 且不再提示开启",
            "strict-warnings: enabled" in strict_line and "run with --strict-warnings" not in strict_line,
            strict_line,
        )
    )
    checks.append(
        (
            "R9-5 正例：非 strict 下 PASS 行如实给出 warnings 数与开启方式",
            "2 warnings not asserted as failures" in non_strict_line
            and "run with --strict-warnings to gate" in non_strict_line,
            non_strict_line,
        )
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
    parser.add_argument("--image", default="xbits-suricata")
    parser.add_argument("--xbits", default=str(ROOT / "xbits" / "target" / "release" / "xbits"))
    parser.add_argument("--rules", default=str(ROOT / "xbits" / "rules" / "qa-all.json"))
    parser.add_argument("--categories", default="dns,recon,web,backdoor")
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="把 ::warning::（未声明命中/跨场景命中）升级为失败；CI 先用默认 warning 模式收集实数",
    )
    parser.add_argument("--self-test", action="store_true", help="本地验证判定语义，不需要 docker")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    image = args.image
    xbits = Path(args.xbits)
    rules = Path(args.rules)
    wanted = {x.strip() for x in args.categories.split(",") if x.strip()}

    failures: list[str] = []
    warnings: list[str] = []
    exact_cases = 0
    total_cases = 0
    for cat in CATEGORIES:
        if cat["name"] not in wanted:
            continue
        cat_sids = category_sids(Path(cat["rule_dir"]))
        cases = json.loads(Path(cat["cases"]).read_text(encoding="utf-8-sig"))
        pcap_dir = Path(cat["pcap_dir"])
        for case, spec in sorted(cases.items()):
            total_cases += 1
            require = {int(x) for x in spec.get("require", [])}
            # 负例（require 为空：整场景规则集都必须沉默）与 web 全量用例默认精确相等；
            # 其它正例的 forbid 只列了已知风险 SID，不能声称穷举，故默认 subset + warning。
            default_exact = (not require) or cat["name"] == "web"
            exact_cases += 1 if (spec.get("match") == "exact" or ("match" not in spec and default_exact)) else 0
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
            case_failures, case_warnings, notes = evaluate_case(
                case, spec, cat_sids, eve, engine, observed["engine_err"], default_exact=default_exact
            )
            label = f"{cat['name']}/{case}"
            for note in notes:
                print(f"{label}: note {note}")
            for warning in case_warnings:
                warnings.append(f"{label}: {warning}")
                print(f"::warning::{label}: {warning}")
            if case_failures:
                failures.extend(f"{label}: {p}" for p in case_failures)
                print(f"{label}: FAIL " + "; ".join(case_failures), file=sys.stderr)
            else:
                print(f"{label}: OK eve={sorted(eve)} engine={sorted(engine)}")

    if failures:
        print(
            f"\nSURICATA HOOK MATRIX: FAIL ({len(failures)} failures, {total_cases} cases)",
            file=sys.stderr,
        )
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1

    if args.strict_warnings and warnings:
        print(
            f"\nSURICATA HOOK MATRIX: FAIL (--strict-warnings: {len(warnings)} warnings)",
            file=sys.stderr,
        )
        for item in warnings:
            print(" -", item, file=sys.stderr)
        return 1

    print("\n" + pass_summary(total_cases, exact_cases, warnings, args.strict_warnings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
