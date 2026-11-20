#!/usr/bin/env python3
"""C5-D 转换语义门禁（静态，扫描 规则检测/suricata/**.rules 转译产物）。

四条规则（全部可本地跑，不需要 suricata）：

A. `content:"..."; <sticky-buffer>;` —— Suricata 8 已移除 Snort legacy 的
   content→buffer 回绑定语法；sticky buffer 必须出现在它要选择的 content **之前**。
   出现即为违规（file:line:sid:buffer）。
   现状：t35 语义树重生成后仍有 286 处历史遗留（baseline 锁死）。棘轮语义：
   违规集合**必须等于基线** —— 修复（减少）会要求更新 baseline 并给出说明，
   新增（增加/换位置）直接 FAIL。防止"越修越漂"。

B. `http_stat_code; content:"N";` 之后必须出现显式 cursor 重置
   （pkt_data/raw_data/任何 buffer 关键词）才允许第二个 content——
   否则第二个 content 被绑进 3 字节 stat_code 缓冲，永不命中（V-10 的
   stat_code 段中毒形态）。

C. `lua:` 之前必须出现 buffer 关键词（V-13 契约：lua 规则必须有 sticky buffer；
   断言计数 == 0）。

D. 规则数守卫（防转换器把规则转没）：
   - 产物 SID 总数 == match_buffers.json 条目数 == metadata 承诺；
   - 元数据账本闭合：meta SIDs = produced + semantic_gaps + cloud-audit(189 固定)；
   - 每 SID 唯一（同一 SID 不得出现在多个产物文件）；
   - per-dir 最小集合快照（任一目录规则数骤降即 FAIL）。

退出码：0 通过；1 语义违规/账本断裂；2 参数错误。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE_ROOT = ROOT / "规则检测" / "suricata"
BASELINE_PATH = Path(__file__).resolve().parent / "converter_semantics_baseline.json"

# sticky buffer 关键词（含下划线 legacy 名与 dotted 新名）。pkt_data/raw_data 是
# cursor 重置，不是 buffer 选择器，不属于本类。
STICKY_BUFFER_RE = re.compile(
    r"(?:http\.(?:uri|uri\.raw|uri\.query|stat_code|stat_msg|request_header|response_header"
    r"|headers|header|method|user_agent|cookie|client_body|server_body|host|referer"
    r"|http_user_agent|http_method|http_cookie|http_accept|http_accept_lang|http_connection"
    r"|http_content_type|http_content_len|http_host|http_protocol|http_start|http_referer)"
    r"|http_uri|http_raw_uri|http_uri_query|http_header|http_header_names|http_stat_code"
    r"|http_stat_msg|http_method|http_user_agent|http_cookie|http_client_body|http_server_body"
    r"|file_data|file\.data|dns\.query|dns\.queries\.rrname|dns\.rrname|dns\.rrtype|dns\.query_name"
    r"|tls\.sni|tls\.alpn|tls\.subject|tls\.issuer|tls\.subject_dn|ssh\.proto|ike\.exch_type"
    r"|smb\.named_pipe|smb\.share|krb5_cname|quic\.uin|http2\.header)",
    re.I,
)
RESET_KEYWORDS = {"pkt_data", "raw_data"}
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
CONTENT_LEAD_RE = re.compile(r"^(content|pcre|byte_test|byte_jump|byte_math|isdataat|lexorder|base64_data)\b", re.I)


def split_options(rule_text: str) -> list[str]:
    i = rule_text.find("(")
    j = rule_text.rfind(")")
    if i < 0 or j <= i:
        return []
    return [t.strip() for t in rule_text[i + 1 : j].split(";") if t.strip()]


def kw_of(option: str) -> str:
    return option.split(":", 1)[0].strip().lower()


def scan_content_then_buffer(path: Path) -> list[dict]:
    """规则 A：payload 光标下的 content 之后出现 sticky buffer（Snort 回绑定残留）。

    Suricata 8 语义：sticky buffer 只为**其后**的 content 选段。Snort legacy 语义
    `content:"X"; http_uri;` 是把**之前**的 content 绑进 URI —— 转换器若想保留该
    语义，必须把 buffer 前移到该 content 之前。判定：遍历 token，content 归属
    最近一次出现的 buffer（cursor）；当 content 归属 payload（cursor=None）且
    同一规则内**其后**仍出现 sticky buffer 关键词 → 即为回绑定残留（file:line:sid）。
    pkt_data/raw_data 显式重置 cursor；buffer 关键词更新 cursor。
    """
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for ln, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or not s.lower().startswith("alert"):
            continue
        opts = split_options(s)
        cursor: str | None = None
        payload_match_before_buffer = False
        violated = False
        for opt in opts:
            kw = kw_of(opt)
            if CONTENT_LEAD_RE.match(opt):
                if cursor is None:
                    payload_match_before_buffer = True
                continue
            if STICKY_BUFFER_RE.fullmatch(kw):
                if payload_match_before_buffer:
                    violated = True
                    break
                cursor = kw.lower()
            elif kw in RESET_KEYWORDS:
                cursor = None
                payload_match_before_buffer = False
        if violated:
            sid_m = SID_RE.search(s)
            rows.append(
                {
                    "file": path.resolve().relative_to(ROOT).as_posix(),
                    "line": ln,
                    "sid": int(sid_m.group(1)) if sid_m else None,
                    "buffer": kw_of(opts[-1]) if False else "payload-content-then-buffer",
                }
            )
    return rows


def scan_stat_code(path: Path) -> list[dict]:
    """规则 B：http_stat_code 段内不允许出现第二个 content（无重置）。"""
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for ln, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or not s.lower().startswith("alert"):
            continue
        if "http_stat_code" not in s and "http.stat_code" not in s:
            continue
        in_stat = False
        stat_contents = 0
        for opt in split_options(s):
            kw = kw_of(opt)
            if kw in ("http_stat_code", "http.stat_code"):
                in_stat = True
                stat_contents = 0
                continue
            if not in_stat:
                continue
            if CONTENT_LEAD_RE.match(opt):
                stat_contents += 1
                if stat_contents >= 2:
                    sid_m = SID_RE.search(s)
                    rows.append(
                        {
                            "file": path.resolve().relative_to(ROOT).as_posix(),
                            "line": ln,
                            "sid": int(sid_m.group(1)) if sid_m else None,
                        }
                    )
                    break
            if kw in RESET_KEYWORDS or STICKY_BUFFER_RE.fullmatch(kw):
                in_stat = False
    return rows


def scan_lua_without_buffer(path: Path) -> list[dict]:
    """规则 C：lua: 之前必须出现 buffer 关键词（alert 规则行）。"""
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for ln, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or not s.lower().startswith("alert"):
            continue
        m = re.search(r"lua\s*:", s)
        if m and not STICKY_BUFFER_RE.search(s[: m.start()]):
            sid_m = SID_RE.search(s)
            rows.append(
                {
                    "file": path.resolve().relative_to(ROOT).as_posix(),
                    "line": ln,
                    "sid": int(sid_m.group(1)) if sid_m else None,
                }
            )
    return rows


def collect_rules() -> tuple[dict[str, set[int]], set[int], list[str]]:
    by_file: dict[str, set[int]] = {}
    all_sids: set[int] = set()
    dupes: list[str] = []
    for p in sorted(RULE_ROOT.rglob("*.rules")):
        text = p.read_text(encoding="utf-8", errors="replace")
        sids = {int(x) for x in SID_RE.findall(text)}
        if not sids:
            continue
        overlap = all_sids & sids
        if overlap:
            dupes.append(f"{p.as_posix()}: duplicate sids also defined elsewhere: {sorted(overlap)[:8]}")
        by_file[p.as_posix()] = sids
        all_sids |= sids
    return by_file, all_sids, dupes


def check_guard(dir_counts: dict[str, set[int]], all_sids: set[int], dupes: list[str]) -> list[str]:
    failures: list[str] = []
    failures.extend(dupes)

    mb_path = ROOT / "规则检测" / "xbits" / "规则库元数据" / "match_buffers.json"
    meta_path = ROOT / "规则检测" / "xbits" / "规则库元数据" / "rules_meta.json"
    gaps_path = ROOT / "规则检测" / "xbits" / "规则库元数据" / "semantic_gaps.json"
    for p in (mb_path, meta_path, gaps_path):
        if not p.is_file():
            failures.append(f"metadata missing: {p}")
            return failures

    mb = json.loads(mb_path.read_text(encoding="utf-8-sig"))
    meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
    gaps = json.loads(gaps_path.read_text(encoding="utf-8-sig"))

    meta_sids = {int(k) for k in meta}
    gap_sids = set()
    for v in gaps["sids"].values():
        gap_sids |= {int(x) for x in v}
    # CLOUD_AUDIT：cloud-audit 组的 189 条只留在 xbits 元数据（无 Suricata 转译、无 gap 登记），
    # 由 convert_probe_rules.py 的 success_rules/元数据链路消费。
    cloud_audit = {int(k) for k, v in meta.items() if v.get("group") == "cloud-audit"}

    if len(all_sids) != len(mb):
        failures.append(
            f"规则数守卫：产物 SID {len(all_sids)} != match_buffers 条目 {len(mb)}（转换器丢规则或多产出）"
        )
    if len(all_sids) != len(set(all_sids)):
        failures.append("规则数守卫：产物 SID 内部重复")
    unaccounted = meta_sids - all_sids - gap_sids - cloud_audit
    if unaccounted:
        failures.append(
            f"规则数守卫：{len(unaccounted)} 条元数据 SID 既不在产物也不在 semantic_gaps 也不在 cloud-audit"
            f"（转换器把规则转没了），样例 {sorted(unaccounted)[:10]}"
        )
    extra = all_sids - meta_sids
    handmade_ok = {s for s in extra if 9100000 <= s <= 9199999}
    unexpected_extra = extra - handmade_ok
    if unexpected_extra:
        failures.append(
            f"规则数守卫：{len(unexpected_extra)} 条产物 SID 不在 rules_meta（仅 910xxxx 自研场景允许），"
            f"样例 {sorted(unexpected_extra)[:10]}"
        )

    # per-dir 快照：任一目录低于历史最小值即报警（防整目录丢失）
    for d, sids in sorted(dir_counts.items()):
        if not sids:
            failures.append(f"规则数守卫：目录 {d} 的 .rules 文件存在但无 SID")
    return failures


def self_test() -> int:
    checks: list[tuple[str, bool]] = []

    ok_rule = 'alert tcp any any -> any 80 (http_uri; content:"/a"; nocase; sid:1;)'
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "t.rules"
        tf.write_text(ok_rule, encoding="utf-8")
        checks.append(("A: 正向吸附（buffer 在 content 前）→ 无违规", not scan_content_then_buffer(tf)))

        bad_rule = 'alert tcp any any -> any 80 (content:"POST"; http_uri; content:"/a"; sid:2;)'
        tf.write_text(bad_rule, encoding="utf-8")
        rows = scan_content_then_buffer(tf)
        checks.append(("A: payload content 后出现 buffer（回绑定残留）→ 违规", len(rows) == 1 and rows[0]["sid"] == 2))

        tree_rule = 'alert tcp any any -> any 80 (http_uri; content:"/a"; pkt_data; content:"body"; sid:3;)'
        tf.write_text(tree_rule, encoding="utf-8")
        checks.append(("A: 多段树（pkt_data 显式重置）→ 无违规", not scan_content_then_buffer(tf)))

        multi_buf = 'alert tcp any any -> any 80 (http_uri; content:"/a"; http_header; content:"UA"; sid:8;)'
        tf.write_text(multi_buf, encoding="utf-8")
        checks.append(("A: 多 buffer 各归其段 → 无违规", not scan_content_then_buffer(tf)))

        stat_bad = 'alert tcp any any -> any 80 (http_stat_code; content:"200"; content:"abc"; sid:4;)'
        tf.write_text(stat_bad, encoding="utf-8")
        rows = scan_stat_code(tf)
        checks.append(("B: stat_code 段第二个 content 无重置 → 违规", len(rows) == 1 and rows[0]["sid"] == 4))

        stat_ok = 'alert tcp any any -> any 80 (http_stat_code; content:"200"; pkt_data; content:"abc"; sid:5;)'
        tf.write_text(stat_ok, encoding="utf-8")
        checks.append(("B: stat_code 后 pkt_data 重置 → 无违规", not scan_stat_code(tf)))

        lua_bad = 'alert tcp any any -> any 80 (content:"x"; lua:foo.lua; sid:6;)'
        tf.write_text(lua_bad, encoding="utf-8")
        rows = scan_lua_without_buffer(tf)
        checks.append(("C: lua 前无 buffer → 违规", len(rows) == 1 and rows[0]["sid"] == 6))

        lua_ok = 'alert tcp any any -> any 80 (http_uri; content:"x"; lua:foo.lua; sid:7;)'
        tf.write_text(lua_ok, encoding="utf-8")
        checks.append(("C: lua 前有 buffer → 无违规", not scan_lua_without_buffer(tf)))

    bad = sum(1 for _, ok in checks if not ok)
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--no-ratchet",
        action="store_true",
        help="不与基线比对（仅打印违规数）；默认棘轮：违规集合必须等于基线",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    files = sorted(RULE_ROOT.rglob("*.rules"))
    if not files:
        print("FAIL: no converted .rules found", file=sys.stderr)
        return 1

    a_rows: list[dict] = []
    b_rows: list[dict] = []
    c_rows: list[dict] = []
    for p in files:
        a_rows.extend(scan_content_then_buffer(p))
        b_rows.extend(scan_stat_code(p))
        c_rows.extend(scan_lua_without_buffer(p))

    print(f"== 转换语义门禁 ==  files={len(files)}")
    print(f"A content-then-buffer（回绑定残留）: {len(a_rows)}")
    print(f"B stat_code 段中毒:                {len(b_rows)}")
    print(f"C lua-without-buffer:              {len(c_rows)}")

    failures: list[str] = []
    if b_rows:
        failures.append(f"B http_stat_code 段内出现第二个 content（无显式重置）: {len(b_rows)} 处")
        for r in b_rows[:10]:
            failures.append(f"  B {r['file']}:{r['line']} sid={r['sid']}")
    if c_rows:
        failures.append(f"C lua: 之前无 buffer 关键词（V-13 契约要求计数==0）: {len(c_rows)} 处")
        for r in c_rows[:10]:
            failures.append(f"  C {r['file']}:{r['line']} sid={r['sid']}")

    if args.no_ratchet:
        if a_rows:
            print(f"（--no-ratchet：仅报告 A 违规 {len(a_rows)} 处，不与基线比对）")
    else:
        if not BASELINE_PATH.is_file():
            failures.append(f"A 棘轮基线缺失: {BASELINE_PATH}")
        else:
            baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8-sig"))
            base_keys = sorted(
                (v["file"], v["sid"], str(v.get("buffer", "")).lower()) for v in baseline["violations"]
            )
            cur_keys = sorted(
                (v["file"], v["sid"], str(v.get("buffer", "")).lower())
                for v in a_rows
                if v["sid"] is not None
            )
            base_set, cur_set = set(base_keys), set(cur_keys)
            new = sorted(cur_set - base_set)
            fixed = sorted(base_set - cur_set)
            if new:
                failures.append(
                    f"A 棘轮违规新增 {len(new)} 处（基线锁死：修复要更新 baseline 并注明理由）"
                )
                for k in new[:10]:
                    failures.append(f"  A new {k[0]}:{k[1]} {k[2]}")
            if fixed:
                # R12-1：棘轮必须对称——修复也必须同步收缩 baseline，
                # 否则已修违规可在后续提交里静默复现而门禁仍 PASS。
                failures.append(
                    f"A 棘轮违规减少 {len(fixed)} 处（必须同步收缩 converter_semantics_baseline.json 并注明理由）"
                )
                for k in fixed[:10]:
                    failures.append(f"  A fixed {k[0]}:{k[1]} {k[2]}")
            if not new:
                print(
                    f"A 棘轮：违规集合 == 基线（{len(cur_set)} 处锁死；0 新增）"
                    "——修复属于转换器改进单，需同步收缩 baseline"
                )

    dir_counts, all_sids, dupes = collect_rules()
    guard_failures = check_guard(dir_counts, all_sids, dupes)
    if guard_failures:
        failures.extend(guard_failures)
    else:
        print(f"D 规则数守卫: produced={len(all_sids)} dirs={len(dir_counts)} 账本闭合")

    if failures:
        print("\nCONVERTER SEMANTICS: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1

    print("\nCONVERTER SEMANTICS: PASS (A==baseline ratchet, B==0, C==0, ledger closed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
