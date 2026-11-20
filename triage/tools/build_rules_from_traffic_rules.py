#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从流量检测规则库（明文规则）里，抽取"适合 triage（文件静态分析）"的规则，生成 YARA。

三个原则（本脚本的硬约束）：
1. 只保留 **triage 能用** 的规则：本质是"文件内容/字节特征"（file_data / only_stream /
   纯字节 content），且能无损转成可编译的 YARA（有可用的 content；pcre-only 丢弃）。
2. **避免与既有 Suricata/Zeek 规则重复检测**：
   - 先按 SID 排除已被仓库 `规则检测/suricata` 覆盖的；
   - 再按 **内容签名** 排除内容已存在的（处理 ml_webshell 与 webshell_detect 同内容不同 SID 的重复）；
   - Zeek 侧只有评分/情报脚本，无文件内容签名，无需按内容排除。
3. **按检测内容分类** 输出到 `triage/rules/<category>/`。

用法：
  python3 triage/tools/build_rules_from_traffic_rules.py \
    --src-dir "C:/Users/sona/Desktop/流量检测规则" \
    --repo-rules 规则检测/suricata \
    --out triage/rules
"""
from __future__ import annotations

import argparse
import json
import os
import re
import collections

CATEGORIES = ["webshell", "trojan", "backdoor", "spyware", "worm", "shellcode", "document"]

RX_RULE = re.compile(r'^\s*(alert|drop|log|pass|reject)\b', re.I)
RX_SID = re.compile(r'\bsid\s*:\s*(\d+)')
RX_MSG = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
RX_CONTENT = re.compile(r'content\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)


def iter_rules(path: str):
    buf = ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            s = raw.rstrip("\n")
            if not buf and not RX_RULE.match(s):
                continue
            buf = (buf + " " + s.strip()) if buf else s.strip()
            if buf.rstrip().endswith("\\"):
                buf = buf.rstrip()[:-1].rstrip()
                continue
            if RX_RULE.match(buf):
                yield buf
            buf = ""
    if buf and RX_RULE.match(buf):
        yield buf


def category_of(rel: str) -> str | None:
    n = os.path.basename(rel).lower()
    for k in ("webshell", "shellcode", "trojan", "backdoor", "spyware", "worm"):
        if k in n:
            return k
    if n == "file.rules":
        return "document"
    return None


def content_key(rule: str):
    conts = [c.strip().lower() for c in RX_CONTENT.findall(rule)]
    if not conts:
        return None
    return tuple(sorted(set(conts)))


def _parse_bytes(content: str) -> bytes:
    out = bytearray()
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "|":
            j = content.find("|", i + 1)
            if j == -1:
                out.append(ord("|"))
                i += 1
                continue
            for h in content[i + 1 : j].split():
                try:
                    out.append(int(h, 16) & 0xFF)
                except ValueError:
                    pass
            i = j + 1
        elif ch == "\\" and i + 1 < n:
            nx = content[i + 1]
            if nx == "x" and i + 3 < n:
                try:
                    out.append(int(content[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            mp = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39}
            out.append(mp.get(nx, ord(nx) & 0xFF))
            i += 2
        else:
            out.append(ord(ch) & 0xFF)
            i += 1
    return bytes(out)


def _byte_len(content: str) -> int:
    return len(_parse_bytes(content))


def _yara_string(content: str, nocase: bool):
    raw = _parse_bytes(content)
    if not raw:
        return None
    printable = all(32 <= b < 127 for b in raw)
    if printable:
        lit = raw.decode("ascii").replace("\\", "\\\\").replace('"', '\\"')
        return f'"{lit}"' + (" nocase" if nocase else "")
    return "{ " + " ".join(f"{b:02x}" for b in raw) + " }"


def _emit_rule(cat: str, sid: str, msg: str, rel: str, contents: list[str], nocase: bool) -> str | None:
    strings = []
    for idx, c in enumerate(contents):
        ys = _yara_string(c, nocase)
        if ys is None:
            continue
        strings.append((f"$s{idx+1}", ys))
    if not strings:
        return None
    safe_msg = (msg or "").replace('"', "'").replace("\n", " ")
    name = f"xb_{cat}_{sid}"
    cond = f"${strings[0][0].lstrip('$')}" if len(strings) == 1 else "all of them"
    if len(strings) > 1:
        cond = "all of them"
    else:
        cond = strings[0][0]
    lines = [
        f"rule {name}",
        "{",
        "    meta:",
        f'        description = "{safe_msg}"',
        f'        sid = "{sid}"',
        f'        category = "{cat}"',
        f'        source = "{rel}"',
        '        engine = "xbits-triage"',
        "    strings:",
    ]
    for var, val in strings:
        lines.append(f"        {var} = {val}")
    lines.append("    condition:")
    lines.append(f"        {cond}")
    lines.append("}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-dir", required=True)
    ap.add_argument("--repo-rules", default=os.path.join("规则检测", "suricata"))
    ap.add_argument("--out", default=os.path.join("triage", "rules"))
    ap.add_argument("--min-total", type=int, default=8, help="所有 content 字节数之和下限")
    ap.add_argument("--min-max", type=int, default=6, help="最长 content 字节数下限")
    args = ap.parse_args()

    # 1) 收集既有 Suricata 规则的 SID 与内容签名（用于去重，避免重复检测）
    covered_sids: set[str] = set()
    covered_keys: set[tuple] = set()
    if os.path.isdir(args.repo_rules):
        for dp, _, fs in os.walk(args.repo_rules):
            for fn in fs:
                if not fn.endswith(".rules"):
                    continue
                for rule in iter_rules(os.path.join(dp, fn)):
                    for m in RX_SID.finditer(rule):
                        covered_sids.add(m.group(1))
                    k = content_key(rule)
                    if k:
                        covered_keys.add(k)

    # 2) 遍历源规则，筛选
    stats = collections.defaultdict(collections.Counter)
    seen_sids: set[str] = set()
    accepted_keys = collections.defaultdict(set)
    per_cat_rules = collections.defaultdict(list)
    manifest = []

    for dp, _, fs in os.walk(args.src_dir):
        for fn in fs:
            if not fn.endswith(".rules"):
                continue
            path = os.path.join(dp, fn)
            rel = os.path.relpath(path, args.src_dir).replace("\\", "/")
            cat = category_of(rel)
            if not cat:
                continue
            for rule in iter_rules(path):
                m = RX_SID.search(rule)
                if not m:
                    stats[cat]["no_sid"] += 1
                    continue
                sid = m.group(1)
                if sid in seen_sids:
                    stats[cat]["dup_sid"] += 1
                    continue
                seen_sids.add(sid)
                if sid in covered_sids:
                    stats[cat]["overlap_sid"] += 1
                    continue
                low = rule.lower()
                is_file = (
                    "file_data" in low
                    or "only_stream" in low
                    or (
                        'content:"|' in low
                        and "uricontent" not in low
                        and "http_" not in low
                        and "method:" not in low
                        and "status_code" not in low
                    )
                )
                if not is_file:
                    stats[cat]["not_file"] += 1
                    continue
                conts = RX_CONTENT.findall(rule)
                if not conts:
                    stats[cat]["no_content"] += 1
                    continue
                key = content_key(rule)
                if key in covered_keys:
                    stats[cat]["overlap_content_repo"] += 1
                    continue
                total = sum(_byte_len(c) for c in conts)
                mx = max(_byte_len(c) for c in conts)
                if total < args.min_total or mx < args.min_max:
                    stats[cat]["weak"] += 1
                    continue
                if key in accepted_keys[cat]:
                    stats[cat]["repeat"] += 1
                    continue
                accepted_keys[cat].add(key)
                msgm = RX_MSG.search(rule)
                msg = msgm.group(1) if msgm else ""
                nocase = "nocase" in low
                yara = _emit_rule(cat, sid, msg, rel, conts, nocase)
                if not yara:
                    stats[cat]["emit_failed"] += 1
                    continue
                per_cat_rules[cat].append(yara)
                manifest.append({"category": cat, "sid": sid, "msg": msg,
                                 "source": rel, "yara_rule": f"xb_{cat}_{sid}"})
                stats[cat]["ACCEPT"] += 1

    # 3) 写文件（按类别）
    written = {}
    for cat in CATEGORIES:
        rules = per_cat_rules.get(cat) or []
        if not rules:
            continue
        d = os.path.join(args.out, cat)
        os.makedirs(d, exist_ok=True)
        fp = os.path.join(d, f"{cat}.yar")
        header = (
            f"// 自动生成（勿手改）：由 triage/tools/build_rules_from_traffic_rules.py 从流量检测规则库（明文规则）抽取。\n"
            f"// 类别: {cat} | 规则数: {len(rules)} | 仅收录：文件内容型 & 不与 Suricata/Zeek 重复。\n"
        )
        with open(fp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header + "\n" + "\n\n".join(rules) + "\n")
        written[cat] = (fp, len(rules))

    # 4) 清单
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    # 5) 报告
    print("== 抽取结果（按类别）==")
    for cat in CATEGORIES:
        if stats[cat]:
            print(f"[{cat}] {dict(stats[cat])}")
    print("\n== 写出文件 ==")
    for cat, (fp, n) in written.items():
        print(f"  {fp}  ({n} rules)")
    print(f"\n总计 ACCEPT = {sum(s['ACCEPT'] for s in stats.values())} 条（YARA 规则）")
    print("跳过原因统计：overlap_sid(已转译) / overlap_content_repo(内容重复) / not_file(非文件内容)"
          " / weak(过短) / repeat(同内容) / dup_sid(重复SID)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
