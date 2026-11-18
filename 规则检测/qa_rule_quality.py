#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则质量 QA：静态估算误报风险、重复规则、Suricata/Zeek 重叠与 xbits 规则概览。

只做只读分析，输出：
  规则检测/docs/规则质量QA数据.json
用法：
  python 规则检测/qa_rule_quality.py
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUR = ROOT / "suricata"
SCENARIOS = {"DNS隧道与带外检测", "Web漏洞利用", "侦察与攻击工具指纹", "后门通信"}
PRIM_KW = {
    "byte_test", "byte_jump", "byte_extract", "byte_math", "dsize", "urilen",
    "filemagic", "fileext", "filename", "isdataat", "lua", "xbits", "bsize", "dataset", "datarep", "dns_query",
}
HTTP_BUFFERS = {
    "http_uri", "http_raw_uri", "http_method", "http_cookie", "http_raw_cookie",
    "http_client_body", "http_server_body", "http_header", "http_raw_header",
    "http_host", "http_raw_host", "http_user_agent", "http_stat_code",
    "http_stat_msg", "file_data",
}


def split_options(opts: str) -> list[str]:
    tokens, cur = [], []
    inq = esc = False
    for ch in opts:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if ch == '"':
            inq = not inq
            cur.append(ch)
            continue
        if ch == ";" and not inq:
            tokens.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        tokens.append(tail)
    return [t for t in tokens if t]


def iter_rules(path: Path):
    text = path.read_bytes().decode("utf-8", "replace")
    buf = ""
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if not buf:
            if not re.match(r"^(alert|log|pass|drop|reject|sdrop)\b", s, re.I):
                continue
            buf = s
        else:
            buf += " " + s
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip()
            continue
        yield buf
        buf = ""
    if buf:
        yield buf


def content_len(s: str) -> int:
    """粗略计算 content 字符长度（hex 段按字节计）。"""
    total = 0
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "|":
            j = s.find("|", i + 1)
            if j > i:
                hexpart = s[i + 1 : j].replace(" ", "")
                total += max(1, len(hexpart) // 2)
                i = j + 1
                continue
        if s[i] == "\\" and i + 1 < n:
            total += 1
            i += 2
            continue
        total += 1
        i += 1
    return total


def parse_rule(line: str):
    if "(" not in line or ")" not in line:
        return None
    body = line[line.find("(") + 1 : line.rfind(")")]
    m = re.search(r"\bsid\s*:\s*(\d+)", body)
    if not m:
        return None
    sid = int(m.group(1))
    m = re.search(r'\bmsg\s*:\s*"([^"]*)"', body)
    msg = m.group(1) if m else ""

    pos_contents: list[tuple[str, int]] = []
    neg_contents: list[str] = []
    for m in re.finditer(r'\bcontent\s*:\s*(!?)\s*"((?:[^"\\]|\\.)*)"', body):
        if m.group(1) == "!":
            neg_contents.append(m.group(2))
        else:
            pos_contents.append((m.group(2), content_len(m.group(2))))
    pcres = [m.group(1) for m in re.finditer(r'\bpcre\s*:\s*"((?:[^"\\]|\\.)*)"', body)]
    primitives = set(re.findall(r"\b(" + "|".join(sorted(PRIM_KW)) + r")\s*:", body, re.I))
    buffers = set(re.findall(r"\b(" + "|".join(sorted(HTTP_BUFFERS)) + r")\b", body, re.I))
    has_flow = bool(re.search(r"\bflow\s*:", body, re.I))
    noalert = bool(re.search(r"\bnoalert\b", body, re.I))
    pattern = " ".join(sorted(x[0] for x in pos_contents)) + " || " + " ".join(sorted(pcres))
    tokens = [x.strip() for x in body.split(";") if x.strip()]
    return {
        "sid": sid,
        "msg": msg,
        "tokens": tokens,
        "noalert": noalert,
        "pos_contents": pos_contents,
        "neg_contents": neg_contents,
        "pcres": pcres,
        "primitives": primitives,
        "buffers": buffers,
        "has_flow": has_flow,
        "any_any": bool(re.match(r"^(alert|log|pass|drop|reject|sdrop)\s+\w+\s+any\s+any\s*->\s*any\s+any\b", line, re.I)),
        "pattern": pattern,
    }


def has_pos_primitive(r) -> bool:
    if r["pos_contents"]:
        return True
    for p in r["pcres"]:
        pat = p.strip()
        if pat.startswith("!"):
            continue
        return True
    return bool(r["primitives"])


def classify(r, tier: str | None):
    pos = r["pos_contents"]
    if r.get("noalert"):
        return ["state-only"], 0, "state"
    flags: list[str] = []
    if not has_pos_primitive(r):
        flags.append("no-positive-primitive")
    if len(pos) == 1 and pos[0][1] <= 3 and not r["pcres"] and not r["primitives"]:
        if not any(x in r["buffers"] or x.startswith("http_") for x in r["tokens"]) and not any(
            x.lower().startswith(("depth:", "offset:", "within:", "distance:")) for x in r["tokens"]
        ):
            flags.append("short-single-content")
    if len(pos) == 1 and pos[0][1] <= 6 and not r["pcres"] and not r["primitives"]:
        flags.append("generic-single-content")
    if not pos and r["pcres"]:
        for p in r["pcres"]:
            pat = p.strip()
            if pat.startswith("!") or not pat.startswith("/"):
                continue
            body = pat[1 : pat.rfind("/")] if pat.rfind("/") > 0 else pat
            if body.startswith(".*") or body.startswith(".+"):
                flags.append("broad-pcre")
                break
    if r["neg_contents"] and not pos and not r["primitives"] and not any(not p.strip().startswith("!") for p in r["pcres"]):
        flags.append("negative-only")
    if r["any_any"] and not r["has_flow"]:
        flags.append("any-any-no-flow")
    if "file_data" in r["buffers"] and not pos and not r["pcres"] and not r["primitives"]:
        flags.append("file-data-no-anchor")
    if tier == "weak":
        flags.append("weak-tier")
    weights = {
        "no-positive-primitive": 5,
        "short-single-content": 4,
        "generic-single-content": 2,
        "broad-pcre": 4,
        "negative-only": 4,
        "any-any-no-flow": 2,
        "file-data-no-anchor": 1,
        "weak-tier": 1,
    }
    score = sum(weights.get(f, 1) for f in flags)
    level = "critical" if score >= 7 else "high" if score >= 4 else "medium" if score >= 2 else "low"
    return flags, score, level


def main() -> int:
    lib = json.load(open(ROOT / "xbits/规则库元数据/sid_library.json", encoding="utf-8"))
    meta = json.load(open(ROOT / "xbits/规则库元数据/rules_meta.json", encoding="utf-8"))
    per_category = defaultdict(lambda: {"count": 0, "weak": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "state": 0})
    all_rules = []
    seen_patterns = defaultdict(list)
    seen_msgs = defaultdict(list)
    for path in sorted(SUR.rglob("*.rules")):
        cat = path.relative_to(SUR).parts[0]
        if cat in SCENARIOS:
            category = f"场景/{cat}"
        else:
            category = "/".join(path.relative_to(SUR).parts[:-1])
        for line in iter_rules(path):
            r = parse_rule(line)
            if not r:
                continue
            sid = r["sid"]
            entry = lib.get(str(sid), {})
            tier = entry.get("tier") or (meta.get(str(sid), {}).get("tier"))
            flags, score, level = classify(r, tier)
            r.update({
                "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                "category": category,
                "tier": tier,
                "flags": flags,
                "risk_score": score,
                "risk_level": level,
                "name": entry.get("name") or r["msg"],
            })
            all_rules.append(r)
            c = per_category[category]
            c["count"] += 1
            if tier == "weak":
                c["weak"] += 1
            c[level] += 1
            if r["pattern"] and r["pattern"] != " || ":
                seen_patterns[r["pattern"]].append(sid)
            if r["msg"]:
                seen_msgs[r["msg"]].append(sid)

    # 重复规则（相同 content/pcre 组合被多个 SID 使用）
    dup_patterns = [
        {"sids": v, "count": len(v)}
        for k, v in seen_patterns.items()
        if len(v) > 1
    ]
    dup_patterns.sort(key=lambda x: -x["count"])
    # 相同 msg 多 SID
    dup_msgs = [
        {"msg": k, "sids": v, "count": len(v)}
        for k, v in seen_msgs.items()
        if len(v) > 1
    ]
    dup_msgs.sort(key=lambda x: -x["count"])

    risky = sorted(
        [r for r in all_rules if r["risk_level"] in ("critical", "high")],
        key=lambda x: (-x["risk_score"], x["sid"]),
    )
    risky_out = [
        {
            "sid": r["sid"],
            "name": r["name"],
            "msg": r["msg"],
            "category": r["category"],
            "file": r["file"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "flags": r["flags"],
        }
        for r in risky[:120]
    ]

    # Suricata 场景规则 vs Zeek 脚本关联
    scenario = {}
    for name in sorted(SCENARIOS):
        sids = []
        for path in (SUR / name).rglob("*.rules"):
            for line in iter_rules(path):
                r = parse_rule(line)
                if r:
                    sids.append(r["sid"])
        scenario[name] = {"suricata_sids": sorted(set(sids)), "count": len(set(sids))}

    # Zeek 脚本中的 related_sids / reason / 检测关键字
    zeek_info = {}
    for path in sorted((ROOT / "zeek").rglob("*.zeek")):
        text = path.read_text(encoding="utf-8", errors="replace")
        related = sorted(set(int(x) for x in re.findall(r'"[0-9]{6,}(?:,[0-9]+)*"', text) for x in x.split(",") if x.strip().isdigit()))
        related2 = []
        for m in re.finditer(r'related_sids\s*=\s*"([^"]+)"', text):
            for x in m.group(1).split(","):
                if x.strip().isdigit():
                    related2.append(int(x.strip()))
        reasons = sorted(set(re.findall(r'emit\([^,]+,\s*"([^"]+)"', text)))
        zeek_info[str(path.relative_to(ROOT)).replace("\\", "/")] = {
            "related_sids": sorted(set(related2)),
            "reasons": reasons,
            "uses_content_inspect": "function inspect" in text,
            "uses_http_events": "event http_request" in text,
            "uses_dns_events": "event dns_" in text,
        }

    summary = {
        "total_rules": len(all_rules),
        "converted_rules": sum(1 for r in all_rules if not r["category"].startswith("场景/")),
        "scenario_rules": sum(1 for r in all_rules if r["category"].startswith("场景/")),
        "weak_tier": sum(1 for r in all_rules if r["tier"] == "weak"),
        "risk_levels": dict(Counter(r["risk_level"] for r in all_rules)),
        "flag_counts": dict(Counter(f for r in all_rules for f in r["flags"])),
        "duplicate_pattern_groups": len(dup_patterns),
        "duplicate_pattern_rules": sum(x["count"] for x in dup_patterns),
        "duplicate_msg_groups": len(dup_msgs),
    }
    data = {
        "summary": summary,
        "per_category": dict(sorted(per_category.items(), key=lambda x: -x[1]["count"])),
        "top_risky_rules": risky_out,
        "duplicate_patterns_top": dup_patterns[:30],
        "duplicate_msgs_top": dup_msgs[:30],
        "scenario_suricata": scenario,
        "zeek_scripts": zeek_info,
        "xbits_rules": {
            "analysis": json.load(open(ROOT.parent / "xbits/rules/analysis.json", encoding="utf-8")),
            "default": json.load(open(ROOT.parent / "xbits/rules/default.json", encoding="utf-8")),
        },
    }
    out = ROOT / "docs" / "规则质量QA数据.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    print("top risky:")
    for r in risky_out[:10]:
        print(r["sid"], r["risk_level"], r["risk_score"], r["flags"], r["msg"][:80])
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())