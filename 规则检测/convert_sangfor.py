#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor (深信服) 探针规则导出 → xbits 项目规则转换器。

输入：桌面 `流量检测规则` 导出目录（已解密的明文规则）。
输出（按消费源归档，见 docs/规则归档与转换方案.md）：
  规则检测/suricata/sangfor/*.rules          强规则（sf_snort/WAF/PVS/UTM）
  规则检测/suricata/sangfor/weak/*.rules      弱/泛化规则（低置信度，交 xbits 收敛）
  规则检测/suricata/sangfor/success/*.rules   PVS 成功确认规则（flowbits 门控）
  规则检测/xbits/sangfor/rules_meta.json     每条规则元数据（depend/scope/holetype/tier）
  规则检测/xbits/sangfor/success_rules.json  PVS 成功确认依赖（中央引擎联动）
  规则检测/xbits/sangfor/audit_rules.json    云审计规则（仅元数据）
  规则检测/xbits/sangfor/sid_library.json    SID → 名称/类别/危险等级映射
  规则检测/xbits/sangfor/exceptions.json     例外/强 SID 列表
  docker/sangfor-validate.yaml               Suricata 加载验证配置（生成）

转换原则：
  * 只取 etc_fw（现网生效）；lib_* 基线库跳过（SID 重复）；
  * Sangfor 私有关键字（ruletype/holetype-id/scope_id/depend/depended/action）
    从 Suricata 规则剥离，保留到 rules_meta.json 给 xbits；
  * uricontent → content + http_uri；
  * <> 双向操作符 → ->（Suricata 不支持 <>）；
  * classtype 全部剥离（类别语义走 xbits sid_library；
    未知 classtype 会导致 Suricata 拒绝加载）；
  * mail_uri / cloud audit 规则不进 Suricata；
  * PVS depend/scope 语义 → Suricata flowbits 门控：
      被依赖的请求规则追加 flowbits:set,xb_dep_<sid>；
      带 depend/scope 的响应规则追加 flowbits:isset,xb_dep_<主依赖>；
      无任何依赖的成功确认规则不进 Suricata（避免 200 OK 泛匹配噪声）。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_SURICATA = ROOT / "suricata" / "sangfor"
OUT_XBITS = ROOT / "xbits" / "sangfor"

# Suricata 转换源（现网 etc_fw）
SURICATA_SOURCES = [
    ("sf_snort", "etc_fw/sf_snort/rules/*.rules"),
    ("waf", "etc_fw/waf/rules/*.rules"),
    ("waf", "etc_fw/waf/webshell_rules/*.rules"),
    ("waf", "etc_fw/waf/cmd_executed_rules/*.rules"),
    ("pvs", "etc_fw/pvs/rules/*.rules"),
    ("pvs-success", "etc_fw/pvs/rules/success/*.rules"),
    ("utm", "etc_fw/utm/rules/*.rules"),
]

# 弱/泛化规则：可被 Suricata 加载，但告警价值低，交 xbits 低置信度/联动评分
WEAK_FILES = {
    "gray_keyword.rules",
    "sql.weak.rules",
    "information_disclose.rules",
    "web_scan.rules",
    "malice_url_report.rules",
}

# xbits 元数据源
CLOUD_GLOBS = ["etc_fw/cloudrules/common_rules/report/*.rules"]
META_FILES = {
    "classification": "etc_fw/_top/classification.json",
    "hole_library": "etc_fw/_top/hole_library.ini",
    "strongsid": "etc_fw/_top/ips_strongsid.list",
    "ips_exception": "etc_fw/_top/ips_exception.ini",
    "waf_exception": "etc_fw/_top/waf_exception.ini",
    "waftype": "etc_fw/_top/waftype.ini",
}

STRIP_KWS = [
    re.compile(r"\bruletype\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bholetype-id\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bscope_id\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bdepend\s*:\s*[^;]+;?", re.I),
    re.compile(r"\bdepended\s*:\s*[^;]+;?", re.I),
    re.compile(r"\baction\s*:\s*[^;]*audit[^;]*;?", re.I),
    re.compile(r"\bstatus_code\s*:\s*[^;]+;?", re.I),
]
METHOD_RE = re.compile(r'\bmethod\s*:\s*"([^"]*)"\s*;?', re.I)
# Sangfor 语义/DSL 关键字：Suricata 无法等价执行，交 xbits/Zeek 语义层
DSL_RE = re.compile(r"\b(uriarg|decode|grammar|payload_extract|result)\s*:", re.I)
URICONTENT_RE = re.compile(r'\buricontent\s*:\s*"(.*?)"\s*;', re.I)
URICONTENT_NEG_RE = re.compile(r'\buricontent\s*:\s*!\s*"(.*?)"\s*;', re.I)
MAIL_URI_RE = re.compile(r"\bmail_uri\b", re.I)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)")
HOLETYPE_RE = re.compile(r"\bholetype-id\s*:\s*(\d+)")
DEPEND_RE = re.compile(r"\bdepend\s*:\s*([0-9,\s]+)")
SCOPE_RE = re.compile(r"\bscope_id\s*:\s*([0-9,\s]+)")
RULETYPE_RE = re.compile(r"\bruletype\s*:\s*(\d+)")
DEPENDED_RE = re.compile(r"\bdepended\s*:\s*(\d+)")
MSG_RE = re.compile(r'\bmsg\s*:\s*"(.*?)"\s*;', re.I)


def read_rule_bytes(path: Path) -> bytes | None:
    """读取规则文件；Windows Defender 可能拦截含 WebShell 的文本，用扩展路径规避。"""
    for candidate in (path, Path("\\\\?\\" + str(path))):
        try:
            return candidate.read_bytes()
        except OSError:
            continue
    return None


def iter_rule_lines(path: Path):
    data = read_rule_bytes(path)
    if data is None:
        print(f"WARN: unreadable rule file (skipped): {path}", file=sys.stderr)
        return
    text = data.decode("utf-8", "replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^(alert|log|pass|drop|reject|sdrop)\b", line, re.I):
            continue
        yield line


def extract_meta(line: str) -> dict:
    meta: dict = {}
    m = SID_RE.search(line)
    if m:
        meta["sid"] = int(m.group(1))
    m = MSG_RE.search(line)
    if m:
        meta["msg"] = m.group(1)
    for rx, key in [
        (HOLETYPE_RE, "holetype"),
        (DEPEND_RE, "depends"),
        (SCOPE_RE, "scopes"),
        (RULETYPE_RE, "ruletype"),
        (DEPENDED_RE, "depended"),
        (REV_RE, "rev"),
    ]:
        m = rx.search(line)
        if m:
            if key in ("depends", "scopes"):
                meta[key] = [int(x) for x in m.group(1).split(",") if x.strip()]
            else:
                meta[key] = int(m.group(1))
    return meta


def convert_rule(line: str, flowbit_set: int | None, flowbit_is: int | None) -> str | None:
    """Return cleaned Suricata rule text or None (if unconvertible)."""
    if MAIL_URI_RE.search(line):
        return None
    out = line
    out = re.sub(r"\s+<>\s+", " -> ", out)  # Suricata 不支持双向
    # uricontent!:"X" → content:!"X"; http_uri（否定形式先替换）
    out = URICONTENT_NEG_RE.sub(lambda m: f'content:!"{m.group(1)}"; http_uri;', out)
    out = URICONTENT_RE.sub(lambda m: f'content:"{m.group(1)}"; http_uri;', out)
    out = METHOD_RE.sub(lambda m: f'http_method; content:"{m.group(1)}";', out)
    for rx in STRIP_KWS:
        out = rx.sub("", out)
    # classtype 剥离（未知 classtype 会导致加载失败；语义在 xbits sid_library）
    out = re.sub(r"\bclasstype\s*:\s*[^;]+;?", "", out, flags=re.I)
    # Snort-only 关键字
    out = re.sub(r"\b(?:resp|logto)\s*:\s*[^;]+;?", "", out, flags=re.I)
    # 残留的 uricontent（无引号等怪形态）也剥离，避免 Suricata 拒载
    out = re.sub(r"\buricontent\s*:\s*[^;]+;?", "", out, flags=re.I)

    injections = []
    if flowbit_set is not None:
        injections.append(f"flowbits:set,xb_dep_{flowbit_set}")
    if flowbit_is is not None:
        injections.append(f"flowbits:isset,xb_dep_{flowbit_is}")

    # 规整：折叠 "; )" 与多余空白
    out = out.strip()
    out = re.sub(r";\s+\)", ";)", out)
    out = re.sub(r";\s+", "; ", out)
    out = re.sub(r"\(\s*;", "(", out)
    # 取出选项体（去掉结尾的 ')'），注入字段必须插在 ')' 之前
    body = out[:-1].rstrip() if out.endswith(")") else out
    body = body.rstrip().rstrip(";").rstrip()
    if injections:
        body = body + "; " + "; ".join(injections)
    return body + ";)"


def parse_ini_sections(path: Path):
    sections: dict[str, dict[str, str]] = {}
    cur = None
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            sections[cur] = {}
            continue
        if cur and "=" in line:
            k, v = line.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def parse_hole_library(path: Path) -> dict[int, dict]:
    lib: dict[int, dict] = {}
    for name, kv in parse_ini_sections(path).items():
        if not name.startswith("Hole_Rule_"):
            continue
        if "sid" not in kv or not kv["sid"].isdigit():
            continue
        lib[int(kv["sid"])] = {
            "name": kv.get("name", ""),
            "danger_class": int(kv["danger_class"]) if kv.get("danger_class", "").isdigit() else None,
        }
    return lib


def parse_strongsid(path: Path) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    cur = None
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\[type\]\s*=\s*(\S+)", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        if line.isdigit() and cur:
            out[cur].append(int(line))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="Sangfor 导出目录（流量检测规则）")
    args = parser.parse_args()
    src = Path(args.src)
    if not src.is_dir():
        print(f"missing source dir: {src}", file=sys.stderr)
        return 2

    # 清理旧产物，避免被跳过规则留下的陈旧文件混入
    shutil.rmtree(OUT_SURICATA, ignore_errors=True)
    shutil.rmtree(OUT_XBITS, ignore_errors=True)
    OUT_SURICATA.mkdir(parents=True, exist_ok=True)
    OUT_XBITS.mkdir(parents=True, exist_ok=True)

    # ---- Pass 1: 预扫描 depend/scope，构建反向依赖表 ----
    dep_refs: set[int] = set()  # 被依赖的请求侧 SID
    success_rules: list[dict] = []
    for path in sorted(src.glob("etc_fw/pvs/rules/**/*.rules")):
        rel = path.relative_to(src).as_posix()
        for line in iter_rule_lines(path):
            meta = extract_meta(line)
            sid = meta.get("sid")
            if sid is None:
                continue
            deps = meta.get("depends", []) + meta.get("scopes", [])
            if deps:
                dep_refs.update(deps)
                success_rules.append(
                    {
                        "sid": sid,
                        "msg": meta.get("msg", ""),
                        "depends": meta.get("depends", []),
                        "scopes": meta.get("scopes", []),
                        "holetype": meta.get("holetype"),
                        "source": rel,
                    }
                )

    # ---- Pass 2: Suricata 转换 ----
    rules_meta: dict[str, dict] = {}
    seen_sids: set[int] = set()
    stats: dict[str, dict] = {}
    rule_files: list[tuple[str, int]] = []
    no_dep_success: list[int] = []

    for group, pattern in SURICATA_SOURCES:
        for path in sorted(src.glob(pattern)):
            rel = path.relative_to(src).as_posix()
            tier = "weak" if path.name in WEAK_FILES else "strong"
            subdir = "weak" if tier == "weak" else ("success" if group == "pvs-success" else "")
            out_dir = OUT_SURICATA / subdir if subdir else OUT_SURICATA
            out_dir.mkdir(parents=True, exist_ok=True)
            converted: list[str] = []
            n_ok = n_skip = n_dupe = 0
            for line in iter_rule_lines(path):
                meta = extract_meta(line)
                sid = meta.get("sid")
                if sid is None:
                    n_skip += 1
                    continue
                meta["source"] = rel
                meta["group"] = group
                meta["tier"] = tier
                deps = meta.get("depends", []) + meta.get("scopes", [])
                primary_dep = deps[0] if deps else None

                if MAIL_URI_RE.search(line):
                    meta["skip"] = "mail_uri"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # Sangfor 语义/DSL 规则：Suricata 无法等价执行，只保留元数据
                if DSL_RE.search(line):
                    meta["skip"] = "dsl-semantic"
                    rules_meta[str(sid)] = meta
                    n_skip += 1
                    continue

                # 无依赖的成功确认规则：200 OK 类泛匹配，不进 Suricata
                if group == "pvs-success" and primary_dep is None:
                    meta["skip"] = "no-dependency"
                    rules_meta.setdefault(str(sid), meta)
                    no_dep_success.append(sid)
                    n_skip += 1
                    continue

                if sid in seen_sids:
                    n_dupe += 1
                    continue
                seen_sids.add(sid)
                rules_meta[str(sid)] = meta

                flowbit_set = sid if sid in dep_refs else None
                rule = convert_rule(line, flowbit_set, primary_dep)
                if rule is None:
                    n_skip += 1
                    continue
                converted.append(rule)
                n_ok += 1
            if converted:
                out_name = "sangfor_" + re.sub(r"[^0-9A-Za-z_.-]+", "_", path.stem) + ".rules"
                header = (
                    f"# Converted from Sangfor export: {rel}\n"
                    f"# rules={n_ok} skipped={n_skip} dup_sid={n_dupe}\n"
                )
                (out_dir / out_name).write_text(header + "\n".join(converted) + "\n", encoding="utf-8")
                rel_out = str((out_dir / out_name).relative_to(ROOT)).replace("\\", "/")
                rule_files.append((rel_out, n_ok))
            stats[rel] = {"ok": n_ok, "skip": n_skip, "dupe": n_dupe}

    # ---- 3) 云审计规则 → xbits 元数据 ----
    audit_rules: list[dict] = []
    for pattern in CLOUD_GLOBS:
        for path in sorted(src.glob(pattern)):
            rel = path.relative_to(src).as_posix()
            for line in iter_rule_lines(path):
                meta = extract_meta(line)
                sid = meta.get("sid")
                if sid is None:
                    continue
                audit_rules.append(
                    {"sid": sid, "msg": meta.get("msg", ""), "source": rel}
                )
                rules_meta.setdefault(
                    str(sid), {**meta, "source": rel, "group": "cloud-audit"}
                )

    # ---- 4) SID 库映射 ----
    lib = parse_hole_library(src / META_FILES["hole_library"])
    classification = json.loads((src / META_FILES["classification"]).read_text(encoding="utf-8"))
    waftype = {}
    for k, v in parse_ini_sections(src / META_FILES["waftype"]).get("config", {}).items():
        m = re.match(r"WafType_(\d+)", k)
        if m:
            waftype[int(m.group(1))] = v

    sid_library: dict[str, dict] = {}
    for sid_str, meta in rules_meta.items():
        sid = int(sid_str)
        entry: dict = {"group": meta.get("group", "")}
        if meta.get("tier"):
            entry["tier"] = meta["tier"]
        hole = lib.get(sid)
        if hole:
            entry["name"] = hole["name"]
            if hole["danger_class"] is not None:
                entry["danger_class"] = hole["danger_class"]
        ht = meta.get("holetype")
        if ht is not None:
            entry["holetype"] = ht
            if ht in waftype:
                entry["waftype"] = waftype[ht]
            for engine in ("waf", "pvs", "ips"):
                if str(ht) in classification.get(engine, {}):
                    cat = classification[engine][str(ht)]
                    entry["category"] = cat[0]
                    entry["subcategory"] = cat[1] if len(cat) > 1 else ""
                    break
        if not entry.get("name") and meta.get("msg"):
            entry["name"] = meta["msg"]
        sid_library[sid_str] = entry

    # ---- 5) 例外 / 强 SID ----
    exceptions = {
        "ips_exception": parse_ini_sections(src / META_FILES["ips_exception"]).get("all", {}),
        "waf_exception": parse_ini_sections(src / META_FILES["waf_exception"]).get("all", {}),
        "ips_strongsid": parse_strongsid(src / META_FILES["strongsid"]),
    }

    (OUT_XBITS / "rules_meta.json").write_text(
        json.dumps(rules_meta, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "success_rules.json").write_text(
        json.dumps(success_rules, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "audit_rules.json").write_text(
        json.dumps(audit_rules, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "sid_library.json").write_text(
        json.dumps(sid_library, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    (OUT_XBITS / "exceptions.json").write_text(
        json.dumps(exceptions, ensure_ascii=False, indent=1), encoding="utf-8"
    )

    # ---- 6) Suricata 加载验证配置 ----
    validate_yaml = [
        "%YAML 1.1",
        "---",
        "# Sangfor 转换规则的 Suricata 加载验证配置（由 convert_sangfor.py 生成）",
        "default-log-dir: /tmp/suri-out",
        "",
        "vars:",
        "  address-groups:",
        '    HOME_NET: "any"',
        '    EXTERNAL_NET: "any"',
        '    CLIENT_NET: "any"',
        "  port-groups:",
        '    HTTP_PORTS: "[80,8080,8000,443,8443]"',
        '    MAIL_PORTS: "[25,110,143,587,993,995]"',
        "",
        "default-rule-path: /opt/xbits/rules/suricata/sangfor",
        "rule-files:",
    ]
    for rel_out, _n in rule_files:
        name = rel_out.rsplit("/", 1)[-1]
        subdir = ""
        if "/weak/" in rel_out:
            subdir = "weak/"
        elif "/success/" in rel_out:
            subdir = "success/"
        validate_yaml.append(f"  - {subdir}{name}")
    validate_yaml += [
        "",
        "classification-file: /opt/xbits/rules/classification.config",
        "reference-config-file: /opt/xbits/rules/reference.config",
        "",
        "# 仅做规则加载验证：不启用插件/事件输出",
        "outputs:",
        "  - eve-log:",
        "      enabled: no",
        "",
    ]
    docker_dir = ROOT.parent / "docker"
    docker_dir.mkdir(exist_ok=True)
    (docker_dir / "sangfor-validate.yaml").write_text("\n".join(validate_yaml), encoding="utf-8")

    total_ok = sum(v["ok"] for v in stats.values())
    total_skip = sum(v["skip"] for v in stats.values())
    total_dupe = sum(v["dupe"] for v in stats.values())
    print(f"suricata rules written: {total_ok} (skipped={total_skip}, dup_sid={total_dupe})")
    print(f"pvs success rules (with deps): {len(success_rules)}; no-dep skipped: {len(no_dep_success)}")
    print(f"cloud audit rules: {len(audit_rules)}")
    print(f"sid meta entries: {len(rules_meta)}; sid library entries: {len(sid_library)}")
    print(f"flowbit-gated request sids: {len(dep_refs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
