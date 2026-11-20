#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""allowlist 刷新器：按 sources.json 把 custom/ 源归一化为 data/ 快照。

设计（V-22 语义分离，与 threat-intel 对称）：
  sources.json —— 唯一真源：每条声明 name/type/enabled/path/output/kind/options
  custom/      —— 手工白名单（tools/add.py 增删；refresh 永不覆盖）
  data/        —— 生成物：domain.txt / ip.txt / public_dns.txt + meta.json

语义隔离（V-22 根治）：
  * ip.txt        只来自 sources.json 中 output=ip.txt 的源（通常是 custom/ip.txt）；
  * public_dns.txt 只由 custom/public_dns_servers.txt **单向派生**；
  * 禁止 public_dns_servers.txt 反向并入 ip.txt；写出前断言两集合交集为空，
    非空即 FAIL（不再出现"ip.txt 与 public_dns.txt 逐行相同"的假成功）。

用法：
  python3 allowlist/tools/refresh.py                       # 按 sources.json 重建 data/
  python3 allowlist/tools/refresh.py --check               # 计算 custom/ 结果并与 data/ 逐项比对
  python3 allowlist/tools/refresh.py --sources <file>      # 指定另份源清单
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ipnorm import canonical_ip  # noqa: E402

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOM_DIR = os.path.join(MODULE_ROOT, "custom")
DATA_DIR = os.path.join(MODULE_ROOT, "data")
SOURCES_PATH = os.path.join(MODULE_ROOT, "sources.json")

RX_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# 已实现的源类型 → 归一语义。sources.json 出现表外 type 一律报错（配置是唯一真源）。
SUPPORTED_TYPES = {
    "static-domain-list": "domain",
    "static-ip-list": "ip",
}
OUTPUT_FILES = ("domain.txt", "ip.txt", "public_dns.txt")
KNOWN_OPTIONS: dict[str, set[str]] = {
    "static-domain-list": set(),
    "static-ip-list": set(),
}


def norm_domain(v: str) -> str | None:
    v = v.strip().lower().lstrip(".")
    return v if v and RX_DOMAIN.match(v) else None


def norm_ip(v: str) -> str | None:
    # V-23：与 add.py/query.py 共用 canonical_ip（IPv6 规范压缩式；zone 拒绝）
    return canonical_ip(v)


def read_custom(fname: str, kind: str, custom_dir: str | None = None) -> tuple[list, list]:
    path = os.path.join(custom_dir or CUSTOM_DIR, fname)
    if not os.path.isfile(path):
        return [], []
    out, bad = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln, line in enumerate(fh, 1):
            v = line.strip().split("#")[0].strip()
            if not v:
                continue
            nv = norm_domain(v) if kind == "domain" else norm_ip(v)
            if nv is None:
                bad.append(f"{fname}:{ln}: {v}")
            else:
                out.append(nv)
    return out, bad


def load_sources(path: str | None = None) -> list[dict]:
    """读取并校验 sources.json，返回 enabled 源列表；未知 type/非法映射直接抛 ValueError。"""
    p = path or SOURCES_PATH
    with open(p, encoding="utf-8") as fh:
        cfg = json.load(fh)
    entries: list[dict] = []
    for raw in cfg.get("sources", []):
        name = str(raw.get("name", "?"))
        if not raw.get("enabled"):
            continue
        stype = str(raw.get("type", ""))
        if stype not in SUPPORTED_TYPES:
            raise ValueError(f"源 {name}: 未知 type {stype!r}（已实现: {sorted(SUPPORTED_TYPES)}）")
        kind = str(raw.get("kind", ""))
        if kind != SUPPORTED_TYPES[stype]:
            raise ValueError(f"源 {name}: kind={kind!r} 与 type={stype!r} 不一致")
        output = str(raw.get("output", ""))
        if output not in OUTPUT_FILES:
            raise ValueError(f"源 {name}: output={output!r} 非法（允许: {list(OUTPUT_FILES)}）")
        rel = os.path.normpath(str(raw.get("path", ""))).replace("\\", "/")
        if rel.startswith("..") or not rel.startswith("custom/"):
            raise ValueError(f"源 {name}: path={rel!r} 必须位于 custom/ 下")
        base = os.path.basename(rel)
        if output == "public_dns.txt" and base != "public_dns_servers.txt":
            raise ValueError(f"源 {name}: public_dns.txt 只允许来自 custom/public_dns_servers.txt（当前 {rel}）")
        if output == "ip.txt" and base == "public_dns_servers.txt":
            raise ValueError(f"源 {name}: 禁止 public_dns_servers.txt 反向并入 ip.txt")
        opts = raw.get("options", {}) or {}
        unknown = sorted(set(opts) - KNOWN_OPTIONS.get(stype, set()))
        if unknown:
            raise ValueError(f"源 {name}: options 未知键 {unknown}")
        entries.append({"name": name, "type": stype, "kind": kind,
                        "path": rel, "base": base, "output": output})
    if not entries:
        raise ValueError("sources.json 无 enabled 源")
    return entries


def build_outputs(entries: list[dict], custom_dir: str | None = None) -> tuple[dict, list[dict], list[str]]:
    """从 sources.json 声明的源构建各输出集合；返回 (outputs, source_map, bad)。

    声明为 enabled 的源其 `path` 文件必须存在——缺失即配置不完整（bad），
    避免"源声明了但文件没了，静默当空"造成快照与声明不一致。
    """
    base_dir = custom_dir or CUSTOM_DIR
    buckets: dict[str, list[str]] = {out: [] for out in OUTPUT_FILES}
    source_map: list[dict] = []
    bad: list[str] = []
    for e in entries:
        p = os.path.join(base_dir, e["base"])
        if not os.path.isfile(p):
            bad.append(f"sources.json 声明的源文件缺失：{e['path']}（源 {e['name']}）；"
                       f"请补建该文件（可为空文件）或从 sources.json 移除/禁用")
            continue
        vals, errs = read_custom(e["base"], e["kind"], custom_dir=base_dir)
        bad.extend(errs)
        buckets[e["output"]].extend(vals)
        source_map.append({"source": e["name"], "from": e["path"], "to": e["output"],
                           "entries": len(vals), "file_present": True})
    outputs = {out: sorted(set(vals)) for out, vals in buckets.items()}

    # 语义正交断言：ip.txt 与 public_dns.txt 不得有交集（V-22 核心）。
    overlap = set(outputs["ip.txt"]) & set(outputs["public_dns.txt"])
    if overlap:
        bad.append(f"语义冲突：ip.txt 与 public_dns.txt 交集 {len(overlap)} 条："
                   + ", ".join(sorted(overlap)[:10]))
    return outputs, source_map, bad


def expected_counts(outputs: dict) -> dict:
    # meta.counts 沿用历史键名（domain/ip/public_dns，不带 .txt），兼容既有消费方。
    return {name[:-4]: len(outputs[name]) for name in OUTPUT_FILES}


def check_snapshot(outputs: dict, data_dir: str | None = None) -> list[str]:
    """custom/ 归一化结果与 data/ 快照逐项比对，返回差异描述（空=一致）。"""
    root = data_dir or DATA_DIR
    diffs: list[str] = []
    for name in OUTPUT_FILES:
        p = os.path.join(root, name)
        actual: set[str] = set()
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    v = line.strip().split("#")[0].strip()
                    if v:
                        actual.add(norm_ip(v) if name in ("ip.txt", "public_dns.txt") else norm_domain(v) or v)
        expected = set(outputs[name])
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing or extra:
            diffs.append(f"{name}: 缺少 {len(missing)} 条 / 多余 {len(extra)} 条")
            if missing:
                diffs.append(f"  缺少: {', '.join(missing[:6])}" + (" …" if len(missing) > 6 else ""))
            if extra:
                diffs.append(f"  多余: {', '.join(extra[:6])}" + (" …" if len(extra) > 6 else ""))
    meta_path = os.path.join(root, "meta.json")
    if not os.path.isfile(meta_path):
        diffs.append("meta.json 缺失")
    else:
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            for key, val in expected_counts(outputs).items():
                if meta.get("counts", {}).get(key) != val:
                    diffs.append(f"meta.counts.{key}={meta.get('counts', {}).get(key)} != custom 推导 {val}")
            if not isinstance(meta.get("source_map"), list):
                diffs.append("meta.source_map 缺失（V-22 来源文件→输出文件映射）")
        except Exception as exc:
            diffs.append(f"meta.json 解析失败：{exc}")
    return diffs


def write_snapshot(outputs: dict, source_map: list[dict], data_dir: str | None = None) -> str:
    """同盘临时文件 + os.replace 写入 3 个名单与 meta.json（失败不留下半份快照）。"""
    root = data_dir or DATA_DIR
    os.makedirs(root, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    meta = {
        "refreshed_utc": now,
        "counts": expected_counts(outputs),
        "source_map": source_map,
        "semantics": {
            "domain.txt": "业务/通用白域名（小写后缀，支持子域名匹配）",
            "ip.txt": "通用 IP 白名单（只来自 sources.json output=ip.txt 的源；不含公共 DNS）",
            "public_dns.txt": "DNS 行为基线（单向派生自 custom/public_dns_servers.txt；不反向并入 ip.txt）",
        },
        "layers": ["custom/（手工，不覆盖）", "sources.json（唯一真源）"],
        "consumers": ["xbits（--allowlist-dir）", "tools/query.py"],
    }
    staged: list[tuple[str, str]] = []
    try:
        for name in OUTPUT_FILES:
            tmp = os.path.join(root, f".{name}.tmp-{os.getpid()}")
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                for x in outputs[name]:
                    fh.write(x + "\n")
            staged.append((tmp, os.path.join(root, name)))
        tmp_meta = os.path.join(root, f".meta.json.tmp-{os.getpid()}")
        with open(tmp_meta, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=2)
        staged.append((tmp_meta, os.path.join(root, "meta.json")))
        for src, dst in staged:
            os.replace(src, dst)
    finally:
        for src, _dst in staged:
            if os.path.exists(src):
                os.remove(src)
    return now


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只比对 custom/ 与 data/，不写 data/")
    ap.add_argument("--sources", default=SOURCES_PATH, help="源清单路径")
    ap.add_argument("--custom-dir", default=CUSTOM_DIR, help="custom/ 目录")
    ap.add_argument("--data-dir", default=DATA_DIR, help="data/ 快照目录")
    args = ap.parse_args(argv)

    try:
        entries = load_sources(args.sources)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[FAIL] sources.json 配置错误：{exc}", file=sys.stderr)
        return 2
    outputs, source_map, bad = build_outputs(entries, custom_dir=args.custom_dir)
    if bad:
        print("[FAIL] custom/ 校验失败：")
        for b in bad:
            print("   ", b)
        return 1

    if args.check:
        diffs = check_snapshot(outputs, data_dir=args.data_dir)
        if diffs:
            print("[FAIL] custom/ 与 data/ 快照不一致：")
            for d in diffs:
                print("   ", d)
            return 1
        print(f"[OK] custom 与 data 一致："
              + " ".join(f"{k}={v}" for k, v in expected_counts(outputs).items()))
        return 0

    now = write_snapshot(outputs, source_map, data_dir=args.data_dir)
    print(f"[DONE] {now} " + " ".join(f"{k}={v}" for k, v in expected_counts(outputs).items())
          + f" -> {args.data_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
