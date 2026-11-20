#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""threat-intel 采集器：按 sources.json 拉取公开情报，规范化后写入 data/，并导出引擎消费文件。

产出（均在模块目录下）：
  data/md5.txt|sha1.txt|sha256.txt|ip.txt|domain.txt   规范化数据（纯行，一行一条）
  data/file_hash.txt                                    全部文件哈希合并（triage 直接消费）
  data/meta.json                                        采集时间/计数/来源统计（溯源）
  exports/suricata/iprep.list + iprep-categories.txt    Suricata IP 信誉
  exports/suricata/datasets/{md5,sha1,sha256,domain}.txt Suricata dataset 数据文件
  local/*.txt                                           自有情报（采集不覆盖，始终合并）

用法：
  python3 threat-intel/tools/collect.py                        # 全量刷新
  python3 threat-intel/tools/collect.py --since 2025-01-01     # 只取该日期后的 CIRCL 事件
  python3 threat-intel/tools/collect.py --domain-max 20000     # 域名上限

说明：需联网环境执行；CI 不自动跑（由部署方定期刷新）。仅采集 IOC 元数据，
不下载样本、不上传数据。请遵守各源 License/ToU（见 sources.json）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(MODULE_ROOT, "data")
LOCAL_DIR = os.path.join(MODULE_ROOT, "local")
EXPORT_SURICATA = os.path.join(MODULE_ROOT, "exports", "suricata")
UA = "xbits-threat-intel-collector/2.0"

RX_HEX = re.compile(r"^[0-9a-fA-F]+$")
RX_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
HASH_TYPES = {"md5": 32, "sha1": 40, "sha256": 64}
MISP_HASH_TYPES = {"md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"}
MISP_NET_KEEP = {"ip-dst": "ip", "ip-src": "ip", "domain": "domain", "hostname": "domain"}


def http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def new_store() -> dict:
    return {"md5": set(), "sha1": set(), "sha256": set(), "ip": set(), "domain": set()}


def add_hash(store: dict, value: str, algo: str) -> bool:
    v = value.strip().lower()
    if len(v) == HASH_TYPES[algo] and RX_HEX.match(v):
        store[algo].add(v)
        return True
    return False


def add_ip(store: dict, value: str) -> bool:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    store["ip"].add(v.lower())
    return True


def add_domain(store: dict, value: str) -> bool:
    v = value.strip().lower().lstrip(".")
    if v and RX_DOMAIN.match(v):
        store["domain"].add(v)
        return True
    return False


# ---------------- 源解析器（新源在此注册） ----------------

def src_circl_misp_feed(src: dict, store: dict, stat: dict, args) -> None:
    base = src["url_base"]
    opts = src.get("options", {})
    try:
        manifest = json.loads(http_get(base + "manifest.json").decode("utf-8", "replace"))
    except Exception as exc:
        print(f"[WARN] {src['name']} manifest 获取失败：{exc}")
        return
    items = []
    for uuid, meta in manifest.items():
        date = str(meta.get("date", ""))
        tags = " ".join(t.get("name", "") for t in (meta.get("Tag") or []))
        info = str(meta.get("info", ""))
        if opts.get("malware_only", True) and not (
                "malware" in tags.lower() or "malicious-code" in tags.lower() or "malware" in info.lower()):
            continue
        if args.since and date and date < args.since:
            continue
        items.append((date, uuid))
    items.sort(reverse=True)
    items = items[: opts.get("max_events", 500)]
    print(f"[{src['name']}] 选中 {len(items)} 个事件（并发抓取）")

    def fetch(uuid: str):
        try:
            return json.loads(http_get(base + uuid + ".json").decode("utf-8", "replace"))
        except Exception:
            return None

    events = []
    with ThreadPoolExecutor(max_workers=opts.get("workers", 12)) as ex:
        futs = [ex.submit(fetch, u) for _d, u in items]
        for fut in as_completed(futs):
            ev = fut.result()
            if ev:
                events.append(ev)

    n_hash = n_net = 0
    for event in events:
        ev = event.get("Event", {})
        attrs = list(ev.get("Attribute", []) or [])
        for obj in ev.get("Object", []) or []:
            attrs.extend(obj.get("Attribute", []) or [])
        for a in attrs:
            if a.get("deleted") or not a.get("to_ids"):
                continue
            t = str(a.get("type", ""))
            v = str(a.get("value", "")).strip()
            if not v:
                continue
            if t in MISP_HASH_TYPES:
                algo = t.split("|")[-1]
                if add_hash(store, v, algo):
                    n_hash += 1
            elif t in MISP_NET_KEEP:
                kind = MISP_NET_KEEP[t]
                ok = add_ip(store, v) if kind == "ip" else add_domain(store, v)
                if ok:
                    n_net += 1
    stat[src["name"]] = {"events": len(events), "attrs_hash": n_hash, "attrs_net": n_net}


def src_abusech_iplist(src: dict, store: dict, stat: dict, args) -> None:
    try:
        text = http_get(src["url"]).decode("utf-8", "replace")
    except Exception as exc:
        print(f"[WARN] {src['name']} 获取失败：{exc}")
        return
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if add_ip(store, line):
            n += 1
    stat[src["name"]] = {"ips": n}


def src_abusech_api(src: dict, store: dict, stat: dict, args) -> None:
    print(f"[SKIP] {src['name']}：需要 Auth-Key（{src.get('options', {}).get('auth_key_env', '')}），尚未实现解析器")


COLLECT_SOURCES = {
    "circl-misp-feed": src_circl_misp_feed,
    "abusech-iplist": src_abusech_iplist,
    "abusech-api": src_abusech_api,
}


# ---------------- local/ 自有情报合并 ----------------

def merge_local(store: dict, stat: dict) -> None:
    n = 0
    for name in ("md5", "sha1", "sha256", "ip", "domain"):
        p = os.path.join(LOCAL_DIR, name + ".txt")
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                v = line.strip().split("#")[0].strip()
                if not v:
                    continue
                ok = (add_ip(store, v) if name == "ip"
                      else add_domain(store, v) if name == "domain"
                      else add_hash(store, v, name))
                if ok:
                    n += 1
    stat["local"] = {"entries": n}


# ---------------- 写出 ----------------

def write_lines(path: str, lines: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for x in lines:
            fh.write(x + "\n")


def write_outputs(store: dict, stat: dict, args, now: str) -> None:
    domain_list = sorted(store["domain"])[: args.domain_max]
    md5_list = sorted(store["md5"])
    sha1_list = sorted(store["sha1"])
    sha256_list = sorted(store["sha256"])
    ip_list = sorted(store["ip"])

    write_lines(os.path.join(DATA_DIR, "md5.txt"), md5_list)
    write_lines(os.path.join(DATA_DIR, "sha1.txt"), sha1_list)
    write_lines(os.path.join(DATA_DIR, "sha256.txt"), sha256_list)
    write_lines(os.path.join(DATA_DIR, "ip.txt"), ip_list)
    write_lines(os.path.join(DATA_DIR, "domain.txt"), domain_list)
    write_lines(os.path.join(DATA_DIR, "file_hash.txt"), md5_list + sha1_list + sha256_list)

    # Suricata 导出
    write_lines(os.path.join(EXPORT_SURICATA, "iprep.list"), [f"{ip},1,100" for ip in ip_list])
    write_lines(os.path.join(EXPORT_SURICATA, "iprep-categories.txt"), ["1,ti-malicious"])
    write_lines(os.path.join(EXPORT_SURICATA, "datasets", "md5.txt"), md5_list)
    write_lines(os.path.join(EXPORT_SURICATA, "datasets", "sha1.txt"), sha1_list)
    write_lines(os.path.join(EXPORT_SURICATA, "datasets", "sha256.txt"), sha256_list)
    write_lines(os.path.join(EXPORT_SURICATA, "datasets", "domain.txt"), domain_list)

    meta = {
        "collected_utc": now,
        "counts": {"md5": len(md5_list), "sha1": len(sha1_list), "sha256": len(sha256_list),
                   "file_hash_total": len(md5_list) + len(sha1_list) + len(sha256_list),
                   "ip": len(ip_list), "domain": len(domain_list),
                   "domain_collected": len(store["domain"]), "domain_cap": args.domain_max},
        "sources": stat,
        "data_schema": {"md5.txt": "一行一个 32 位 md5", "sha1.txt": "一行一个 40 位 sha1",
                        "sha256.txt": "一行一个 64 位 sha256", "ip.txt": "一行一个 IPv4/IPv6",
                        "domain.txt": "一行一个小写域名", "file_hash.txt": "md5+sha1+sha256 合并"},
        "consumers": {"triage": "data/file_hash.txt（默认加载）",
                      "suricata": "exports/suricata/（iprep + datasets，见其 README）"},
    }
    with open(os.path.join(DATA_DIR, "meta.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default=os.path.join(MODULE_ROOT, "sources.json"))
    ap.add_argument("--since", default=None, help="YYYY-MM-DD，仅取该日期之后的事件（对支持的源生效）")
    ap.add_argument("--domain-max", type=int, default=50000, help="域名输出上限（DGA 噪声大）")
    args = ap.parse_args()

    with open(args.sources, encoding="utf-8") as fh:
        cfg = json.load(fh)

    store = new_store()
    stat: dict = {}
    for src in cfg.get("sources", []):
        if not src.get("enabled"):
            print(f"[SKIP] {src['name']}：disabled")
            continue
        fn = COLLECT_SOURCES.get(src.get("type"))
        if fn is None:
            print(f"[WARN] {src['name']}：未知 type {src.get('type')}")
            continue
        fn(src, store, stat, args)
    merge_local(store, stat)

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    write_outputs(store, stat, args, now)

    m = {}
    for k in ("md5", "sha1", "sha256", "ip", "domain"):
        m[k] = len(store[k])
    print(f"[DONE] {now} md5={m['md5']} sha1={m['sha1']} sha256={m['sha256']} ip={m['ip']} domain={m['domain']}")
    print(f"[DONE] -> {DATA_DIR} 与 {EXPORT_SURICATA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
