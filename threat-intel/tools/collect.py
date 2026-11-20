#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""threat-intel 采集器：按 sources.json 拉取公开情报，规范化后写入 data/，并导出引擎消费文件。

产出（均在模块目录下）：
  data/md5.txt|sha1.txt|sha256.txt|ip.txt|domain.txt   规范化数据（纯行，一行一条）
  data/file_hash.txt                                    全部文件哈希合并（triage 直接消费）
  data/meta.json                                        最近一次**成功**采集的元数据（溯源）
  exports/suricata/iprep.list + iprep-categories.txt    Suricata IP 信誉
  exports/suricata/datasets/{md5,sha1,sha256,domain}.txt Suricata dataset 数据文件
  local/*.txt                                           自有情报（采集不覆盖，始终合并）
  collect_last_attempt.json                             最近一次尝试（含失败）的结构化记录

V-21 失败可见契约：
  * 每个 enabled 源返回 SourceResult{ok, fetched, http_code, error, last_success_utc}；
    任一源失败 → 非零退出、**不触碰** data/ 与 exports/（旧快照完好），失败详情写
    collect_last_attempt.json（其中 sources[name]={status:"failed", error:…}），
    data/meta.json 的 last_success_utc 保持上次成功值不变。
  * 全部源成功且各自产出 ≥ 最小阈值 → 先写同盘临时目录、逐字段校验，再 os.replace
    逐文件原子替换；meta.json 的 last_success_utc 仅在成功快照写入时更新。
  * enabled 且 type 未实现 / options 含未知键 → 计为失败并非零退出。

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
import shutil
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(MODULE_ROOT, "data")
LOCAL_DIR = os.path.join(MODULE_ROOT, "local")
EXPORT_SURICATA = os.path.join(MODULE_ROOT, "exports", "suricata")
ATTEMPT_PATH = os.path.join(MODULE_ROOT, "collect_last_attempt.json")
UA = "xbits-threat-intel-collector/3.0"

RX_HEX = re.compile(r"^[0-9a-fA-F]+$")
RX_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
HASH_TYPES = {"md5": 32, "sha1": 40, "sha256": 64}
MISP_HASH_TYPES = {"md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"}
MISP_NET_KEEP = {"ip-dst": "ip", "ip-src": "ip", "domain": "domain", "hostname": "domain"}

# 最小产出阈值（每源在 sources.json 的 options.min_fetched 可覆盖）。
# 依据（2026-11-19 快照）：circl md5=2408 / sha256=3204 / ip+domain=30 万+；
# feodo ipblocklist_recommended 正常为几十条（当前仓内仅 1 条即被 QA 判为假成功）。
# 因此 1000/10 是保守下限：低于该量级基本等于抓取失败/被限流/返回错误页，
# 宁可非零退出保留旧快照，也不用残缺数据覆盖生产情报。
DEFAULT_MIN_FETCHED = 100
MIN_FETCHED_BY_TYPE = {"circl-misp-feed": 1000, "abusech-iplist": 10, "abusech-api": 10}

# 每类解析器允许的 options 键；未知键一律报错（配置驱动，不允许"装饰品"选项）。
KNOWN_OPTIONS = {
    "circl-misp-feed": {"max_events", "malware_only", "to_ids", "workers", "min_fetched"},
    "abusech-iplist": {"min_fetched"},
    "abusech-api": {"auth_key_env", "min_fetched"},
}


class FetchError(Exception):
    """HTTP/网络失败；http_code 为 None 表示非 HTTP 错误（超时、DNS 等）。"""

    def __init__(self, message: str, http_code: int | None = None):
        super().__init__(message)
        self.http_code = http_code


@dataclass
class SourceResult:
    """单源采集结果（V-21 契约）。fetched = 本源新增的有效 IOC 条数。"""

    ok: bool
    fetched: int = 0
    http_code: int | None = None
    error: str | None = None
    last_success_utc: str | None = None
    detail: dict = field(default_factory=dict)

    def to_meta(self) -> dict:
        return {
            "status": "ok" if self.ok else "failed",
            "ok": self.ok,
            "fetched": self.fetched,
            "http_code": self.http_code,
            "error": self.error,
            "last_success_utc": self.last_success_utc,
            **self.detail,
        }


def http_get_with_code(url: str, timeout: int = 20) -> tuple[bytes, int]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), int(getattr(r, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} for {url}", int(exc.code)) from exc
    except FetchError:
        raise
    except Exception as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}", None) from exc


def http_get(url: str, timeout: int = 20) -> bytes:
    data, _code = http_get_with_code(url, timeout)
    return data


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


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


# ---------------- 源解析器（新源在此注册；返回 SourceResult，不再写 stat） ----------------

def src_circl_misp_feed(src: dict, store: dict, args, getter) -> SourceResult:
    base = src["url_base"]
    opts = src.get("options", {})
    to_ids = opts.get("to_ids", True)
    if not isinstance(to_ids, bool):
        return SourceResult(False, error="options.to_ids 必须是 true/false", http_code=None)
    code: int | None = None
    try:
        raw, code = getter(base + "manifest.json")
        manifest = json.loads(raw.decode("utf-8", "replace"))
    except FetchError as exc:
        return SourceResult(False, error=str(exc), http_code=exc.http_code)
    except Exception as exc:
        return SourceResult(False, error=f"manifest 解析失败：{exc}", http_code=code)

    items = []
    for uuid, meta in manifest.items():
        date = str(meta.get("date", ""))
        tags = " ".join(t.get("name", "") for t in (meta.get("Tag") or []))
        info = str(meta.get("info", ""))
        if opts.get("malware_only", True) and not (
                "malware" in tags.lower() or "malicious-code" in tags.lower() or "malware" in info.lower()):
            continue
        if getattr(args, "since", None) and date and date < args.since:
            continue
        items.append((date, uuid))
    items.sort(reverse=True)
    items = items[: opts.get("max_events", 500)]
    print(f"[{src['name']}] 选中 {len(items)} 个事件（并发抓取）")

    def fetch(uuid: str):
        try:
            return getter(base + uuid + ".json")
        except FetchError as exc:
            return exc

    events = []
    failed_events = 0
    with ThreadPoolExecutor(max_workers=opts.get("workers", 12)) as ex:
        futs = [ex.submit(fetch, u) for _d, u in items]
        for fut in as_completed(futs):
            res = fut.result()
            if isinstance(res, FetchError):
                failed_events += 1
                continue
            raw_ev, _ = res
            try:
                events.append(json.loads(raw_ev.decode("utf-8", "replace")))
            except Exception:
                failed_events += 1

    before = (len(store["md5"]), len(store["sha1"]), len(store["sha256"]),
              len(store["ip"]), len(store["domain"]))
    n_hash = n_net = 0
    for event in events:
        ev = event.get("Event", {})
        attrs = list(ev.get("Attribute", []) or [])
        for obj in ev.get("Object", []) or []:
            attrs.extend(obj.get("Attribute", []) or [])
        for a in attrs:
            if a.get("deleted") or (to_ids and not a.get("to_ids")):
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
                if add_ip(store, v) if kind == "ip" else add_domain(store, v):
                    n_net += 1
    after = (len(store["md5"]), len(store["sha1"]), len(store["sha256"]),
             len(store["ip"]), len(store["domain"]))
    fetched = sum(b - a for a, b in zip(before, after))
    return SourceResult(
        ok=fetched > 0,
        fetched=fetched,
        http_code=code,
        error=None if fetched > 0 else "manifest 有事件但无任何有效 IOC（可能被限流或返回错误页）",
        detail={"events": len(events), "events_failed": failed_events,
                "attrs_hash_new": n_hash, "attrs_net_new": n_net, "to_ids": to_ids},
    )


def src_abusech_iplist(src: dict, store: dict, args, getter) -> SourceResult:
    try:
        raw, code = getter(src["url"])
    except FetchError as exc:
        return SourceResult(False, error=str(exc), http_code=exc.http_code)
    n = 0
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if add_ip(store, line):
            n += 1
    return SourceResult(ok=n > 0, fetched=n, http_code=code,
                        error=None if n > 0 else "iplist 无有效 IP（可能被限流或返回错误页）")


COLLECT_SOURCES = {
    "circl-misp-feed": src_circl_misp_feed,
    "abusech-iplist": src_abusech_iplist,
}


# ---------------- local/ 自有情报合并 ----------------

def merge_local(store: dict, local_dir: str = LOCAL_DIR) -> dict:
    n = 0
    for name in ("md5", "sha1", "sha256", "ip", "domain"):
        p = os.path.join(local_dir, name + ".txt")
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
    return {"entries": n}


# ---------------- 候选快照写入与校验（同盘临时目录 → 逐文件 os.replace） ----------------

DATA_FILES = ("md5.txt", "sha1.txt", "sha256.txt", "ip.txt", "domain.txt", "file_hash.txt")
SURI_FILES = ("iprep.list", "iprep-categories.txt",
              "datasets/md5.txt", "datasets/sha1.txt", "datasets/sha256.txt", "datasets/domain.txt")


def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for x in lines:
            fh.write(x + "\n")


def snapshot_payloads(store: dict, args, meta: dict) -> dict[str, list[str] | str]:
    domain_list = sorted(store["domain"])[: getattr(args, "domain_max", 50000)]
    md5_list = sorted(store["md5"])
    sha1_list = sorted(store["sha1"])
    sha256_list = sorted(store["sha256"])
    ip_list = sorted(store["ip"])
    return {
        "data/md5.txt": md5_list,
        "data/sha1.txt": sha1_list,
        "data/sha256.txt": sha256_list,
        "data/ip.txt": ip_list,
        "data/domain.txt": domain_list,
        "data/file_hash.txt": md5_list + sha1_list + sha256_list,
        "data/meta.json": json.dumps(meta, ensure_ascii=False, indent=2),
        "suri/iprep.list": [f"{ip},1,100" for ip in ip_list],
        "suri/iprep-categories.txt": ["1,ti-malicious"],
        "suri/datasets/md5.txt": md5_list,
        "suri/datasets/sha1.txt": sha1_list,
        "suri/datasets/sha256.txt": sha256_list,
        "suri/datasets/domain.txt": domain_list,
    }


def validate_snapshot(stage: str, payloads: dict) -> list[str]:
    """替换前在临时目录上做逐文件校验；失败即整体放弃，不触碰目标。"""
    errors: list[str] = []
    for rel, expected in payloads.items():
        p = os.path.join(stage, rel)
        if not os.path.isfile(p):
            errors.append(f"临时文件缺失 {rel}")
            continue
        if rel.endswith(".json"):
            try:
                with open(p, encoding="utf-8") as fh:
                    json.load(fh)
            except Exception as exc:
                errors.append(f"meta.json 非法：{exc}")
        else:
            with open(p, encoding="utf-8", errors="replace") as fh:
                content = fh.read().splitlines()
            if len(content) != len(expected):
                errors.append(f"{rel} 行数 {len(content)} != 预期 {len(expected)}")
    meta_path = os.path.join(stage, "data", "meta.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            counts = meta.get("counts", {})
            for key, rel in (("md5", "data/md5.txt"), ("sha1", "data/sha1.txt"),
                             ("sha256", "data/sha256.txt"), ("ip", "data/ip.txt"),
                             ("domain", "data/domain.txt")):
                p = os.path.join(stage, rel)
                with open(p, encoding="utf-8", errors="replace") as fh:
                    actual = len(fh.read().splitlines())
                if counts.get(key) != actual:
                    errors.append(f"meta.counts.{key}={counts.get(key)} 与 {rel} 实际 {actual} 不符")
        except Exception as exc:
            errors.append(f"meta 计数核对失败：{exc}")
    return errors


def _copy_existing(src_root: str, dst_root: str, rel_files: list[str]) -> None:
    for rel in rel_files:
        src = os.path.join(src_root, rel)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(dst_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)


def atomic_write_snapshot(payloads: dict, meta: dict, args,
                          data_dir: str = DATA_DIR, suri_dir: str = EXPORT_SURICATA) -> None:
    """先写同盘临时目录并校验，再逐文件 os.replace；失败时从备份回滚，目标目录保持原样。

    临时目录与目标目录同级（同一文件系统），os.replace 为原子操作。
    备份目录仅用于替换阶段中途失败的回滚；校验未过时在任何 os.replace 之前就放弃，
    现有 data/exports 完全不被触碰。
    """
    pid = os.getpid()
    # 临时目录必须与目标同盘（os.replace 跨盘会失败）；取两个目标的公共父目录。
    common_parent = os.path.commonpath([os.path.abspath(data_dir), os.path.abspath(suri_dir)])
    stage = os.path.join(common_parent, f".collect-stage-{pid}")
    data_tmp = os.path.join(stage, "data")
    suri_tmp = os.path.join(stage, "suri")
    data_bak = os.path.join(stage, "data.bak")
    suri_bak = os.path.join(stage, "suri.bak")
    if os.path.exists(stage):
        shutil.rmtree(stage)
    try:
        for rel, content in payloads.items():
            _write_lines(os.path.join(stage, rel),
                         content if isinstance(content, list) else [content.rstrip("\n")])

        problems = validate_snapshot(stage, payloads)
        if problems:
            raise RuntimeError("快照校验失败：\n  " + "\n  ".join(problems))

        data_rel = [rel[len("data/"):] for rel in payloads if rel.startswith("data/")]
        suri_rel = [rel[len("suri/"):] for rel in payloads if rel.startswith("suri/")]
        _copy_existing(data_dir, data_bak, data_rel)
        _copy_existing(suri_dir, suri_bak, suri_rel)

        try:
            for rel in data_rel:
                os.makedirs(os.path.dirname(os.path.join(data_dir, rel)), exist_ok=True)
                os.replace(os.path.join(data_tmp, rel), os.path.join(data_dir, rel))
            for rel in suri_rel:
                os.makedirs(os.path.dirname(os.path.join(suri_dir, rel)), exist_ok=True)
                os.replace(os.path.join(suri_tmp, rel), os.path.join(suri_dir, rel))
        except Exception as exc:
            # 替换阶段中途失败：用备份把目标目录恢复原状（原本不存在的文件则删除）
            restored = 0
            for rel, target_root, bak_root in (
                *[(r, data_dir, data_bak) for r in data_rel],
                *[(r, suri_dir, suri_bak) for r in suri_rel],
            ):
                target = os.path.join(target_root, rel)
                backup = os.path.join(bak_root, rel)
                try:
                    if os.path.isfile(backup):
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        os.replace(backup, target)
                    elif os.path.isfile(target):
                        os.remove(target)
                    restored += 1
                except OSError:
                    pass
            raise RuntimeError(f"原子替换中途失败，已从备份回滚（{restored} 个文件）：{exc}") from exc
    finally:
        if os.path.exists(stage):
            shutil.rmtree(stage, ignore_errors=True)


def write_attempt_record(record: dict, path: str = ATTEMPT_PATH) -> None:
    """单次尝试记录（无论成功/失败）原子落盘，不经过 data/ 目录。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------- 主流程 ----------------

def load_prior_meta(data_dir: str) -> dict:
    p = os.path.join(data_dir, "meta.json")
    if not os.path.isfile(p):
        return {}
    try:
        with open(p, encoding="utf-8") as fh:
            loaded = json.load(fh)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def build_meta(store: dict, args, collected: str, last_success: str,
               sources: dict, local_stat: dict) -> dict:
    md5_list = sorted(store["md5"])
    sha1_list = sorted(store["sha1"])
    sha256_list = sorted(store["sha256"])
    domain_list = sorted(store["domain"])[: getattr(args, "domain_max", 50000)]
    return {
        "collected_utc": collected,
        "last_success_utc": last_success,
        "counts": {"md5": len(md5_list), "sha1": len(sha1_list), "sha256": len(sha256_list),
                   "file_hash_total": len(md5_list) + len(sha1_list) + len(sha256_list),
                   "ip": len(store["ip"]), "domain": len(domain_list),
                   "domain_collected": len(store["domain"]), "domain_cap": getattr(args, "domain_max", 50000)},
        "sources": {**sources, "local": {"status": "ok", "entries": local_stat["entries"]}},
        "data_schema": {"md5.txt": "一行一个 32 位 md5", "sha1.txt": "一行一个 40 位 sha1",
                        "sha256.txt": "一行一个 64 位 sha256", "ip.txt": "一行一个 IPv4/IPv6",
                        "domain.txt": "一行一个小写域名", "file_hash.txt": "md5+sha1+sha256 合并"},
        "consumers": {"triage": "data/file_hash.txt（默认加载）",
                      "suricata": "exports/suricata/（iprep + datasets，见其 README）"},
    }


def collect_once(cfg: dict, args, *,
                 getter=http_get_with_code,
                 data_dir: str = DATA_DIR,
                 suri_dir: str = EXPORT_SURICATA,
                 local_dir: str = LOCAL_DIR,
                 attempt_path: str = ATTEMPT_PATH,
                 now: str | None = None) -> int:
    """返回 0=成功写快照；非 0=失败（旧 data/exports 未被触碰）。"""
    now = now or now_utc()
    prior = load_prior_meta(data_dir)
    prior_sources = prior.get("sources", {}) if isinstance(prior.get("sources"), dict) else {}
    prior_last_success = prior.get("last_success_utc") or prior.get("collected_utc")
    store = new_store()
    reports: dict[str, dict] = {}
    enabled = 0
    successes = 0

    for src in cfg.get("sources", []):
        name = str(src.get("name", "?"))
        stype = str(src.get("type", ""))
        if not src.get("enabled"):
            reports[name] = {"status": "disabled"}
            continue
        enabled += 1
        prior_time = (prior_sources.get(name, {}) or {}).get("last_success_utc") or prior_last_success
        opts = src.get("options", {}) or {}
        unknown = sorted(set(opts) - KNOWN_OPTIONS.get(stype, set()))
        if unknown:
            reports[name] = SourceResult(False, error=f"options 未知键：{unknown}",
                                         last_success_utc=prior_time).to_meta()
            print(f"[FAIL] {name}: options 未知键 {unknown}", file=sys.stderr)
            continue
        min_fetched = opts.get("min_fetched", MIN_FETCHED_BY_TYPE.get(stype, DEFAULT_MIN_FETCHED))
        if not isinstance(min_fetched, int) or min_fetched < 1:
            reports[name] = SourceResult(False, error="options.min_fetched 必须为正整数",
                                         last_success_utc=prior_time).to_meta()
            continue
        fn = COLLECT_SOURCES.get(stype)
        if fn is None:
            reports[name] = SourceResult(
                False, error=f"unimplemented source type: {stype!r}（enabled=true 但无解析器）",
                last_success_utc=prior_time).to_meta()
            print(f"[FAIL] {name}: 未实现的 type {stype!r}", file=sys.stderr)
            continue
        try:
            result = fn(src, store, args, getter)
        except Exception as exc:
            result = SourceResult(False, error=f"解析器异常：{type(exc).__name__}: {exc}")
        if result.ok and result.fetched < min_fetched:
            result = SourceResult(False, fetched=result.fetched, http_code=result.http_code,
                                  error=f"产出 {result.fetched} < 最小阈值 {min_fetched}"
                                        f"（{stype} 正常量级见 MIN_FETCHED_BY_TYPE 注释）",
                                  detail=result.detail)
        result.last_success_utc = now if result.ok else prior_time
        reports[name] = result.to_meta()
        if result.ok:
            successes += 1
            print(f"[OK] {name}: fetched={result.fetched} http={result.http_code}")
        else:
            print(f"[FAIL] {name}: {result.error}", file=sys.stderr)

    local_stat = merge_local(store, local_dir)
    failed = [n for n, r in reports.items() if r.get("status") == "failed"]
    ok = enabled > 0 and successes == enabled and not failed
    attempt = {
        "attempt_utc": now,
        "status": "success" if ok else "failed",
        "last_success_utc": now if ok else prior_last_success,
        "sources": reports,
        "failed_sources": failed,
        "note": "失败尝试只写本文件；data/meta.json 与 exports 保持上次成功快照不变"
                if not ok else "成功快照已原子替换 data/ 与 exports/",
    }
    if not ok:
        write_attempt_record(attempt, attempt_path)
        print(f"[ABORT] {len(failed)}/{enabled} 个源失败；旧快照未改动，失败详情 -> {attempt_path}",
              file=sys.stderr)
        return 1

    meta = build_meta(store, args, now, now, reports, local_stat)
    payloads = snapshot_payloads(store, args, meta)
    try:
        atomic_write_snapshot(payloads, meta, args, data_dir=data_dir, suri_dir=suri_dir)
    except Exception as exc:
        attempt["status"] = "failed"
        attempt["failed_sources"] = ["<write>"]
        attempt["error"] = str(exc)
        attempt["note"] = "写入/替换阶段失败，已回滚；data/ 与 exports/ 保持原样"
        write_attempt_record(attempt, attempt_path)
        print(f"[ABORT] 写入失败：{exc}", file=sys.stderr)
        return 2
    write_attempt_record(attempt, attempt_path)
    m = {k: len(store[k]) for k in ("md5", "sha1", "sha256", "ip", "domain")}
    print(f"[DONE] {now} md5={m['md5']} sha1={m['sha1']} sha256={m['sha256']} ip={m['ip']} domain={m['domain']}")
    print(f"[DONE] -> {data_dir} 与 {suri_dir}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default=os.path.join(MODULE_ROOT, "sources.json"))
    ap.add_argument("--since", default=None, help="YYYY-MM-DD，仅取该日期之后的事件（对支持的源生效）")
    ap.add_argument("--domain-max", type=int, default=50000, help="域名输出上限（DGA 噪声大）")
    args = ap.parse_args()

    with open(args.sources, encoding="utf-8") as fh:
        cfg = json.load(fh)
    return collect_once(cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())
