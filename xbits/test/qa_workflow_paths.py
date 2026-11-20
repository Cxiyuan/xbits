#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CI 触发路径一致性门禁（纯静态元测试，stdlib only）。

背景（qa/QA_REPORT.md V-16 / S-01 / TS-01）：
`.github/workflows/*.yml` 的 `paths:` 触发面与 QA 脚本实际读取的仓库资源，是两份
互相独立、手工维护的清单。新增根目录（triage/、threat-intel/、allowlist/）时没人
回头补 `paths:`，结果就是「改了被测代码，CI 一次都不跑」的结构性假绿。

本脚本的不变量（都是「每个 workflow 自己对自己」）：

1. **自覆盖**：workflow W 的文本 + 它调用的脚本 / Dockerfile（最多向下追 3 层）里
   出现的每个仓库相对路径，都必须被 **W 自己的** `push.paths` 覆盖。被别的
   workflow 覆盖不算——那正是 V-16 的成因（`测试用例/cases.json` 被场景 workflow
   监听，但读它的 `xbits-images` 门禁不会启动）。
2. **事件一致**：同一 workflow 的 `push.paths` 与 `pull_request.paths` 必须是同一
   集合（只在一侧加 = 另一半永远不会被验证）。
3. **动态目录补盲**：脚本用变量拼出来、字面量扫描看不见的数据目录，由
   `REQUIRED_DIR_ROOTS` 显式列出并要求被覆盖。

刻意不做的事（避免制造新的假绿）：
- 不联网、不依赖 PyYAML、不执行任何测试/构建；
- 不检查生成物目录（`xbits/target/`、`测试用例/web_pcap/` 等）——源头是
  `generate_*.py` / `gen_pcaps.py`，已由 `paths:` 覆盖；
- 不检查绝对路径（`/tmp/...`）；
- 扫描不到「变量拼接」得出的路径，故只对 `REQUIRED_DIR_ROOTS` 兜底。

退出码：0 = 通过；1 = 有未覆盖资源 / 事件不一致；2 = 解析失败（文件里存在
`paths:` 却解析不到条目时不允许静默通过）。
"""
from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
SELF = Path(__file__).resolve()

# 生成物目录 / 非输入目录：不进 paths（源头已被覆盖，或本身不是 QA 输入）。
IGNORED_PREFIXES = (
    "xbits/target/",
    "docker/stage/",
    "app-id/tests/pcaps/",
    "app-id/tests/manifest.json",
    "测试用例/pcap/",
    "测试用例/recon_pcap/",
    "测试用例/web_pcap/",
    "测试用例/backdoor_pcap/",
    "测试用例/out/",
    "测试用例/stage/",
    "测试用例/zeek_out/",
    "测试用例/xbits_run/",
    "qa/",            # 审计/交接文档，不是 QA 脚本的输入
    ".agent-teams/",
    ".git/",
)

# 动态解析的数据目录：脚本用变量拼接路径，字面量扫描看不见，必须显式列出。
REQUIRED_DIR_ROOTS = (
    ("triage/rules", "triage 默认 YARA 规则目录（triage.py 内 <script_dir>/rules）"),
    ("threat-intel/data", "triage 默认 hash 情报与 xbits --threat-intel-dir 数据目录"),
    ("allowlist/data", "xbits --allowlist-dir 默认查询目录"),
)

SCAN_SUFFIX = (".py", ".sh", ".yml", ".yaml")
MAX_SCAN_DEPTH = 3


def is_scannable(path: Path) -> bool:
    """可继续向下追读的文本文件：脚本/配置 + Dockerfile（镜像层的输入）。"""
    return (
        path.suffix in SCAN_SUFFIX
        or path.name.startswith("Dockerfile")
        or path.name.endswith(".Dockerfile")
    )

EVENT_LINE = re.compile(r"^  (push|pull_request):\s*$")
ITEM_LINE = re.compile(r"^(\s+)-\s*(.+?)\s*$")
# ROOT / "a" / "b" / "c"（最多 4 段，单/双引号都支持）
JOIN_SEQ_DQ = re.compile(
    r'"([^"\n]{1,80})"\s*/\s*"([^"\n]{1,80})"'
    r'(?:\s*/\s*"([^"\n]{1,80})")?(?:\s*/\s*"([^"\n]{1,80})")?'
)
JOIN_SEQ_SQ = re.compile(
    r"'([^'\n]{1,80})'\s*/\s*'([^'\n]{1,80})'"
    r"(?:\s*/\s*'([^'\n]{1,80})')?(?:\s*/\s*'([^'\n]{1,80})')?"
)
TOKEN = re.compile(r"""[^\s"'`;,|&<>()\[\]{}]+""")
# 只接受路径字符（\w 在 Python3 下含中文）：拒绝把 markdown 粗体 `**`、中文标点
# 等散文残留混进路径（例：注释里的 `threat-intel/data/file_hash.txt**。这样`）。
PATH_CHARS = re.compile(r"^[\w.\-/*?\[\]]+$")
ENV_PREFIXES = (
    "${GITHUB_WORKSPACE}/",
    "$GITHUB_WORKSPACE/",
    "${{ github.workspace }}/",
    "$PWD/",
    "./",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_event_paths(text: str) -> dict[str, list[str]]:
    """解析 `on.<event>.paths`，只关心 push / pull_request。"""
    events: dict[str, list[str]] = {}
    cur: str | None = None
    in_paths = False
    paths_indent = 0
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        event = EVENT_LINE.match(raw)
        if event:
            cur = event.group(1)
            in_paths = False
            events.setdefault(cur, [])
            continue
        if cur is not None:
            flow = re.match(r"^\s*paths:\s*\[(.*)\]\s*$", raw)
            if flow:
                events[cur].extend(
                    item.strip().strip("\"'") for item in flow.group(1).split(",") if item.strip()
                )
                continue
        if cur is not None and stripped == "paths:":
            in_paths = True
            paths_indent = indent
            continue
        if in_paths:
            item = ITEM_LINE.match(raw)
            if item and len(item.group(1)) > paths_indent:
                events[cur].append(item.group(2).strip().strip('"\''))
                continue
            if indent <= paths_indent:
                in_paths = False
    return {k: v for k, v in events.items() if k in ("push", "pull_request")}


def normalize(token: str) -> str | None:
    """把文本 token 归一成仓库相对路径；无法判定为路径时返回 None。"""
    tok = token.strip().strip("\"'`;,)(")
    if not tok or tok.startswith(("-", "#", "//")):
        return None
    for prefix in ENV_PREFIXES:
        if tok.startswith(prefix):
            tok = tok[len(prefix):]
            break
    if tok.startswith(("/", "$", "~", "\\")):
        return None
    if "=" in tok:  # --rules=xbits/rules/default.json
        tok = tok.split("=", 1)[1]
    if ":" in tok:
        return None
    if any(ch in tok for ch in "{}<>|$`\\"):
        return None
    if not PATH_CHARS.match(tok):
        return None
    # 通配符：保留通配形式（与 paths 里同样的 glob 精确比对，如 `dir/*.lua`）
    if any(ch in tok for ch in "*?[]"):
        head = re.split(r"[*?\[]", tok, maxsplit=1)[0].rstrip("/")
        if "/" not in head:
            return None
        return tok
    tok = tok.rstrip("/").rstrip(".")
    # 只要求「嵌套路径」：裸的顶层目录名（常出现在散文里，如 "(triage/, stdlib path)"）
    # 不当作资源；顶层目录的覆盖由 REQUIRED_DIR_ROOTS 与内部嵌套路径共同保证。
    return tok if "/" in tok else None


def join_sequences(text: str) -> set[str]:
    out: set[str] = set()
    for regex in (JOIN_SEQ_DQ, JOIN_SEQ_SQ):
        for groups in regex.findall(text):
            parts = [g for g in groups if g]
            if parts:
                out.add("/".join(parts))
    return out


def scan_literals(text: str) -> set[str]:
    found = join_sequences(text)
    found.update(TOKEN.findall(text))
    out: set[str] = set()
    for token in found:
        norm = normalize(token)
        if norm:
            out.add(norm)
    return out


def resolve_repo_path(rel: str) -> Path | None:
    base = re.split(r"[*?\[]", rel, maxsplit=1)[0].rstrip("/")
    path = ROOT / (base if base else rel)
    try:
        return path if path.exists() else None
    except OSError:
        return None


def is_ignored(rel: str) -> bool:
    base = re.split(r"[*?\[]", rel, maxsplit=1)[0].rstrip("/")
    candidates = {rel, base}
    return any(
        cand == p.rstrip("/") or cand.startswith(p) for cand in candidates for p in IGNORED_PREFIXES
    )


def entry_covers(entry: str, rel: str) -> bool:
    entry = entry.rstrip("/")
    if any(ch in rel for ch in "*?["):
        if fnmatch.fnmatchcase(rel, entry):
            return True
        base = re.split(r"[*?\[]", rel, maxsplit=1)[0].rstrip("/")
        return bool(base) and entry_covers(entry, base)
    if entry.endswith("/**"):
        base = entry[:-3].rstrip("/")
        return rel == base or rel.startswith(base + "/")
    if any(ch in entry for ch in "*?["):
        return fnmatch.fnmatchcase(rel, entry)
    return rel == entry or rel.startswith(entry + "/")


def parse_all_workflows() -> tuple[dict[str, dict[str, list[str]]], list[str], list[str]]:
    """返回 (workflows, 解析失败, 一致性失败)。解析失败 → 退出码 2，不一致 → 1。"""
    workflows: dict[str, dict[str, list[str]]] = {}
    parse_failures: list[str] = []
    consistency_failures: list[str] = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        text = read_text(path)
        events = parse_event_paths(text)
        if "paths:" in text:
            for event in ("push", "pull_request"):
                if not events.get(event):
                    parse_failures.append(
                        f"{path.name}: 文件里有 `paths:` 但 `on.{event}.paths` 解析为空"
                        "（解析器可能失效，拒绝静默通过）"
                    )
            if events.get("push") and events.get("pull_request"):
                only_push = sorted(set(events["push"]) - set(events["pull_request"]))
                only_pr = sorted(set(events["pull_request"]) - set(events["push"]))
                if only_push or only_pr:
                    consistency_failures.append(
                        f"{path.name}: push 与 pull_request 的 paths 不一致"
                        f"（only-push={only_push} only-pr={only_pr}）"
                    )
        workflows[path.name] = events
    return workflows, parse_failures, consistency_failures


def collect_resources(workflow_text: str) -> dict[str, set[str]]:
    """workflow 自己读取的仓库路径 → 引用它的一层来源（workflow / 脚本）。"""
    resources: dict[str, set[str]] = {}

    def record(rel: str, source: str) -> None:
        if is_ignored(rel) or resolve_repo_path(rel) is None:
            return
        resources.setdefault(rel, set()).add(source)

    def expand(text: str, source: str, depth: int, seen: set[Path]) -> None:
        for rel in scan_literals(text):
            if is_ignored(rel):
                continue
            path = resolve_repo_path(rel)
            if path is None:
                continue
            record(rel, source)
            if (
                depth < MAX_SCAN_DEPTH
                and path.is_file()
                and is_scannable(path)
                and path != SELF
                and path not in seen
            ):
                seen.add(path)
                expand(read_text(path), str(path.relative_to(ROOT)).replace("\\", "/"), depth + 1, seen)

    expand(workflow_text, "<workflow>", 0, set())
    return resources


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    workflows, parse_failures, failures = parse_all_workflows()
    if not workflows:
        print("FAIL: .github/workflows 下没有找到任何 workflow", file=sys.stderr)
        return 2
    if parse_failures:
        print("\nFAIL: workflow 解析失败（拒绝静默通过）：", file=sys.stderr)
        for item in parse_failures:
            print(f"  - {item}", file=sys.stderr)
        return 2

    print("== workflow paths 自覆盖检查 ==")
    total_resources = 0
    for name in sorted(workflows):
        events = workflows[name]
        paths = events.get("push") or []
        text = read_text(WORKFLOW_DIR / name)
        resources = collect_resources(text)
        total_resources += len(resources)
        uncovered = sorted(
            rel for rel in resources if not any(entry_covers(entry, rel) for entry in paths)
        )
        status = "OK" if not uncovered else f"UNCOVERED {len(uncovered)}"
        print(
            f"  {name}: push={len(paths)} pull_request={len(events.get('pull_request') or [])} "
            f"resources={len(resources)} -> {status}"
        )
        for rel in uncovered:
            sources = ", ".join(sorted(resources[rel]))
            failures.append(f"{name}: 读取 {rel}（引用: {sources}）但该 workflow 的 paths 未覆盖")

    # 动态数据目录补盲（至少被一个 workflow 覆盖）
    all_entries = [
        entry for events in workflows.values() for paths in events.values() for entry in paths
    ]
    for root, why in REQUIRED_DIR_ROOTS:
        if not (ROOT / root).is_dir():
            failures.append(f"{root}: 目录不存在（{why}）")
        elif not any(entry_covers(entry, root) for entry in all_entries):
            failures.append(f"{root}: 无任何 workflow paths 覆盖（{why}）")

    print(f"  合计被读仓库路径: {total_resources} 个；paths 条目: {len(all_entries)} 个")

    if failures:
        print("\nFAIL: CI 触发面与 QA 脚本实际读取的资源不一致：", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\n修复方向：在该 workflow 自己的 push/pull_request `paths:` 里补上该资源"
            "（精确到子目录，不要加全仓 `**`），并保持 push 与 pull_request 一致。",
            file=sys.stderr,
        )
        return 1

    print("\nCI PATHS: PASS (each workflow's paths cover every repo path it reads)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
