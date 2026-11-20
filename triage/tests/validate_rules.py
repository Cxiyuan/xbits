#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 triage/rules 下所有 YARA 规则可编译，并对已知样本做 命中/不命中 断言。

默认要求 yara-python 必须存在：缺失 → 返回 2（不允许"没装就当通过"的静默跳过，
见 qa/QA_REPORT.md V-19）。确需在无 yara 的环境手动跑，可显式加
`--allow-missing-yara`（会把跳过原因打到 stdout，CI 不传这个开关）。

编译校验之外还做一对语义断言（只验"能编译"曾让坏规则一路绿灯）：
  * 正例：一段已知 PHP webshell 字节必须命中 `webshell_php_eval_superglobal`；
  * 负例：一段良性文本不得命中任何规则。
"""
import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-missing-yara",
        action="store_true",
        help="允许在未安装 yara-python 时跳过（默认不允许；CI 不传）",
    )
    args = parser.parse_args()

    try:
        import yara  # type: ignore
    except Exception:
        if args.allow_missing_yara:
            print("::warning:: yara-python not installed; YARA validation SKIPPED by explicit --allow-missing-yara")
            return 0
        print(
            "FAIL: yara-python not installed — YARA 规则校验不能静默跳过；"
            "CI 必须先 pip install yara-python（或显式加 --allow-missing-yara）",
            file=sys.stderr,
        )
        return 2

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))
    total = bad = 0
    compiled = []
    for dp, _dirs, fnames in os.walk(root):
        for f in sorted(fnames):
            if not (f.endswith(".yar") or f.endswith(".yara")):
                continue
            total += 1
            p = os.path.join(dp, f)
            rule = None
            try:
                rule = yara.compile(filepath=p)
            except Exception as exc:
                # 非 ASCII 路径（如中文目录）下 C 库打不开文件：读字节 source 编译回退
                try:
                    with open(p, "rb") as fh:
                        rule = yara.compile(source=fh.read().decode("utf-8", "replace"))
                except Exception as exc2:
                    bad += 1
                    print(f"FAIL {p}: {exc} / {exc2}")
            if rule is not None:
                compiled.append((p, rule))

    failures = list()
    if total == 0:
        failures.append(f"no rule files found under {root}")

    # ---- 语义断言对：正例必须命中，负例不得命中 ----
    php_webshell = b"<?php\n@eval($_POST['cmd']);\nsystem($_GET['x']);\n?>\n"
    benign = b"weekly report\nall good\nwindow 42\n"
    positive_hits = set()
    negative_hits = set()
    for path, rule in compiled:
        try:
            positive_hits.update(m.rule for m in rule.match(data=php_webshell))
        except Exception as exc:  # pragma: no cover - 运行期匹配失败同样是缺陷
            failures.append(f"match() failed for {path}: {exc}")
        try:
            negative_hits.update(m.rule for m in rule.match(data=benign))
        except Exception as exc:  # pragma: no cover
            failures.append(f"match() failed for {path}: {exc}")

    if "webshell_php_eval_superglobal" not in positive_hits:
        failures.append(
            "positive sample did not hit webshell_php_eval_superglobal; "
            f"hits={sorted(positive_hits)}"
        )
    if negative_hits:
        failures.append(f"benign sample must not match any rule; hits={sorted(negative_hits)}")

    print(f"validated {total} rule files, {bad} bad")
    print(f"positive hits: {sorted(positive_hits)}")
    print(f"negative hits: {sorted(negative_hits)}")
    if bad:
        failures.append(f"{bad} rule files failed to compile")

    if failures:
        print("\nYARA RULES: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print("YARA RULES: PASS (all compile; positive sample hits, benign sample clean)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
