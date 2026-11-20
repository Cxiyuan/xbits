#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 triage/rules 下所有 YARA 规则可编译（确保 triage 可用）。

未安装 yara-python 时跳过（返回 0），安装后强制执行校验。
"""
import os
import sys

def main() -> int:
    try:
        import yara  # type: ignore
    except Exception:
        print("yara-python not installed; skip YARA validation")
        return 0
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))
    total = bad = 0
    for dp, _dirs, fnames in os.walk(root):
        for f in sorted(fnames):
            if not (f.endswith(".yar") or f.endswith(".yara")):
                continue
            total += 1
            p = os.path.join(dp, f)
            try:
                yara.compile(filepath=p)
            except Exception as exc:
                # 非 ASCII 路径（如中文目录）下 C 库打不开文件：读字节 source 编译回退
                try:
                    with open(p, "rb") as fh:
                        yara.compile(source=fh.read().decode("utf-8", "replace"))
                except Exception as exc2:
                    bad += 1
                    print(f"FAIL {p}: {exc} / {exc2}")
    print(f"validated {total} rule files, {bad} bad")
    return 1 if bad else 0

if __name__ == "__main__":
    raise SystemExit(main())
