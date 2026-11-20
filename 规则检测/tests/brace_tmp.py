#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时检查：Rust 文件括号配平（剔除字符串/注释/char literal）。只读。"""
from __future__ import annotations

import re
import sys
from pathlib import Path

for arg in sys.argv[1:]:
    text = Path(arg).read_text(encoding="utf-8")
    s = re.sub(r"//[^\n]*", "", text)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r'r?"(?:[^"\\]|\\.)*"', "Q", s)
    s = re.sub(r"'(?:[^'\\]|\\.)'", "Q", s)
    print(arg, "open", s.count("{"), "close", s.count("}"))
