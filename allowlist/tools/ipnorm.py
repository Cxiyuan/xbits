# -*- coding: utf-8 -*-
"""allowlist 共享工具：IP 归一化的单一实现（V-23）。

历史问题：add.py 用 `str(ipaddress.ip_address(...))`（IPv6 压缩式）、
refresh.py 用 `exploded.lower()`（IPv6 展开式）、query.py 原文小写比较——
三套归一化互不相容，导致 IPv6 白名单条目在查询端永不命中。

规范（本模块 `canonical_ip()`，三处共用，xbits Rust 侧同语义）：
  * 合法 IPv4/IPv6 → ipaddress 标准字符串（str()），统一小写；
      - IPv4  原样十进制（"8.8.8.8"）
      - IPv6  规范压缩式（"2001:db8::1"），全零段压缩、字母小写
  * 带.scope zone id（fe80::1%eth0）→ 拒绝（返回 None）：白名单按地址匹配，
    zone 属于链路本地语义，落盘会产生两条"同址不同名"条目
  * 非法输入 → None（调用方按各自语义处理：add.py SKIP，refresh.py 记 bad 行）
"""
from __future__ import annotations

import ipaddress


def canonical_ip(value: str) -> str | None:
    """把任意合法 IP 字符串归一为规范表示；非法（含 zone id）返回 None。"""
    v = (value or "").strip()
    if not v or "%" in v:
        return None
    try:
        return str(ipaddress.ip_address(v)).lower()
    except ValueError:
        return None
