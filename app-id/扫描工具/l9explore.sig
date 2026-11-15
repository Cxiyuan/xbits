# ============================================================================
# l9explore.sig —— l9explore 扫描工具 UA 指纹（Zeek Signature）
# 类别: measurement   来源: 原 Suricata 侦察规则 SID 9101027（User-Agent 特征）
# 层级: Tier A（工具独有 UA 字面；命中即可判该工具，最终由 scan.zeek 统一聚合）
# 目标: Zeek 9.0.1
# ============================================================================

signature l9explore_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent:.*l9explore/
    event "scanner_ua_l9explore"
}
