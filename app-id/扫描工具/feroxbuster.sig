# ============================================================================
# feroxbuster.sig —— feroxbuster 扫描工具 UA 指纹（Zeek Signature）
# 类别: dirbrute   来源: 原 Suricata 侦察规则 SID 9101003（User-Agent 特征）
# 层级: Tier A（工具独有 UA 字面；命中即可判该工具，最终由 scan.zeek 统一聚合）
# 目标: Zeek 9.0.1
# ============================================================================

signature feroxbuster_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent: feroxbuster\//
    event "scanner_ua_feroxbuster"
}
