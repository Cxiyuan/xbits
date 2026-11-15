# ============================================================================
# l9explore.sig —— l9explore 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: measurement   来源: 原 Suricata 侦察规则 SID 9101027
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature l9explore_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent:.*[^A-Za-z0-9]l9explore([^A-Za-z0-9]|$)/
    event "scanner_ua_l9explore"
}
