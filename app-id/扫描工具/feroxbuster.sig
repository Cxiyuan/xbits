# ============================================================================
# feroxbuster.sig —— feroxbuster 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: dirbrute   来源: 原 Suricata 侦察规则 SID 9101003
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature feroxbuster_ua {
    ip-proto == tcp
    tcp-state originator
    payload /[\x09\x0a\x0d\x20-\x7e]*User-Agent: feroxbuster\//
    event "scanner_ua_feroxbuster"
}
