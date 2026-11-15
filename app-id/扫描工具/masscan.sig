# ============================================================================
# masscan.sig —— masscan 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: masscan   来源: 原 Suricata 侦察规则 SID 9101011
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature masscan_ua {
    ip-proto == tcp
    tcp-state originator
    payload /(.|\r|\n)*User-Agent: masscan\//
    event "scanner_ua_masscan"
}
