# ============================================================================
# shodan.sig —— shodan 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: measurement   来源: 原 Suricata 侦察规则 SID 9101024
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature shodan_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent:.*Shodan\//
    event "scanner_ua_shodan"
}
