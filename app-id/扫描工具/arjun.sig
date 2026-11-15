# ============================================================================
# arjun.sig —— arjun 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: param   来源: 原 Suricata 侦察规则 SID 9101020
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature arjun_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent: Arjun\//
    event "scanner_ua_arjun"
}
