# ============================================================================
# acunetix.sig —— acunetix 扫描工具 UA 指纹（Zeek Signature，词边界已加固）
# 类别: commercial   来源: 原 Suricata 侦察规则 SID 9101007
# 层级: Tier A（工具独有 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature acunetix_ua {
    ip-proto == tcp
    tcp-state originator
    payload /(.|\r|\n)*User-Agent:.*[^A-Za-z0-9]Acunetix([^A-Za-z0-9]|$)/
    event "scanner_ua_acunetix"
}

# Acunetix 专用请求头（SID 9101110）
signature acunetix_header {
    ip-proto == tcp
    tcp-state originator
    payload /(.|\r|\n)*Acunetix-(Aspect|Product)/
    event "scanner_hdr_acunetix"
}
