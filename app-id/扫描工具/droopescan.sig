# ============================================================================
# droopescan.sig —— droopescan 扫描工具 UA 指纹（Zeek Signature，品牌词词边界）
# 类别: cms   形式: word   置信: 中（UA 版本/大小写需实测校准；主要为漏报风险）
# 层级: Tier A（品牌 UA 字面；B+ 下可"字面自证"）
# 目标: Zeek 9.0.1
# ============================================================================

signature droopescan_ua {
    ip-proto == tcp
    tcp-state originator
    payload /User-Agent:.*[^A-Za-z0-9]Droopescan([^A-Za-z0-9]|$)/
    event "scanner_ua_droopescan"
}
