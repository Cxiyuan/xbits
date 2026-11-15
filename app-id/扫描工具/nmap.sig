# ============================================================================
# nmap.sig —— Nmap 探针 DPI 签名（Zeek Signature Framework）
# 目录：app-id/扫描工具/
# 用法：@load-sigs ./nmap.sig（见同目录 __load__.zeek）
#
# 分层（依据 app-id/docs/nmap-dpi.md）：
#   Tier A：Nmap 固有字面/指纹，命中即可判定 Nmap（高精确、近零误报）
#   Tier B：强线索，必须由 appid/nmap.zeek 组合（多探针 / 扫描行为）后才判 Nmap
#   Tier C：弱线索，仅记录证据，禁止单独判定
#
# 说明：
#   - 本文件只放"纯 ASCII 且可稳定锚定"的探针；TLS JA3、DNS version.bind、
#     GenericLines(\r\n\r\n)、HELP/EHLO、扫描行为 等由 appid/nmap.zeek 处理。
#   - 目标 Zeek 9.0.1；regex 转义/`\r\n` 支持需按 9.0.1 校验（本版刻意不含裸 CRLF，
#     以保证可加载；精确 CRLF 锚定作为后续增强）。
# ============================================================================

# ---------------------------- Tier A（直判） ----------------------------

# FourOhFourRequest 探针：GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
signature nmap_fourohfour_request {
    ip-proto == tcp
    tcp-state originator
    payload /GET \/nice%20ports%2C\/Tri%6Eity\.txt%2ebak HTTP\/1\.0/
    event "nmap_tierA_fourohfour"
}

# RDP 探测自带 Cookie: mstshash=nmap
signature nmap_terminal_server_cookie {
    ip-proto == tcp
    tcp-state originator
    payload /(.|\r|\n)*Cookie: mstshash=nmap/
    event "nmap_tierA_mstshash"
}

# NSE 默认 User-Agent（nselib/http.lua）
signature nmap_nse_user_agent {
    ip-proto == tcp
    tcp-state originator
    payload /(.|\r|\n)*User-Agent: Mozilla\/5\.0 \(compatible; Nmap Scripting Engine; https:\/\/nmap\.org\/book\/nse\.html\)/
    event "nmap_tierA_nse_ua"
}

# SIP 探测（占位串 sip:nm 为 Nmap 特征）
signature nmap_sip_nm {
    ip-proto == tcp
    tcp-state originator
    payload /OPTIONS sip:nm SIP\/2\.0/
    event "nmap_tierA_sip_nm"
}

# ---------------------------- Tier B（需组合） ----------------------------

# GetRequest 探针：GET / HTTP/1.0\r\n\r\n（无 Host/UA）——仅前缀锚定，最终由 nmap.zeek 结合"无 Host/UA + 扫描行为"
signature nmap_get_request_10 {
    ip-proto == tcp
    tcp-state originator
    payload /^GET \/ HTTP\/1\.0/
    event "nmap_tierB_get_request"
}

# HTTPOptions 探针：OPTIONS / HTTP/1.0
signature nmap_http_options_10 {
    ip-proto == tcp
    tcp-state originator
    payload /^OPTIONS \/ HTTP\/1\.0/
    event "nmap_tierB_http_options"
}

# RTSPRequest 探针：OPTIONS / RTSP/1.0
signature nmap_rtsp_options {
    ip-proto == tcp
    tcp-state originator
    payload /^OPTIONS \/ RTSP\/1\.0/
    event "nmap_tierB_rtsp_options"
}

# ---------------------------------------------------------------------------
# TODO（待 Zeek 9.0.1 校验后补充，避免当前文件因二进制/CRLF 正则加载失败）：
#   - GenericLines 探针  ^\r\n\r\n            -> event "nmap_tierC_generic_lines"
#   - Help 探针          ^HELP\r\n             -> event "nmap_tierC_help"
#   - Hello 探针         ^EHLO\r\n             -> event "nmap_tierC_ehlo"
#   - DNSVersionBindReq（UDP/TCP 二进制载荷）
#   - SSLSessionReq / TLSSessionReq 的 JA3（在 nmap.zeek 用 JA3 判定）
# ---------------------------------------------------------------------------
