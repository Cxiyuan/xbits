-- ============================================================================
-- dns_dot_policy.lua
-- 规则内嵌 Lua：DNS over TLS 853 的 SNI 二次过滤（Suricata 8.0.8）
--
-- 使用规则：9109101（TLS 853 + tls.alpn "dot"）
-- 作用：
--   - ALPN 由规则里的 tls.alpn 负责（Lua TLS 不暴露 ALPN）
--   - Lua 检查 SNI：明显不是 DNS 解析器的 SNI（www/mail/vpn/api 等）降为 0
--   - SNI 为空时放行（部分 DoT 客户端不发 SNI）
--
-- 说明：已批准的 DoT 解析器仍需用源/目的地址或抑制策略处理。
-- ============================================================================

local tls = require("suricata.tls")

local NON_DNS_PREFIXES = {
    "www.", "mail.", "smtp.", "imap.", "pop.", "vpn.", "api.",
    "web.", "ftp.", "git.", "ssh.",
}

local DNS_HINTS = {
    "dns", "dot", "resolver", "quad9", "cloudflare-dns",
    "adguard", "nextdns", "dnscrypt", "mullvad", "controld",
}

function init(args)
    return {}
end

function match(args)
    local tx = tls.get_tx()
    if not tx then
        return 0
    end

    local sni = tx:get_client_sni()
    if not sni or #sni == 0 then
        return 1
    end
    sni = sni:lower()

    for _, prefix in ipairs(NON_DNS_PREFIXES) do
        if sni:sub(1, #prefix) == prefix then
            return 0
        end
    end

    for _, hint in ipairs(DNS_HINTS) do
        if sni:find(hint, 1, true) then
            return 1
        end
    end

    return 1
end
