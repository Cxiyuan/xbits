-- ============================================================================
-- dns_doh_policy.lua
-- 规则内嵌 Lua：DoH 请求的 method/URI 二次过滤（Suricata 8.0.8）
--
-- 使用规则：9109102（Content-Type: application/dns-message）
-- 作用：
--   - 要求 HTTP method 为 POST 或 GET
--   - 要求 URI 包含 /dns-query、?dns= 或 dns-query
--   - 要求 Host 非空
--   - 过滤"普通应用恰好使用该 Content-Type"的误报
--
-- 说明：已批准的 DoH 解析器仍需用目标地址/域名策略处理。
-- ============================================================================

local http = require("suricata.http")

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if not tx then
        return 0
    end

    local line = tx:request_line() or ""
    if not line:find("^POST ") and not line:find("^GET ") then
        return 0
    end

    local uri = tx:request_uri_raw() or ""
    if not uri:find("/dns%-query") and not uri:find("?dns=", 1, true)
        and not uri:find("dns-query", 1, true) then
        return 0
    end

    local host = tx:request_host() or ""
    if #host == 0 then
        return 0
    end

    return 1
end
