-- ============================================================================
-- Web 扫描器规则 · UA/Header 上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 只对“扫描器/安全工具”类规则挂载；检查 User-Agent、Cookie 和请求头中
-- 是否真的出现工具指纹，避免仅凭 URI 中偶然出现工具名误报。
-- ============================================================================

local http = require("suricata.http")

-- xbits: 显式导出实际命中的精确 buffer（未打补丁的 Suricata 上为 nil，自动跳过）
local function xbits_export(value)
    if xbits_export_match ~= nil and type(value) == "string" and #value > 0 then
        xbits_export_match("lua", value)
    end
end


local TOKENS = {
    "acunetix", "netsparker", "appscan", "webinspect", "nstalker",
    "nmap", "nikto", "sqlmap", "nuclei", "wpscan", "joomscan",
    "droopescan", "zgrab", "masscan", "dirbuster", "gobuster",
    "feroxbuster", "ffuf", "whatweb", "httpx", "wafw00f",
    "burp", "xray", "nessus", "openvas", "qualys", "dirsearch",
    "webscarab", "paros", "w3af", "skipfish", "vega", "zap",
}

local function contains_token(s)
    s = s:lower()
    for _, token in ipairs(TOKENS) do
        if s:find(token, 1, true) ~= nil then
            return true
        end
    end
    return false
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local ua = tx:request_header("User-Agent")
    if type(ua) == "string" and contains_token(ua) then
        xbits_export(ua)
        return 1
    end

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" then
        uri = tx:request_uri_normalized()
    end
    if type(uri) == "string" and contains_token(uri) then
        xbits_export(uri)
        return 1
    end

    local raw = tx:request_headers_raw()
    if type(raw) == "string" and contains_token(raw) then
        xbits_export(raw)
        return 1
    end

    local cookie = tx:request_header("Cookie")
    if type(cookie) == "string" and contains_token(cookie) then
        xbits_export(cookie)
        return 1
    end

    return 0
end