-- ============================================================================
-- Web 漏洞利用 · SSRF 检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 只在 URL/跳转/代理/抓取类参数的值中出现内网地址、云元数据地址或
-- file/gopher/dict/ldap/rmi 等危险协议时告警。
-- 不把普通外链 https://example.com/ 当成 SSRF。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local PARAMS = {
    "url", "uri", "target", "dest", "destination", "redirect", "proxy",
    "image", "fetch", "callback", "webhook", "feed", "link", "src",
    "source", "path", "site", "domain", "host",
}

local TARGETS = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "[::1]",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "file://",
    "gopher://",
    "dict://",
    "ftp://",
    "ldap://",
    "rmi://",
    "jar://",
}

local function decode(s, rounds)
    for _ = 1, rounds do
        local before = s
        s = s:gsub("%%(%x%x)", function(hex)
            return string.char(tonumber(hex, 16))
        end)
        if s == before then
            break
        end
    end
    return s
end

local function read_body(tx)
    local chunks = tx:request_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = MAX_BODY - total
            if remain <= 0 then
                break
            end
            if #chunk > remain then
                chunk = chunk:sub(1, remain)
            end
            out[#out + 1] = chunk
            total = total + #chunk
        end
    end
    return table.concat(out)
end

local function sources(tx)
    local out = {}
    local function add(value)
        if type(value) == "string" and #value > 0 then
            out[#out + 1] = decode(value, 2):lower()
        end
    end
    add(tx:request_uri_raw())
    add(tx:request_uri_normalized())
    add(read_body(tx))
    add(tx:request_headers_raw())
    add(tx:request_header("Cookie"))
    return out
end

local function has_any(s, list)
    for _, token in ipairs(list) do
        if s:find(token, 1, true) then
            return true
        end
    end
    return false
end

local function has_target(window)
    return has_any(window, TARGETS)
end

local function detect(s)
    for _, name in ipairs(PARAMS) do
        local positions = {}
        local p = s:find(name .. "=", 1, true)
        if p ~= nil then
            positions[#positions + 1] = p
        end
        p = s:find('"' .. name .. '":', 1, true)
        if p ~= nil then
            positions[#positions + 1] = p
        end
        p = s:find("'" .. name .. "':", 1, true)
        if p ~= nil then
            positions[#positions + 1] = p
        end

        for _, pos in ipairs(positions) do
            local window = s:sub(pos, pos + 300)
            if has_target(window) then
                return true
            end
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

    for _, source in ipairs(sources(tx)) do
        if detect(source) then
            return 1
        end
    end
    return 0
end
