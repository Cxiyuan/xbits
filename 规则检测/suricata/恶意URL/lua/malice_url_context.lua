-- ============================================================================
-- 恶意 URL 页面规则 · 响应上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 只对响应侧规则挂载：要求 200/206、HTML/JS 文本，并且页面包含脚本注入/
-- 跳转/解码类语义，避免把普通页面中出现相似字节序列当成恶意页面。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local MARKERS = {
    "eval(", "atob(", "fromcharcode", "unescape(", "document.write(",
    "window.location", "<iframe", "onerror=", "onload=", "string.fromcharcode",
    "base64_decode", "activexobject", "wscript.shell",
}

local function read_body(tx)
    local chunks = tx:response_body()
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

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local line = tx:response_line()
    if type(line) ~= "string" then
        return 0
    end
    local status = tonumber(line:match("^HTTP/%d%.%d%s+(%d%d%d)"))
    if status ~= 200 and status ~= 206 then
        return 0
    end

    local ctype = tx:response_header("Content-Type")
    if type(ctype) == "string" and #ctype > 0 then
        ctype = ctype:lower()
        if not (ctype:find("html", 1, true) or ctype:find("javascript", 1, true)
            or ctype:find("text/", 1, true)) then
            return 0
        end
    end

    local body = read_body(tx):lower()
    if #body == 0 then
        return 0
    end
    for _, marker in ipairs(MARKERS) do
        if body:find(marker, 1, true) then
            return 1
        end
    end
    return 0
end