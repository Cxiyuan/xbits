-- ============================================================================
-- XSS 规则 · HTML 上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 要求请求/响应中出现可执行 HTML/JS 结构，而不是只出现 onerror、script 等
-- 普通单词。规则本身仍负责具体特征。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local MARKERS = {
    "<script", "javascript:", "onerror=", "onload=", "onfocus=", "onmouseover=",
    "srcdoc=", "document.cookie", "document.write(", "window.location",
    "alert(", "prompt(", "confirm(", "fromcharcode", "eval(",
}

local function read_body(tx, response)
    local chunks
    if response then
        chunks = tx:response_body()
    else
        chunks = tx:request_body()
    end
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

local function decode(s)
    for _ = 1, 2 do
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

local function detect(s)
    s = decode(s):lower()
    if #s == 0 then
        return false
    end
    for _, marker in ipairs(MARKERS) do
        if s:find(marker, 1, true) then
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

    local parts = {
        tx:request_uri_raw(),
        tx:request_uri_normalized(),
        read_body(tx, false),
        tx:request_headers_raw(),
        tx:request_header("Cookie"),
        read_body(tx, true),
    }
    for _, part in ipairs(parts) do
        if type(part) == "string" and detect(part) then
            return 1
        end
    end
    return 0
end