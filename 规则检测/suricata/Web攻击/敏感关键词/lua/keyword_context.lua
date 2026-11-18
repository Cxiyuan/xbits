-- ============================================================================
-- 敏感关键词规则 · 参数上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 原始 gray_keyword 规则是“HTTP 任意位置出现某关键词”，正常搜索、文档、
-- 静态资源都会命中。本脚本把命中限制到：
--   * 非 benign 的查询参数值；
--   * 请求体参数赋值；
--   * 带命令/代码语义的 Cookie/请求头参数。
-- 规则仍负责关键词本身，Lua 只负责上下文。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local BENIGN_PARAMS = {
    q = true, search = true, query = true, keyword = true, keywords = true,
    s = true, wd = true, lang = true, locale = true, page = true,
    sort = true, order = true, filter = true, category = true, tag = true,
}

local STATIC_EXT = {
    js = true, css = true, png = true, jpg = true, jpeg = true, gif = true,
    svg = true, ico = true, woff = true, woff2 = true, ttf = true,
    map = true, mp4 = true, webp = true,
}

local DANGEROUS_NAMES = {
    cmd = true, exec = true, command = true, execute = true, shell = true,
    pass = true, password = true, pwd = true, code = true, eval = true,
    run = true, z0 = true, z1 = true, z2 = true, z3 = true,
}

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

local function parse_query(query)
    for pair in query:gmatch("[^&]+") do
        local name, value = pair:match("^([^=]+)=(.*)$")
        if name ~= nil and value ~= nil and #value > 0 then
            name = decode(name):lower()
            value = decode(value)
            if not BENIGN_PARAMS[name] then
                return true
            end
            if value:find("[%'\"`;|$%(%){}]") ~= nil then
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

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" then
        uri = tx:request_uri_normalized()
    end
    if type(uri) ~= "string" then
        uri = ""
    end
    uri = decode(uri)

    local path = uri:match("^[^?]*") or uri
    local ext = path:match("%.([%w]+)$")
    if ext ~= nil and STATIC_EXT[ext:lower()] then
        return 0
    end

    local query = uri:match("%?(.*)$") or ""
    if #query > 0 and parse_query(query) then
        return 1
    end

    local body = decode(read_body(tx))
    if #body > 0 and (body:find("=") ~= nil or body:find("{") ~= nil) then
        return 1
    end

    -- Cookie/自定义头里的命令参数也属于可利用上下文。
    local headers = tx:request_headers_raw()
    if type(headers) == "string" then
        local lower = headers:lower()
        for name in pairs(DANGEROUS_NAMES) do
            if lower:find(name .. "=", 1, true) ~= nil then
                return 1
            end
        end
    end

    return 0
end