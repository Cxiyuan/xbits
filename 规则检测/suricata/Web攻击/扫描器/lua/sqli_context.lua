-- ============================================================================
-- Web 漏洞利用 · SQL 注入上下文检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 同时检查 URI、请求体、Cookie、请求头；做 URL 解码、注释/空白归一化。
-- 不使用“出现 union/select/information_schema 即告警”的宽泛逻辑。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

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
            out[#out + 1] = value
        end
    end
    add(tx:request_uri_raw())
    add(tx:request_uri_normalized())
    add(read_body(tx))
    add(tx:request_headers_raw())
    add(tx:request_header("Cookie"))
    return out
end

local function sql_normalize(s)
    s = decode(s, 2):lower()
    s = s:gsub("%+", " ")
    s = s:gsub("/%*.-%*/", " ")
    s = s:gsub("%-%-[^\r\n]*", " ")
    s = s:gsub("%c", " ")
    s = s:gsub("%s+", " ")
    return s
end

local function has_union_select(s)
    local start = 1
    while true do
        local u = s:find("union", start, true)
        if u == nil then
            return false
        end
        local sel = s:find("select", u + 5, true)
        if sel ~= nil and sel - u <= 60 then
            return true
        end
        start = u + 5
    end
end

local function has_any(s, list)
    for _, token in ipairs(list) do
        if s:find(token, 1, true) then
            return true
        end
    end
    return false
end

local ERROR_FUNCS = {
    "extractvalue(",
    "updatexml(",
    "name_const(",
    "gtid_subset(",
    "exp(~",
    "geometrycollection(",
    "multipoint(",
}

local TIME_FUNCS = {
    "sleep(",
    "benchmark(",
    "pg_sleep(",
    "waitfor delay",
    "dbms_pipe.receive_message",
}

local MSSQL_FUNCS = {
    "fn_sqlvarbasetostr(",
    "hashbytes(",
    "sys.fn_varbintohexstr",
}

local function has_boolean(s)
    local patterns = {
        "[%'\"]?%s*or%s+[%'\"]?%d+[%'\"]?%s*=%s*[%'\"]?%d+",
        "[%'\"]?%s*and%s+[%'\"]?%d+[%'\"]?%s*=%s*[%'\"]?%d+",
        "[%'\"]?%s*or%s+[%'\"]?[%w_]+[%'\"]?%s*=%s*[%'\"]?[%w_]+",
        "or%s+true%f[%W]",
        "or%s+1%s+like%s+1",
    }
    for _, pat in ipairs(patterns) do
        if s:find(pat) then
            return true
        end
    end
    return false
end

local function detect(s)
    if #s == 0 then
        return false
    end

    if has_union_select(s) then
        return true
    end
    if has_any(s, ERROR_FUNCS) then
        return true
    end
    if has_any(s, TIME_FUNCS) then
        return true
    end
    if has_any(s, MSSQL_FUNCS) then
        return true
    end
    if s:find("procedure%s+analyse") then
        return true
    end

    -- information_schema 只有在带 SQL 上下文时才算，单独出现不算。
    if s:find("information_schema", 1, true) then
        if s:find("select", 1, true) or s:find("from", 1, true)
            or s:find("union", 1, true) or s:find("where", 1, true)
            or s:find(".tables", 1, true) or s:find(".columns", 1, true) then
            return true
        end
    end

    if has_boolean(s) then
        return true
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
        if detect(sql_normalize(source)) then
            return 1
        end
    end
    return 0
end
