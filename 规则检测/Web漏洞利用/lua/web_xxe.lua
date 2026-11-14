-- ============================================================================
-- Web 漏洞利用 · XXE 检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查请求体/URI/请求头中的 XML 外部实体声明。
-- 普通 <!DOCTYPE html> 不告警；必须出现 <!ENTITY SYSTEM/PUBLIC 语义。
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
            out[#out + 1] = decode(value, 2):lower()
        end
    end
    add(tx:request_uri_raw())
    add(read_body(tx))
    add(tx:request_headers_raw())
    add(tx:request_header("Cookie"))
    return out
end

local function detect(s)
    if not s:find("<!entity", 1, true) then
        return false
    end
    if s:find("system", 1, true) or s:find("public", 1, true) then
        return true
    end
    if s:find("<!doctype", 1, true)
        and (s:find("file://", 1, true) or s:find("http://", 1, true)
            or s:find("php://", 1, true) or s:find("jar://", 1, true)) then
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
        if detect(source) then
            return 1
        end
    end
    return 0
end
