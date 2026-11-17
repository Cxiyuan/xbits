-- ============================================================================
-- Web 漏洞利用 · Log4Shell / JNDI 检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI、任意请求头、Cookie、请求体；支持 URL 编码和常见嵌套混淆：
--   ${jndi:ldap://...}
--   ${${lower:j}ndi:ldap://...}
--   ${${::-j}ndi:rmi://...}
--   %24%7Bjndi%3Aldap...
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local PROTOCOLS = {
    "ldap:",
    "ldaps:",
    "rmi:",
    "dns:",
    "iiop:",
    "nis:",
    "nds:",
    "corba:",
    "http:",
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

local function normalize(s)
    s = decode(s, 3):lower()

    -- 常见 Log4j lookup 嵌套混淆；迭代几次以处理多层嵌套。
    for _ = 1, 3 do
        local before = s
        s = s:gsub("%$%{lower:([^}])%}", "%1")
        s = s:gsub("%$%{upper:([^}])%}", "%1")
        s = s:gsub("%$%{::%-([^}])%}", "%1")
        if s == before then
            break
        end
    end
    return s
end

local function has_jndi(s)
    if not s:find("jndi:", 1, true) then
        return false
    end
    for _, protocol in ipairs(PROTOCOLS) do
        if s:find(protocol, 1, true) then
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

    for _, source in ipairs(sources(tx)) do
        if has_jndi(normalize(source)) then
            return 1
        end
    end
    return 0
end
