-- ============================================================================
-- 命令与控制信标 · a/f/t/p URI 结构变体
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 9110002 使用：允许参数顺序变化，但仍要求 a/f/t/p 四个键、
-- 至少两个空值、p 为数字。避免仅凭“有四个参数”告警。
-- ============================================================================

local http = require("suricata.http")

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

local function uri_parts(uri)
    uri = decode(uri, 2):lower()
    local path = uri:match("^[^?]*") or uri
    local query = uri:match("%?(.*)$") or ""
    return path, query
end

local function parse_query(query)
    local out = {}
    for pair in query:gmatch("[^&]+") do
        local key, value = pair:match("^([^=]+)=(.*)$")
        if key ~= nil then
            out[key] = value
        end
    end
    return out
end

local function is_beacon(path, query)
    if path ~= "/" and path ~= "" then
        return false
    end
    local params = parse_query(query)
    if params.a == nil or params.f == nil or params.t == nil or params.p == nil then
        return false
    end
    if params.p:match("^%d+$") == nil then
        return false
    end
    local empty = 0
    if params.a == "" then empty = empty + 1 end
    if params.f == "" then empty = empty + 1 end
    if params.t == "" then empty = empty + 1 end
    return empty >= 2
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local candidates = {}
    local raw = tx:request_uri_raw()
    if type(raw) == "string" and #raw > 0 then candidates[#candidates + 1] = raw end
    local normalized = tx:request_uri_normalized()
    if type(normalized) == "string" and #normalized > 0 then candidates[#candidates + 1] = normalized end

    for _, uri in ipairs(candidates) do
        local path, query = uri_parts(uri)
        if is_beacon(path, query) then
            return 1
        end
    end
    return 0
end
