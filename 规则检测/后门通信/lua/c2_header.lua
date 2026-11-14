-- ============================================================================
-- 命令与控制信标 · 信标式 URI + 请求头异常组合
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 9110004 不再仅凭“缺失 Accept”告警。要求：
--   1) GET + HTTP/1.1；
--   2) 至少两个请求头异常（缺 Accept/Accept-Language/Referer/Sec-Fetch，
--      或 Connection: close）；
--   3) URI 呈现信标式结构（a/f/t/p 或 3 个以上单字母参数）。
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

local function query_keys(query)
    local keys = {}
    for pair in query:gmatch("[^&]+") do
        local key = pair:match("^([^=]+)=")
        if key ~= nil then
            keys[#keys + 1] = key
        end
    end
    return keys
end

local function beacon_like(path, query)
    if path ~= "/" and path ~= "" then
        return false
    end
    local keys = query_keys(query)
    local single = 0
    local has_aftp = false
    local set = {}
    for _, key in ipairs(keys) do
        set[key] = true
        if #key == 1 then
            single = single + 1
        end
    end
    if set.a and set.f and set.t and set.p then
        has_aftp = true
    end
    return has_aftp or single >= 3
end

local function header_anomalies(headers)
    local score = 0
    if not headers:find("\naccept:", 1, true)
        and not headers:find("^accept:", 1, true) then
        score = score + 1
    end
    if not headers:find("\naccept-language:", 1, true)
        and not headers:find("^accept-language:", 1, true) then
        score = score + 1
    end
    if not headers:find("\nreferer:", 1, true)
        and not headers:find("^referer:", 1, true) then
        score = score + 1
    end
    if not headers:find("\nsec-fetch-", 1, true)
        and not headers:find("^sec-fetch-", 1, true) then
        score = score + 1
    end
    if headers:find("\nconnection: close", 1, true) then
        score = score + 1
    end
    return score
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local line = tx:request_line()
    if type(line) ~= "string" or not line:find("^GET ") then
        return 0
    end
    if not line:find("HTTP/1%.1$") then
        return 0
    end

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" or #uri == 0 then
        return 0
    end
    local path, query = uri_parts(uri)
    if not beacon_like(path, query) then
        return 0
    end

    local headers = tx:request_headers_raw()
    if type(headers) ~= "string" or #headers == 0 then
        return 0
    end
    headers = headers:lower()
    if header_anomalies(headers) >= 2 then
        return 1
    end
    return 0
end
