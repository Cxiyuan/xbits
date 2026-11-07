-- ============================================================================
-- 命令与控制信标 · 全单字母参数 + 空值/请求头异常
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 9110006 不单凭“单字母参数”告警。要求：
--   - 根路径下至少 3 个单字母参数；
--   - 且至少 2 个空值，或至少 2 个请求头异常。
-- 正常分析/埋点的 ?a=1&b=2&c=3 不命中。
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

local function single_letter_stats(query)
    local count, empty = 0, 0
    for pair in query:gmatch("[^&]+") do
        local key, value = pair:match("^([^=]+)=(.*)$")
        if key ~= nil and #key == 1 then
            count = count + 1
            if value == "" then
                empty = empty + 1
            end
        end
    end
    return count, empty
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

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" or #uri == 0 then
        return 0
    end
    local path, query = uri_parts(uri)
    if path ~= "/" and path ~= "" then
        return 0
    end

    local count, empty = single_letter_stats(query)
    if count < 3 then
        return 0
    end

    local headers = tx:request_headers_raw()
    if type(headers) ~= "string" then
        headers = ""
    else
        headers = headers:lower()
    end

    if empty >= 2 or header_anomalies(headers) >= 2 then
        return 1
    end
    return 0
end
