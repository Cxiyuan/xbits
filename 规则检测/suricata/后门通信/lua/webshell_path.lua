-- ============================================================================
-- 后门通信 · 已知 WebShell 文件名访问
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 只返回“已知 WebShell 文件名”的线索，不判断是否成功执行。
-- 规则侧使用 tier triage；响应确认由 webshell_response.lua 负责。
-- ============================================================================

local http = require("suricata.http")

local NAMES = {
    "rce", "cmd", "shell", "backdoor", "wso", "b374k", "c99",
    "cmdjsp", "gsl", "godzilla", "behinder", "ants", "n1nty",
    "webshell", "webshells", "c100", "r57", "phpspy", "milw0rm",
}

local EXTS = {
    "php", "php3", "php4", "php5", "php7", "phtml", "phar",
    "jsp", "jspx", "jspf", "asp", "aspx", "asa", "cer", "cdx",
    "ashx", "asmx", "cfm", "cgi", "pl", "py", "rb",
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

local function normalize_uri(uri)
    uri = decode(uri, 2):lower()
    uri = uri:gsub("\\", "/")
    local path = uri:match("^[^?]*") or uri
    path = path:gsub("//+", "/")
    return path
end

local function is_known(path)
    for segment in path:gmatch("[^/]+") do
        local name, ext = segment:match("^([%w%-_]+)%.([%w]+)$")
        if name ~= nil then
            for _, known in ipairs(NAMES) do
                if name == known then
                    for _, e in ipairs(EXTS) do
                        if ext == e then
                            return true
                        end
                    end
                end
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

    local candidates = {}
    local raw = tx:request_uri_raw()
    if type(raw) == "string" and #raw > 0 then
        candidates[#candidates + 1] = raw
    end
    local normalized = tx:request_uri_normalized()
    if type(normalized) == "string" and #normalized > 0 then
        candidates[#candidates + 1] = normalized
    end

    for _, uri in ipairs(candidates) do
        if is_known(normalize_uri(uri)) then
            return 1
        end
    end
    return 0
end
