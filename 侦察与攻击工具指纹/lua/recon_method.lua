-- ============================================================================
-- 侦察与攻击工具指纹 · 异常 HTTP 方法 / Host 组合
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 只作为 triage 组合信号：
--   - TRACE/TRACK/PROPFIND/MKCOL 在外部 -> 内部场景很少见；
--   - PUT/DELETE 需要同时满足“Host 为 IP/localhost/空”或“敏感路径”，
--     避免把正常 REST/WebDAV 客户端全部告警。
-- ============================================================================

local http = require("suricata.http")

local ALWAYS_METHODS = {
    TRACE = true,
    TRACK = true,
    PROPFIND = true,
    MKCOL = true,
}

local CONDITIONAL_METHODS = {
    PUT = true,
    DELETE = true,
}

local SUSPICIOUS_PATH = {
    "^/%.git%f[%W]",
    "^/%.env",
    "^/%.aws%f[%W]",
    "^/%.ssh%f[%W]",
    "^/actuator",
    "^/server%-status",
    "^/server%-info",
    "^/manager",
    "^/console",
    "^/swagger",
    "^/openapi",
    "^/graphql",
    "^/backup",
    "^/config",
    "^/credentials",
    "^/secrets",
    "^/tokens",
    "^/keys",
    "^/web%.config",
    "^/application%.yml",
    "^/application%.properties",
    "^/docker%-compose%.yml",
    "^/dockerfile",
}

local function normalize_path(uri)
    uri = uri:lower()
    uri = uri:gsub("^https?://[^/]+", "")
    uri = uri:gsub("\\", "/")
    local path = uri:match("^[^?]*") or ""
    path = path:gsub("//+", "/")
    return path
end

local function get_path(tx)
    local uri = tx:request_uri_normalized()
    if type(uri) ~= "string" or #uri == 0 then
        uri = tx:request_uri_raw()
    end
    if type(uri) ~= "string" or #uri == 0 then
        return ""
    end
    return normalize_path(uri)
end

local function suspicious_path(path)
    for _, pat in ipairs(SUSPICIOUS_PATH) do
        if path:find(pat) then
            return true
        end
    end
    return false
end

local function suspicious_host(host)
    if type(host) ~= "string" or #host == 0 then
        return true
    end
    host = host:lower():gsub(":%d+$", "")
    if host == "localhost" or host == "127.0.0.1" or host == "::1"
        or host == "[::1]" or host == "0.0.0.0" then
        return true
    end
    if host:match("^%d+%.%d+%.%d+%.%d+$") then
        return true
    end
    if host:match("^%[.*%]$") then
        return true
    end
    return false
end

local function method_of(tx)
    local line = tx:request_line()
    if type(line) ~= "string" or #line == 0 then
        return nil
    end
    return line:match("^(%u+)%s+")
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local method = method_of(tx)
    if method == nil then
        return 0
    end

    if ALWAYS_METHODS[method] then
        return 1
    end

    if CONDITIONAL_METHODS[method] then
        local path = get_path(tx)
        if suspicious_path(path) then
            return 1
        end
        local host = tx:request_host()
        if suspicious_host(host) then
            return 1
        end
    end

    return 0
end
