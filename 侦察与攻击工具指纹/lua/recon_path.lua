-- ============================================================================
-- 侦察与攻击工具指纹 · 敏感路径高频探测（不依赖 UA）
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 用于捕获伪造/随机 UA、缺失 UA 的扫描器：只看请求路径是否命中高价值
-- 敏感路径，是否来自已排除的健康检查/监控客户端。
-- 告警频率由规则上的 threshold: type both 控制，脚本本身不聚合、不计数。
-- ============================================================================

local http = require("suricata.http")

local CRITICAL_PATHS = {
    "^/%.git%f[%W]",
    "^/%.svn%f[%W]",
    "^/%.hg%f[%W]",
    "^/%.env",
    "^/%.aws%f[%W]",
    "^/%.ssh%f[%W]",
    "^/%.docker/config%.json",
    "^/%.kube/config",
    "^/%.npmrc",
    "^/%.netrc",
    "^/%.git%-credentials",
    "^/%.htpasswd",
    "^/%.htaccess",
    "^/%.ds_store",
    "^/wp%-config%.php",
    "^/wp%-login%.php",
    "^/xmlrpc%.php",
    "^/wp%-admin/",
    "^/phpmyadmin",
    "^/pma/",
    "^/adminer%.php",
    "^/phpinfo%.php",
    "^/info%.php",
    "^/server%-status",
    "^/server%-info",
    "^/actuator",
    "^/jolokia",
    "^/env",
    "^/refresh",
    "^/bus/refresh",
    "^/swagger",
    "^/openapi",
    "^/redoc",
    "^/graphiql",
    "^/altair",
    "^/playground",
    "^/voyager",
    "^/v2/api%-docs",
    "^/v3/api%-docs",
    "^/v2/swagger%.json",
    "^/api%-docs",
    "^/graphql",
    "^/manager/html",
    "^/host%-manager/html",
    "^/cgi%-bin/",
    "^/vendor/phpunit",
    "^/phpunit%.xml",
    "^/solr/admin",
    "^/jenkins/script",
    "^/jmx%-console",
    "^/web%-console",
    "^/invoker/jmxinvokerservlet",
    "^/console",
    "^/backup",
    "^/db%.sql",
    "^/dump%.sql",
    "^/config%.php",
    "^/web%.config",
    "^/appsettings%.json",
    "^/application%.yml",
    "^/application%.properties",
    "^/bootstrap%.yml",
    "^/docker%-compose%.yml",
    "^/dockerfile",
    "^/id_rsa",
    "^/id_dsa",
    "^/server%.key",
    "^/server%.pem",
    "^/keystore",
    "^/truststore",
    "^/%.p12",
    "^/%.pfx",
    "^/latest/meta%-data/",
    "^/metadata/v1/",
    "^/computemetadata/v1/",
    "^/_cat/",
    "^/_cluster/",
    "^/_nodes",
    "^/_search",
    "^/config",
    "^/credentials",
    "^/secrets",
    "^/tokens",
    "^/keys",
}

-- 明确排除的自动化健康检查/监控客户端；不要在这里放业务 API 客户端。
local BENIGN_UA = {
    "^kube%-probe/",
    "^elb%-healthchecker/",
    "^googlehc/",
    "^amazon%-route53%-health%-check%-service",
    "^datadog/synthetics",
    "^newrelicpinger",
    "^prometheus/",
    "^zabbix",
    "^nagios",
    "^check_http",
    "^uptimerobot",
    "^pingdom",
    "^statuscake",
    "^better uptime",
}

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function normalize_uri(uri)
    uri = uri:lower()
    uri = uri:gsub("^https?://[^/]+", "")
    if #uri == 0 then
        return ""
    end

    uri = uri:gsub("\\", "/")

    for _ = 1, 2 do
        local before = uri
        uri = uri:gsub("%%(%x%x)", function(hex)
            return string.char(tonumber(hex, 16))
        end)
        if uri == before then
            break
        end
    end
    uri = uri:lower()
    uri = uri:gsub("\\", "/")
    uri = uri:gsub("//+", "/")

    local path, query = uri:match("^([^?]*)(.*)$")
    if path == nil then
        path, query = uri, ""
    end
    local parts = {}
    for seg in path:gmatch("[^/]+") do
        if seg == ".." then
            if #parts > 0 then
                table.remove(parts)
            end
        elseif seg ~= "." and seg ~= "" then
            parts[#parts + 1] = seg
        end
    end
    local normalized = "/" .. table.concat(parts, "/")
    return normalized .. (query or "")
end

local function get_uris(tx)
    local out = {}
    local normalized = tx:request_uri_normalized()
    if type(normalized) == "string" and #normalized > 0 then
        out[#out + 1] = normalized
    end
    local raw = tx:request_uri_raw()
    if type(raw) == "string" and #raw > 0 then
        out[#out + 1] = raw
    end
    return out
end

local function is_critical_path(uri)
    for _, pat in ipairs(CRITICAL_PATHS) do
        if uri:find(pat) then
            return true
        end
    end
    return false
end

local function is_benign_ua(ua)
    for _, pat in ipairs(BENIGN_UA) do
        if ua:find(pat) then
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
    -- On error get_tx() returns an error string; on success it is a userdata
    -- transaction object (Suricata 8.0.8 util-lua-http.c).
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local uris = get_uris(tx)
    if #uris == 0 then
        return 0
    end

    local critical = false
    for _, uri in ipairs(uris) do
        if is_critical_path(normalize_uri(uri)) then
            critical = true
            break
        end
    end
    if not critical then
        return 0
    end

    local ua = tx:request_header("User-Agent")
    if type(ua) == "string" and #ua > 0 and is_benign_ua(trim(ua):lower()) then
        return 0
    end

    return 1
end
