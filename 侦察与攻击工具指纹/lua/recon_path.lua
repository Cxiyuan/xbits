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
    "^/%.git/",
    "^/%.svn/",
    "^/%.hg/",
    "^/%.env",
    "^/%.aws/credentials",
    "^/%.ssh/",
    "^/%.ds_store",
    "^/wp%-config%.php",
    "^/wp%-login%.php",
    "^/xmlrpc%.php",
    "^/wp%-admin/",
    "^/phpmyadmin",
    "^/pma/",
    "^/adminer%.php",
    "^/server%-status",
    "^/server%-info",
    "^/actuator/",
    "^/swagger%-ui",
    "^/v2/api%-docs",
    "^/v3/api%-docs",
    "^/openapi%.json",
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

local function normalize_uri(uri)
    uri = uri:lower()
    uri = uri:gsub("^https?://[^/]+", "")
    if #uri == 0 then
        uri = "/"
    end
    uri = uri:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    uri = uri:lower()
    uri = uri:gsub("//+", "/")
    return uri
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

    local uri = tx:request_uri_raw()
    if uri == nil or #uri == 0 then
        return 0
    end
    if not is_critical_path(normalize_uri(uri)) then
        return 0
    end

    local ua = tx:request_header("User-Agent")
    if ua ~= nil and #ua > 0 and is_benign_ua(ua:lower()) then
        return 0
    end

    return 1
end
