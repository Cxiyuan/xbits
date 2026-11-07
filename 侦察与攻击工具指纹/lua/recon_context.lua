-- ============================================================================
-- 侦察与攻击工具指纹 · 已知攻击工具 + 敏感路径上下文
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 只对“已知攻击工具默认 UA”且“请求了高价值敏感路径”返回 1。
-- 互联网测绘爬虫（Shodan/Censys/Expanse/l9explore）和 masscan/zgrab
-- 不进入本脚本的高置信集合，避免把第三方测绘当成攻击确认。
--
-- 本脚本同时用于请求侧和响应侧：
--   - 请求侧规则在 http.uri 上调用；
--   - 响应侧规则在 http.stat_code 上调用，仍可通过 tx 读取请求 URI/UA。
-- ============================================================================

local http = require("suricata.http")

local TOOL_PATTERNS = {
    "^fuzz faster u fool%f[%W]",
    "^gobuster/",
    "^feroxbuster/",
    "^sqlmap/",
    "^nuclei%f[%W]",
    "^nmap scripting engine%f[%W]",
    "^acunetix%f[%W]",
    "^dirbuster%f[%W]",
    "^nikto/",
    "^wpscan%f[%W]",
    "^nessus%f[%W]",
    "^openvas%f[%W]",
    "^whatweb/",
    "^httpx%f[%W]",
    "^arjun/",
    "^wafw00f/",
    "^commix/",
    "^xsstrike%f[%W]",
    "^zmeu%f[%W]",
    "^morfeus%f[%W]",
}

-- 高价值路径：路径前缀使用 Lua pattern；默认小写、百分号解码后再匹配。
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

local function normalize_uri(uri)
    uri = uri:lower()

    -- 代理形式可能给出绝对 URI；去掉 scheme://host，保留 path。
    uri = uri:gsub("^https?://[^/]+", "")
    if #uri == 0 then
        uri = "/"
    end

    -- 解码 %2e/%2f 等，避免 /%2e%67%69%74/ 绕过路径判断。
    uri = uri:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)

    -- 解码后可能重新出现大写字符，再次小写化。
    uri = uri:lower()

    -- 合并重复斜杠，避免 //.git// 绕过。
    uri = uri:gsub("//+", "/")
    return uri
end

local function is_offensive_tool(ua)
    for _, pat in ipairs(TOOL_PATTERNS) do
        if ua:find(pat) then
            return true
        end
    end
    -- NSE UAs are commonly wrapped in a Mozilla/5.0 (compatible; ...) string.
    if ua:find("nmap scripting engine", 1, true) then
        return true
    end
    return false
end

local function is_critical_path(uri)
    for _, pat in ipairs(CRITICAL_PATHS) do
        if uri:find(pat) then
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

    local ua = tx:request_header("User-Agent")
    if ua == nil or #ua == 0 then
        return 0
    end

    local uri = tx:request_uri_raw()
    if uri == nil or #uri == 0 then
        return 0
    end

    if not is_offensive_tool(ua:lower()) then
        return 0
    end
    if not is_critical_path(normalize_uri(uri)) then
        return 0
    end

    return 1
end
