-- ============================================================================
-- 侦察与攻击工具指纹 · 已知攻击工具 + 敏感路径上下文
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 请求侧：已知攻击工具默认/包裹/多值 UA + 高价值敏感路径 -> 1。
-- 响应侧：在请求侧条件之外，读取响应体；SPA/登录页/WAF 页造成的
-- “200 软 404”返回 0，避免把 9101102 误判为敏感文件读取成功。
--
-- 本脚本不做跨包聚合；所有判断限于当前 HTTP 事务。
-- ============================================================================

local http = require("suricata.http")
local rule = require("suricata.rule")

local MAX_BODY = 8192

-- 以 UA 开头匹配的工具（小写后比较）。
local START_PATTERNS = {
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

-- 任意位置 + 词边界；不包含 httpx，避免重新命中 python-httpx/。
local TOKEN_PATTERNS = {
    "%f[%w]fuzz faster u fool%f[%W]",
    "%f[%w]gobuster/",
    "%f[%w]feroxbuster/",
    "%f[%w]sqlmap/",
    "%f[%w]nuclei%f[%W]",
    "%f[%w]dirbuster%f[%W]",
    "%f[%w]nikto/",
    "%f[%w]wpscan%f[%W]",
    "%f[%w]nessus%f[%W]",
    "%f[%w]openvas%f[%W]",
    "%f[%w]acunetix%f[%W]",
    "%f[%w]whatweb/",
    "%f[%w]arjun/",
    "%f[%w]wafw00f/",
    "%f[%w]commix/",
    "%f[%w]xsstrike%f[%W]",
    "%f[%w]zmeu%f[%W]",
    "%f[%w]morfeus%f[%W]",
}

-- 高价值路径：默认小写、百分号解码、点段归一化后匹配。
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

-- 真实泄露标记：软 404 判断时先看这些，避免误杀真实配置文件。
local EXPOSURE_HINTS = {
    "[core]",
    "repositoryformatversion",
    "logallrefupdates",
    "[remote",
    "ref: refs/",
    "db_password",
    "db_name",
    "app_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "secret_key",
    "api_key",
    "jwt_secret",
    "database_url",
    "smtp_password",
    "mysql_root_password",
    "propertySources",
    "systemProperties",
    "spring.datasource",
    "activeProfiles",
    "apache server status",
    "total accesses",
    "apache server information",
    "phpinfo",
    "php version",
    "create table",
    "mysql dump",
    "postgresql database dump",
    "-- mysql dump",
    "akia",
    "ghp_",
    "xoxb-",
    "xoxp-",
    "sk_live_",
    "-----begin",
    "private key",
    "ssh-rsa",
    "ssh-ed25519",
}

local SOFT404_MARKERS = {
    "<!doctype html",
    "<html",
    "page not found",
    "not found",
    "cannot get",
    "whitelabel error page",
    "access denied",
    "request blocked",
    "cloudflare",
    "mod_security",
    "login",
    "sign in",
    "signin",
    "unauthorized",
    "forbidden",
    'id="app"',
    "id='app'",
    "__next",
    "ng-version",
    "data-reactroot",
    "webpack",
    "vite",
}

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function normalize_uri(uri)
    uri = uri:lower()

    -- 代理形式可能给出绝对 URI；去掉 scheme://host，保留 path。
    uri = uri:gsub("^https?://[^/]+", "")
    if #uri == 0 then
        return ""
    end

    -- IIS/畸形客户端可能使用反斜杠。
    uri = uri:gsub("\\", "/")

    -- 最多解码两次，覆盖 %252e 等双重编码。
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

    -- 解码后可能重新出现反斜杠；再次归一化。
    uri = uri:gsub("\\", "/")

    -- 合并重复斜杠。
    uri = uri:gsub("//+", "/")

    -- 处理 . / .. 点段，保留 query。
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

local function collect_user_agents(tx)
    local out = {}
    local raw = tx:request_headers_raw()
    if type(raw) == "string" and #raw > 0 then
        for line in raw:gmatch("[^\r\n]+") do
            local name, value = line:match("^([%w%-_]+):%s*(.*)$")
            if name ~= nil and name:lower() == "user-agent" and #value > 0 then
                out[#out + 1] = trim(value)
            end
        end
    end
    if #out == 0 then
        local ua = tx:request_header("User-Agent")
        if type(ua) == "string" and #ua > 0 then
            out[1] = trim(ua)
        end
    end
    return out
end

local function read_body(tx, max_len)
    local chunks = tx:response_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = max_len - total
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

local function has_any(haystack, needles)
    for _, needle in ipairs(needles) do
        if haystack:find(needle:lower(), 1, true) then
            return true
        end
    end
    return false
end

local function is_offensive_tool(ua)
    for _, pat in ipairs(START_PATTERNS) do
        if ua:find(pat) then
            return true
        end
    end
    for _, pat in ipairs(TOKEN_PATTERNS) do
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

local function is_soft_404(tx, body)
    if body == nil or #body == 0 then
        return false
    end
    local lower = body:lower()

    -- 真实泄露标记优先，避免 .env 中的 LOGIN=/PASSWORD= 被当成登录页。
    if has_any(lower, EXPOSURE_HINTS) then
        return false
    end

    local content_type = tx:response_header("Content-Type")
    if type(content_type) ~= "string" then
        content_type = ""
    else
        content_type = content_type:lower()
    end

    local is_html = content_type:find("text/html", 1, true) ~= nil
        or lower:find("<!doctype", 1, true) ~= nil
        or lower:find("<html", 1, true) ~= nil

    if is_html then
        -- 敏感路径返回 HTML，绝大多数是 SPA/登录页/WAF 页/软 404；
        -- 真实 HTML 泄露（phpinfo、server-status）已由 EXPOSURE_HINTS 兜住。
        if has_any(lower, SOFT404_MARKERS) then
            return true
        end
        return true
    end

    if content_type:find("application/json", 1, true) ~= nil
        and lower:find('"error"', 1, true) ~= nil then
        if has_any(lower, SOFT404_MARKERS) then
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

    local uas = collect_user_agents(tx)
    if #uas == 0 then
        return 0
    end

    local tool = false
    for _, ua in ipairs(uas) do
        if is_offensive_tool(ua:lower()) then
            tool = true
            break
        end
    end
    if not tool then
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

    -- 只有 9101102（2xx 访问成功）需要做软 404 抑制。
    -- 9101101（探测）和 9101107（401/403 被保护但仍被探测）不能被
    -- 登录页/WAF 页误抑制，因此按当前规则 SID 分支。
    local sid = 0
    local sig = rule.get_rule()
    if sig ~= nil and type(sig) ~= "string" then
        sid = sig:sid()
    end

    if sid == 9101102 then
        local response_line = tx:response_line()
        if type(response_line) == "string" and #response_line > 0 then
            local body = read_body(tx, MAX_BODY)
            if is_soft_404(tx, body) then
                return 0
            end
        end
    end

    return 1
end
