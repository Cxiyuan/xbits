-- ============================================================================
-- 信息泄露规则 · 请求路径上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 请求侧规则常见问题是“URL 任何位置出现 httpd.conf/.git 等字符串就告警”。
-- 本脚本要求请求路径确实指向敏感文件/目录，再允许规则命中。
-- ============================================================================

local http = require("suricata.http")

-- xbits: 显式导出实际命中的精确 buffer（未打补丁的 Suricata 上为 nil，自动跳过）
local function xbits_export(value)
    if xbits_export_match ~= nil and type(value) == "string" and #value > 0 then
        xbits_export_match("lua", value)
    end
end


local SENSITIVE_PREFIX = {
    "/.git/", "/.svn/", "/.hg/", "/.env", "/.htpasswd", "/.htaccess",
    "/server-status", "/server-info", "/phpinfo", "/.well-known/",
    "/backup", "/backups/", "/config", "/conf/", "/web.config",
    "/wp-config", "/database", "/db/", "/logs/", "/log/", "/tmp/",
}

local SENSITIVE_EXT = {
    env = true, git = true, svn = true, htpasswd = true, conf = true,
    config = true, bak = true, backup = true, old = true, log = true,
    sql = true, zip = true, tar = true, gz = true, tgz = true,
    pem = true, key = true, ini = true, yml = true, yaml = true,
    inc = true, php = true, asp = true, aspx = true, jsp = true,
}

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" then
        uri = tx:request_uri_normalized()
    end
    if type(uri) ~= "string" or #uri == 0 then
        return 0
    end

    local path = (uri:match("^[^?]*") or uri):lower()
    path = path:gsub("\\", "/")

    for _, prefix in ipairs(SENSITIVE_PREFIX) do
        if path:find(prefix, 1, true) then
            xbits_export(path)
            return 1
        end
    end

    local ext = path:match("%.([%w]+)$")
    if ext ~= nil and SENSITIVE_EXT[ext] then
        xbits_export(path)
        return 1
    end
    return 0
end