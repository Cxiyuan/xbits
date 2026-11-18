-- ============================================================================
-- 信息泄露规则 · 响应上下文增强
-- 目标: Suricata 8.0.8 / Lua 5.4
--
-- 只在响应侧确认：响应成功/被拒绝、内容类型是文本、响应体出现真实泄露
-- 标记，或请求路径命中敏感文件扩展。避免“URL 里出现文件名”就告警。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local MARKERS = {
    "root:x:0:0", "<?php", "phpinfo()", "server-status", "index of /",
    "db_password", "db_passwd", "aws_access_key", "private key",
    "begin rsa private key", "begin openssh private key",
    "apache server", "nginx", "microsoft windows", "volume serial number",
}

local SENSITIVE_EXT = {
    env = true, git = true, svn = true, htpasswd = true, conf = true,
    config = true, bak = true, backup = true, old = true, log = true,
    sql = true, zip = true, tar = true, gz = true, tgz = true,
    pem = true, key = true, ini = true, yml = true, yaml = true,
}

local function read_body(tx)
    local chunks = tx:response_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = MAX_BODY - total
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

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local line = tx:response_line()
    if type(line) ~= "string" then
        return 0
    end
    local status = tonumber(line:match("^HTTP/%d%.%d%s+(%d%d%d)"))
    if status ~= 200 and status ~= 206 and status ~= 403 and status ~= 500 then
        return 0
    end

    local ctype = tx:response_header("Content-Type")
    if type(ctype) == "string" and #ctype > 0 then
        ctype = ctype:lower()
        if not (ctype:find("text/", 1, true) or ctype:find("json", 1, true)
            or ctype:find("xml", 1, true) or ctype:find("html", 1, true)) then
            return 0
        end
    end

    local body = read_body(tx):lower()
    if #body > 0 then
        for _, marker in ipairs(MARKERS) do
            if body:find(marker, 1, true) then
                return 1
            end
        end
    end

    local uri = tx:request_uri_raw()
    if type(uri) ~= "string" then
        uri = tx:request_uri_normalized()
    end
    if type(uri) == "string" then
        local path = (uri:match("^[^?]*") or uri):lower()
        local ext = path:match("%.([%w]+)$")
        if ext ~= nil and SENSITIVE_EXT[ext] and status == 200 then
            return 1
        end
    end

    return 0
end