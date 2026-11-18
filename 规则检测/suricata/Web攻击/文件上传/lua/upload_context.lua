-- ============================================================================
-- Web 漏洞利用 · WebShell 上传检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- multipart 上传中同时出现：
--   1) 可执行脚本扩展名（php/jsp/asp/aspx/...）；
--   2) 脚本代码标记（<?php、<% 、eval(、system( 等）。
-- 只有文件名没有代码标记、或只有普通文件内容，不告警。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local SCRIPT_EXTS = {
    "php", "php3", "php4", "php5", "phtml", "phar",
    "jsp", "jspx", "jspf", "asp", "aspx", "ashx", "asmx",
    "cgi", "pl", "py", "rb",
}

local CODE_MARKERS = {
    "<?php",
    "<?=",
    "<%",
    "<%@",
    "eval(",
    "system(",
    "base64_decode",
    "cmd.exe",
    "request[",
    "runtime.getruntime",
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

local function read_body(tx)
    local chunks = tx:request_body()
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

local function has_any(s, list)
    for _, token in ipairs(list) do
        if s:find(token, 1, true) then
            return true
        end
    end
    return false
end

local function has_script_filename(s)
    local pos = s:find("filename", 1, true)
    while pos ~= nil do
        local window = s:sub(pos, pos + 300)
        for _, ext in ipairs(SCRIPT_EXTS) do
            if window:find("%." .. ext .. "%f[%W]") then
                return true
            end
        end
        pos = s:find("filename", pos + 8, true)
    end
    return false
end

local function detect(body, content_type)
    if #body == 0 then
        return false
    end
    body = decode(body, 2):lower()
    content_type = type(content_type) == "string" and content_type:lower() or ""

    if content_type:find("application/x-httpd-php", 1, true)
        or content_type:find("application/x-php", 1, true) then
        if has_any(body, CODE_MARKERS) then
            return true
        end
    end

    if not has_script_filename(body) then
        return false
    end
    return has_any(body, CODE_MARKERS)
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local body = read_body(tx)
    if detect(body, tx:request_header("Content-Type")) then
        return 1
    end
    return 0
end
