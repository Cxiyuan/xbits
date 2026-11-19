-- ============================================================================
-- Web 漏洞利用 · 路径穿越 / LFI 检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI、请求体、Cookie、请求头；支持 URL 编码、反斜杠、双重编码、
-- 单级/多级 ../、敏感文件、协议包装器和文件参数。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

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

local function sources(tx)
    local out = {}
    local function add(value, kind)
        if type(value) == "string" and #value > 0 then
            out[#out + 1] = { text = value, kind = kind }
        end
    end
    add(tx:request_uri_raw(), "uri")
    add(tx:request_uri_normalized(), "uri")
    add(read_body(tx), "body")
    add(tx:request_headers_raw(), "headers")
    add(tx:request_header("Cookie"), "cookie")
    return out
end

local function normalize(s)
    s = decode(s, 2):lower()
    s = s:gsub("\\", "/")
    s = s:gsub("%z", "")
    s = s:gsub(";", "")
    return s
end

local SENSITIVE = {
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "etc/group",
    "proc/self/environ",
    "proc/self/cmdline",
    "proc/version",
    "root/.ssh/id_rsa",
    "/.ssh/id_rsa",
    "windows/win.ini",
    "windows/system32/",
    "win.ini",
    "boot.ini",
    "web-inf/web.xml",
}

local WRAPPERS = {
    "php://filter",
    "php://input",
    "data://",
    "expect://",
    "phar://",
    "zip://",
    "file://",
    "jar://",
    "netdoc://",
}

local FILE_PARAMS = {
    "file", "path", "page", "include", "template", "view", "doc",
    "url", "download", "read", "load", "lang", "dir", "filename",
    "folder", "image", "src", "source",
}

local function has_any(s, list)
    for _, token in ipairs(list) do
        if s:find(token, 1, true) then
            return true
        end
    end
    return false
end

local function count_traversal(s)
    local _, count = s:gsub("%.%./", "")
    return count
end

local function has_file_param(s)
    for _, name in ipairs(FILE_PARAMS) do
        if s:find(name .. "=", 1, true) then
            return true
        end
        if s:find('"' .. name .. '":', 1, true) then
            return true
        end
        if s:find("'" .. name .. "':", 1, true) then
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
    if tx == nil or type(tx) == "string" then
        return 0
    end

    for _, source in ipairs(sources(tx)) do
        local s = normalize(source.text)
        if #s > 0 then
            local traversals = count_traversal(s)
            local sensitive = has_any(s, SENSITIVE)
            local wrapper = has_any(s, WRAPPERS)
            local file_param = has_file_param(s)

            -- 单级 ../ 必须叠加敏感文件；两级以上本身已经足够可疑。
            if traversals > 0 and (sensitive or traversals >= 2) then
                return 1
            end
            -- file:// 等包装器在 XXE 的 <!ENTITY SYSTEM "file:///..."> 中也会出现；
            -- 这里要求 LFI 语义（文件参数/穿越），避免与 XXE 规则互相误报。
            if wrapper and (file_param or traversals > 0
                or (source.kind == "uri" and sensitive)) then
                return 1
            end
            if sensitive and file_param then
                return 1
            end
            -- 直接访问 /etc/passwd 这类 URI 路径，不要求参数名。
            if source.kind == "uri" and sensitive and s:sub(1, 5) == "/etc/" then
                return 1
            end
        end
    end
    return 0
end
