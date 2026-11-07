-- ============================================================================
-- 后门通信 · WebShell 命令参数检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI 查询、POST Body、Cookie、请求头中的参数名和值。
-- 修复原规则把参数名/值写反的问题：既看 cmd=id，也看 POST cmd=whoami。
-- 已知路径 + 命令参数名本身即可告警；未知路径要求参数值有命令/代码语义。
-- 对 z0/z1/z2/z3/pass 等 AntSword/China Chopper 风格参数尝试 base64 解码。
-- ============================================================================

local http = require("suricata.http")

local MAX_BODY = 16384

local CORE_PARAMS = {
    cmd = true, exec = true, command = true, execute = true,
    shell = true, pass = true, password = true, pwd = true,
    z0 = true, z1 = true, z2 = true, z3 = true,
    action = true, method = true, func = true, ["function"] = true,
    eval = true, code = true, run = true, ["do"] = true,
}

local TOOL_PARAMS = {
    cmd = true, exec = true, command = true, execute = true,
    pass = true, password = true, pwd = true,
    z0 = true, z1 = true, z2 = true, z3 = true,
}

local COMMANDS = {
    "id", "whoami", "cat", "ls", "dir", "uname", "ifconfig",
    "ipconfig", "pwd", "echo", "system", "exec", "eval", "assert",
    "passthru", "shell_exec", "cmd.exe", "powershell", "net user",
    "cat /etc/passwd", "/etc/passwd", "uid=", "gid=",
}

local CODE_MARKERS = {
    "<?php", "<?=", "eval(", "assert(", "system(", "passthru(",
    "shell_exec(", "base64_decode", "runtime.getruntime",
    "processbuilder", "request[",
}

local KNOWN_NAMES = {
    "rce", "cmd", "shell", "backdoor", "wso", "b374k", "c99",
    "cmdjsp", "gsl", "godzilla", "behinder", "ants", "n1nty",
    "webshell", "webshells", "c100", "r57", "phpspy", "milw0rm",
}

local KNOWN_EXTS = {
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

local function normalize_path(uri)
    uri = decode(uri, 2):lower()
    uri = uri:gsub("\\", "/")
    local path = uri:match("^[^?]*") or uri
    return path
end

local function is_known_path(path)
    for segment in path:gmatch("[^/]+") do
        local name, ext = segment:match("^([%w%-_]+)%.([%w]+)$")
        if name ~= nil then
            for _, known in ipairs(KNOWN_NAMES) do
                if name == known then
                    for _, e in ipairs(KNOWN_EXTS) do
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

local function value_has_command(value)
    value = value:lower()
    for _, marker in ipairs(CODE_MARKERS) do
        if value:find(marker, 1, true) then
            return true
        end
    end
    for _, cmd in ipairs(COMMANDS) do
        if value == cmd then
            return true
        end
        local escaped = cmd:gsub("(%W)", "%%%1")
        if value:find("%f[%w]" .. escaped .. "%f[%W]") then
            return true
        end
        if value:find("%f[%w]" .. escaped .. "$") then
            return true
        end
        if value:find(escaped, 1, true) and cmd:find(" ") then
            return true
        end
    end
    return false
end

local function valid_base64(value)
    if #value < 8 or #value % 4 == 1 then
        return false
    end
    if value:find("=") and #value % 4 ~= 0 then
        return false
    end
    local body = value:gsub("=+$", "")
    if #body % 4 == 1 then
        return false
    end
    return value:match("^[A-Za-z0-9+/]+={0,2}$") ~= nil
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- 纯 Lua base64 解码：避免沙箱 base64 库在异常输入上 luaL_error，
-- 也避免依赖 Rust base64 的具体 padding 模式。
local function b64decode(value)
    local clean = value:gsub("[^%w%+/=]", "")
    local out = {}
    local function val(ch)
        if ch == "" or ch == "=" then
            return -1
        end
        local pos = B64:find(ch, 1, true)
        if pos == nil then
            return -1
        end
        return pos - 1
    end

    for i = 1, #clean, 4 do
        local c1 = clean:sub(i, i)
        local c2 = clean:sub(i + 1, i + 1)
        local c3 = clean:sub(i + 2, i + 2)
        local c4 = clean:sub(i + 3, i + 3)
        local v1, v2 = val(c1), val(c2)
        if v1 < 0 or v2 < 0 then
            break
        end
        out[#out + 1] = string.char(v1 * 4 + math.floor(v2 / 16))
        local v3 = val(c3)
        if v3 < 0 then
            break
        end
        out[#out + 1] = string.char((v2 % 16) * 16 + math.floor(v3 / 4))
        local v4 = val(c4)
        if v4 < 0 then
            break
        end
        out[#out + 1] = string.char((v3 % 4) * 64 + v4)
    end
    return table.concat(out)
end

local function decoded_has_command(value)
    if not valid_base64(value) then
        return false
    end
    local decoded = b64decode(value)
    if #decoded == 0 then
        return false
    end
    return value_has_command(decoded)
end

local function add_params(out, text, separator, prefix)
    for pair in text:gmatch("[^" .. separator .. "]+") do
        local key, value = pair:match("^([^=]+)=(.*)$")
        if key ~= nil then
            if prefix ~= nil and key:sub(1, #prefix) == prefix then
                key = key:sub(#prefix + 1)
            end
            key = key:gsub("^%s+", ""):gsub("%s+$", "")
            value = value:gsub("^%s+", ""):gsub("%s+$", "")
            out[#out + 1] = { key = key:lower(), value = value }
        end
    end
end

local function params(tx)
    local out = {}
    local uri = tx:request_uri_raw()
    if type(uri) == "string" and #uri > 0 then
        local normalized = decode(uri, 2):lower()
        local query = normalized:match("%?(.*)$")
        if query ~= nil then
            add_params(out, query, "&", nil)
        end
    end

    local body = read_body(tx)
    if type(body) == "string" and #body > 0 then
        local normalized = decode(body, 2):lower()
        add_params(out, normalized, "&", nil)
        for _, key in ipairs({
            "cmd", "exec", "command", "execute", "pass", "password",
            "pwd", "z0", "z1", "z2", "z3", "action", "method",
            "func", "function", "eval", "code", "run", "do",
        }) do
            local value = normalized:match('"' .. key .. '"%s*:%s*"([^"]*)"')
            if value ~= nil then
                out[#out + 1] = { key = key, value = value }
            end
        end
    end

    local cookie = tx:request_header("Cookie")
    if type(cookie) == "string" and #cookie > 0 then
        local normalized = decode(cookie, 2):lower()
        add_params(out, normalized, ";", nil)
        add_params(out, normalized, "&", nil)
    end

    local headers = tx:request_headers_raw()
    if type(headers) == "string" and #headers > 0 then
        local normalized = decode(headers, 2):lower()
        for line in normalized:gmatch("[^\r\n]+") do
            local name, value = line:match("^([%w%-_]+):%s*(.*)$")
            if name ~= nil and #value > 0 then
                local key = name:gsub("^x%-", "")
                if CORE_PARAMS[key] then
                    out[#out + 1] = { key = key, value = value }
                end
            end
        end
    end

    return out
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local uri = tx:request_uri_raw()
    local known_path = false
    if type(uri) == "string" then
        known_path = is_known_path(normalize_path(uri))
    end

    for _, param in ipairs(params(tx)) do
        if CORE_PARAMS[param.key] and #param.value > 0 then
            if known_path and TOOL_PARAMS[param.key] then
                return 1
            end
            if value_has_command(param.value) then
                return 1
            end
            if TOOL_PARAMS[param.key] and decoded_has_command(param.value) then
                return 1
            end
        end
    end

    return 0
end
