-- ============================================================================
-- Web 漏洞利用 · 命令注入检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI、请求体、Cookie、请求头；识别 Shell 元字符后紧跟系统命令，
-- 支持 URL 编码、换行、反引号、$(...)、${IFS} 等变体。
-- 不把普通查询参数（如 &id=2、&cat=3）当作命令注入。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local COMMANDS = {
    "id", "whoami", "cat", "ls", "uname", "ifconfig", "ipconfig",
    "pwd", "wget", "curl", "nc", "ncat", "bash", "sh", "cmd.exe",
    "powershell", "python", "perl", "sleep", "ping", "echo", "rm",
    "chmod", "base64", "nslookup", "dig", "tftp", "certutil",
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

local function sources(tx)
    local out = {}
    local function add(value)
        if type(value) == "string" and #value > 0 then
            out[#out + 1] = value
        end
    end
    add(tx:request_uri_raw())
    add(tx:request_uri_normalized())
    add(read_body(tx))
    add(tx:request_headers_raw())
    add(tx:request_header("Cookie"))
    return out
end

local function normalize(s)
    s = decode(s, 2):lower()
    s = s:gsub("%+", " ")
    return s
end

local function detect(s)
    for _, command in ipairs(COMMANDS) do
        local cmd = command:gsub("%.", "%%.")
        local patterns = {
            "[;|&`\r\n]%s*" .. cmd .. "[%s;|&`<>/)]",
            "[;|&`\r\n]%s*" .. cmd .. "$",
            "%$%(%s*" .. cmd .. "[%)%s;|&`<>/]",
            "%$%{IFS%}%s*" .. cmd,
            cmd .. "%$%{IFS%}",
            cmd .. "%$IFS",
        }
        for _, pat in ipairs(patterns) do
            if s:find(pat) then
                return true
            end
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
        if detect(normalize(source)) then
            return 1
        end
    end
    return 0
end
