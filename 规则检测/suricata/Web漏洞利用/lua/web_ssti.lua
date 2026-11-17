-- ============================================================================
-- Web 漏洞利用 · SSTI 检测
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI/请求体/Cookie/请求头中的模板表达式。
-- 普通变量插值 {{name}} 不算；需要模板定界符 + 算术/危险对象访问。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local DANGEROUS = {
    "__class__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "os.popen",
    "subprocess",
    "freemarker.template.utility.execute",
    "java.lang.runtime",
    "getruntime().exec",
    "system(",
}

local ARITHMETIC = {
    "{{%s*%d+%s*[*+%-/]%s*%d+%s*}}",
    "{{%s*'[^']*'%s*[*+%-/]%s*%d+%s*}}",
    "%${%s*%d+%s*[*+%-/]%s*%d+%s*}",
    "#{%s*%d+%s*[*+%-/]%s*%d+%s*}",
    "<%%=%s*%d+%s*[*+%-/]%s*%d+%s*%%>",
    "%*{%s*%d+%s*[*+%-/]%s*%d+%s*}",
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
            out[#out + 1] = decode(value, 2):lower()
        end
    end
    add(tx:request_uri_raw())
    add(tx:request_uri_normalized())
    add(read_body(tx))
    add(tx:request_headers_raw())
    add(tx:request_header("Cookie"))
    return out
end

local function has_any(s, list)
    for _, token in ipairs(list) do
        if s:find(token, 1, true) then
            return true
        end
    end
    return false
end

local function has_delimiter(s)
    return s:find("{{", 1, true) ~= nil
        or s:find("${", 1, true) ~= nil
        or s:find("#{", 1, true) ~= nil
        or s:find("<%=", 1, true) ~= nil
        or s:find("*{", 1, true) ~= nil
end

local function detect(s)
    for _, pat in ipairs(ARITHMETIC) do
        if s:find(pat) then
            return true
        end
    end
    if has_delimiter(s) and has_any(s, DANGEROUS) then
        return true
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
        if detect(source) then
            return 1
        end
    end
    return 0
end
