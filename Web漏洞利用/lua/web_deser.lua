-- ============================================================================
-- Web 漏洞利用 · Java 反序列化 / 框架利用
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 检查 URI、请求体、Cookie、请求头，按“有利用语义的上下文”判断：
--   - Fastjson：JSON @type/autoType + 危险类/gadget
--   - OGNL/Struts2：OGNL 对象访问 + Runtime/ProcessBuilder
--   - ThinkPHP：invokefunction + call_user_func_array/vars/think\app
--   - Java 序列化：rO0AB (base64) / aced0005 (hex)
--   - PHP 序列化：O:/a:/s: + __destruct/__wakeup/unserialize/phar://
--
-- 不把 URI 中出现 fastjson/ognl/thinkphp 这些普通单词当成攻击。
-- 仅凭 Shiro rememberMe Cookie 长度无法区分正常会话与加密 payload，
-- 因此不在本脚本中单独告警。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local FASTJSON_CLASSES = {
    "java.lang.runtime",
    "java.lang.processbuilder",
    "com.sun.rowset.jdbcrowsetimpl",
    "javax.naming.initialcontext",
    "com.alibaba.fastjson",
    "org.apache.tomcat",
    "com.mchange.v2.c3p0",
    "org.springframework",
    "java.net.url",
    "java.lang.class",
    "com.zaxxer.hikari",
    "org.apache.xbean",
    "org.apache.ibatis",
    "org.h2",
    "org.apache.commons.collections",
    "org.apache.xalan",
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
            out[#out + 1] = decode(value, 2)
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

local function detect(s)
    s = s:lower()

    -- Fastjson: @type/autoType 必须叠加危险类/gadget。
    if s:find("@type", 1, true) or s:find("autotype", 1, true) then
        if has_any(s, FASTJSON_CLASSES) then
            return true
        end
    end

    -- OGNL / Struts2：需要表达式标记 + 危险对象访问。
    if s:find("%{", 1, true) then
        if s:find("@java.", 1, true) or s:find("#_memberaccess", 1, true)
            or s:find("ognl.", 1, true) or s:find("getruntime().exec", 1, true) then
            return true
        end
    end
    if s:find("@java.lang.runtime@getruntime", 1, true)
        or s:find("@java.lang.processbuilder", 1, true)
        or s:find("getruntime().exec", 1, true) then
        return true
    end

    -- ThinkPHP：invokefunction + 调用链/变量注入。
    if s:find("invokefunction", 1, true) then
        if s:find("call_user_func_array", 1, true)
            or s:find("vars[", 1, true)
            or s:find("think\\app", 1, true)
            or s:find("think/app", 1, true) then
            return true
        end
    end

    -- Java 序列化 magic（base64/hex）。
    if s:find("ro0ab", 1, true) or s:find("aced0005", 1, true) then
        return true
    end

    -- PHP 序列化 + 反序列化/包装器语义。
    if s:find("unserialize", 1, true) or s:find("phar://", 1, true) then
        if s:find("o:%d+:\"") or s:find("a:%d+:{") or s:find("s:%d+:\"") then
            return true
        end
    end
    if (s:find("o:%d+:\"") or s:find("a:%d+:{")) and
        (s:find("__destruct", 1, true) or s:find("__wakeup", 1, true)) then
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
