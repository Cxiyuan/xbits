-- ============================================================================
-- 侦察与攻击工具指纹 · 已知工具 User-Agent 精确匹配
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 仅用于规则内 lua: 调用。读取当前 HTTP 事务的 User-Agent，按“前缀/边界”
-- 判断是否为已知工具默认 UA，避免 content 子串误报：
--   httpx           != python-httpx/
--   Java/           != JavaScript/
--   Nuclei          != 任意包含 Nuclei 的浏览器 UA
--
-- 返回 1: 命中已知工具；返回 0: 未命中或 UA 缺失。
-- UA 可伪造；本脚本只做规范化与边界判断，不把 UA 当作攻击成功证据。
-- ============================================================================

local http = require("suricata.http")

-- 以 UA 开头匹配的工具（小写后比较）。
-- %f[%W] 是 Lua 的 frontier：要求前缀后面是非字母数字字符或字符串结束。
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
    "^masscan/",
    "^zmeu%f[%W]",
    "^morfeus%f[%W]",
    "^zgrab/",
    "^nessus%f[%W]",
    "^openvas%f[%W]",
    "^whatweb/",
    "^httpx%f[%W]",
    "^arjun/",
    "^wafw00f/",
    "^commix/",
    "^xsstrike%f[%W]",
    "^l9explore%f[%W]",
}

-- 可能被包在 Mozilla/5.0 (compatible; ...) 中的测绘/扫描器。
local CONTAINS_PATTERNS = {
    "shodan/",
    "censysinspect/",
    "expanse/",
    "nmap scripting engine",
}

local function is_tool(ua)
    for _, pat in ipairs(START_PATTERNS) do
        if ua:find(pat) then
            return true
        end
    end
    for _, token in ipairs(CONTAINS_PATTERNS) do
        if ua:find(token, 1, true) then
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

    if is_tool(ua:lower()) then
        return 1
    end
    return 0
end
