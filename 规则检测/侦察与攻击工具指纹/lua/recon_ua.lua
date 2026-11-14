-- ============================================================================
-- 侦察与攻击工具指纹 · 已知攻击工具 User-Agent 精确匹配
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 仅用于规则内 lua: 调用。读取当前 HTTP 事务的所有 User-Agent 头，
-- 支持重复头、首尾空白、包裹在 Mozilla/5.0 (compatible; ...) 中的变体。
-- 仅覆盖攻击/漏洞扫描工具；Shodan/Censys/Expanse/masscan/zgrab/l9explore
-- 由 recon_scanner_ua.lua 单独处理，避免把测绘工具升级成 High 攻击告警。
--
-- httpx 只允许开头匹配，避免重新命中 python-httpx/。
-- ============================================================================

local http = require("suricata.http")

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

-- 任意位置 + 词边界；不包含 httpx。
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

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
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

local function is_tool(ua)
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
    if ua:find("nmap scripting engine", 1, true) then
        return true
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

    for _, ua in ipairs(collect_user_agents(tx)) do
        if is_tool(ua:lower()) then
            return 1
        end
    end
    return 0
end
