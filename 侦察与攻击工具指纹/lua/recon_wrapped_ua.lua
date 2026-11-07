-- ============================================================================
-- 侦察与攻击工具指纹 · 已知工具 UA 包裹变体
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 26 条工具规则对部分工具使用 ^ 开头匹配。真实/自定义 UA 可能写成：
--   Mozilla/5.0 (compatible; sqlmap/1.8.8)
--   SomeClient/1.0 Nuclei/3.1
-- 本脚本只在“已知工具 token 不在 UA 开头”时返回 1，交给 triage 规则；
-- 开头匹配仍由对应工具 SID 负责，避免重复告警。
--
-- 不包含 httpx（避免 python-httpx/）；不包含已由分隔符边界覆盖的工具。
-- ============================================================================

local http = require("suricata.http")

local WRAPPED_PATTERNS = {
    "%f[%w]fuzz faster u fool%f[%W]",
    "%f[%w]gobuster/",
    "%f[%w]feroxbuster/",
    "%f[%w]sqlmap/",
    "%f[%w]nuclei%f[%W]",
    "%f[%w]masscan/",
    "%f[%w]zgrab/",
    "%f[%w]whatweb/",
    "%f[%w]arjun/",
    "%f[%w]wafw00f/",
    "%f[%w]commix/",
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

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    for _, ua in ipairs(collect_user_agents(tx)) do
        ua = ua:lower()
        for _, pat in ipairs(WRAPPED_PATTERNS) do
            local pos = ua:find(pat)
            if pos ~= nil and pos > 1 then
                return 1
            end
        end
    end
    return 0
end
