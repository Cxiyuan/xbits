-- ============================================================================
-- 侦察与攻击工具指纹 · 互联网测绘/资产扫描 UA
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 与 recon_ua.lua 分离：Shodan/Censys/Expanse/masscan/zgrab/l9explore
-- 属于测绘/资产发现，不升级成 High 攻击工具告警。
-- ============================================================================

local http = require("suricata.http")

local START_PATTERNS = {
    "^masscan/",
    "^zgrab/",
    "^l9explore%f[%W]",
}

local CONTAINS_PATTERNS = {
    "shodan/",
    "censysinspect/",
    "expanse/",
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

local function is_scanner(ua)
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
    if tx == nil or type(tx) == "string" then
        return 0
    end

    for _, ua in ipairs(collect_user_agents(tx)) do
        if is_scanner(ua:lower()) then
            return 1
        end
    end
    return 0
end
