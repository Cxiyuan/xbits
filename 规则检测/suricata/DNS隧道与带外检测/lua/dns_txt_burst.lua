-- ============================================================================
-- dns_txt_burst.lua
-- 规则内嵌 Lua：TXT 查询突发的服务标签过滤（Suricata 8.0.8）
--
-- 使用规则：9109103（TXT 查询突发）
-- 作用：
--   - 跳过邮件认证/服务发现查询：任意 label 以 "_" 开头
--   - 跳过 _domainkey/_dmarc/_spf/_acme-challenge/_mta-sts 等
--   - 跳过 apex TXT（常见 SPF），只保留有子域的 TXT 查询
-- ============================================================================

local dns = require("suricata.dns")

function init(args)
    return {}
end

local function first_query(tx)
    local queries = tx:queries()
    if not queries then
        return nil
    end
    for _, query in pairs(queries) do
        return query
    end
    return nil
end

local function is_service_name(name)
    for label in name:gmatch("[^.]+") do
        if label:sub(1, 1) == "_" then
            return true
        end
    end
    if name:find("_domainkey", 1, true) or name:find("_dmarc", 1, true)
        or name:find("_acme-challenge", 1, true) or name:find("_spf", 1, true)
        or name:find("_mta-sts", 1, true) or name:find("_sip", 1, true)
        or name:find("_ldap", 1, true) or name:find("_kerberos", 1, true)
        or name:find("_vlmcs", 1, true) or name:find("_msdcs", 1, true) then
        return true
    end
    return false
end

function match(args)
    local tx = dns.get_tx()
    if not tx then
        return 0
    end

    local query = first_query(tx)
    if not query then
        return 0
    end

    local name = (query["rrname"] or ""):lower()
    name = name:gsub("%.$", "")
    local qtype = (query["type"] or ""):upper()

    if qtype ~= "TXT" then
        return 0
    end
    if #name < 4 then
        return 0
    end

    if is_service_name(name) then
        return 0
    end

    local depth = 0
    for _ in name:gmatch("[^.]+") do
        depth = depth + 1
    end
    if depth <= 2 then
        return 0
    end

    return 1
end
