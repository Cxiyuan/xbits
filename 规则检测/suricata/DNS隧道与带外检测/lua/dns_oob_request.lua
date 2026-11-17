-- ============================================================================
-- dns_oob_request.lua
-- 规则内嵌 Lua：OOB 平台域名的二次过滤（Suricata 8.0.8）
--
-- 使用规则：9109004（OAST/Interactsh）、9109005（其他公共 OOB 平台）
-- 作用：
--   - 拒绝平台根域（oast.pro）与过短的泛查询（x.oast.pro）
--   - 只对带随机 token 的子域放行（token 长度或熵达到阈值）
--   - 只允许 A/AAAA/TXT/CNAME，排除 MX/NS/SOA/PTR
--
-- 说明：授权红队/邮件沙箱引爆仍无法靠单事务判断，需要源地址抑制。
-- ============================================================================

local dns = require("suricata.dns")

local MIN_TOKEN_LEN = 6
local MIN_TOKEN_ENTROPY = 2.5

local function shannon_entropy(value)
    local n = #value
    if n == 0 then
        return 0.0
    end
    local counts = {}
    for i = 1, n do
        local c = value:sub(i, i)
        counts[c] = (counts[c] or 0) + 1
    end
    local h = 0.0
    for _, count in pairs(counts) do
        local p = count / n
        h = h - p * (math.log(p) / math.log(2))
    end
    return h
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

function init(args)
    return {}
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

    if qtype ~= "A" and qtype ~= "AAAA" and qtype ~= "TXT"
        and qtype ~= "CNAME" then
        return 0
    end

    local labels = {}
    for label in name:gmatch("[^.]+") do
        labels[#labels + 1] = label
    end
    if #labels < 3 then
        return 0
    end

    -- 平台域通常占最后两个 label；前面的 label 是交互 token
    local token_count = #labels - 2
    local max_len = 0
    local max_ent = 0.0
    for i = 1, token_count do
        local label = labels[i]
        if label:sub(1, 1) == "_" or label:sub(1, 4) == "xn--" then
            return 0
        end
        if #label > max_len then
            max_len = #label
        end
        local entropy = shannon_entropy(label)
        if entropy > max_ent then
            max_ent = entropy
        end
    end

    if max_len < MIN_TOKEN_LEN and max_ent < MIN_TOKEN_ENTROPY then
        return 0
    end
    return 1
end
