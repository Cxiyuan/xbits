-- ============================================================================
-- dns_tunnel_request.lua
-- 规则内嵌 Lua：请求侧编码/结构评分（Suricata 8.0.8）
--
-- 使用规则：
--   9109201 请求侧主评分
--   9109002 32 位十六进制首标签（作为二次过滤）
--   9109003 UUID 首标签（作为二次过滤）
--   9109006 超长单标签（作为二次过滤）
--
-- 强化点：
--   - 任意位置的服务标签（_tcp/_ldap/_dmarc/...）直接跳过
--   - punycode（xn--）与高连字符标签跳过
--   - qtype 分级：A/AAAA 要求更强证据，TXT/NULL/CNAME 保持敏感
--   - RFC 4122 UUID 版本/变体校验（只给合法 UUID 加分）
--   - 静态高频域安全网（主白名单仍是规则里的 dataset）
-- ============================================================================

local dns = require("suricata.dns")

local HEX = "0123456789abcdef"
local B32 = "abcdefghijklmnopqrstuvwxyz234567"
local B64 = "abcdefghijklmnopqrstuvwxyz0123456789-_"

local SCORE_THRESHOLD = 3.5
local ENTROPY_HIGH = 3.8
local ENTROPY_MID = 3.0
local LABEL_LONG = 30
local ENCODED_LABEL_MIN = 10
local DEPTH_SUSPECT = 5
local NAME_LONG = 60
local A_ENTROPY_MIN = 3.8
local A_LABEL_MIN = 40
local A_ENCODED_TOTAL = 40

local SKIP_SUFFIX_LIST = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "office.net", "azure.com", "azureedge.net",
    "azurewebsites.net", "msedge.net", "live.com", "msn.com", "bing.com",
    "skype.com", "xboxlive.com", "apple.com", "icloud.com", "mzstatic.com",
    "apple-dns.net", "cdn-apple.com", "google.com", "googleapis.com",
    "gstatic.com", "googleusercontent.com", "googlevideo.com", "gvt1.com",
    "youtube.com", "ggpht.com", "google-analytics.com", "cloudflare.com",
    "cloudflare.net", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "akamaihd.net", "edgekey.net", "edgesuite.net", "fastly.net",
    "fastlylb.net", "llnwd.net", "cdn77.org", "amazonaws.com", "amazon.com",
    "media-amazon.com", "facebook.com", "fbcdn.net", "instagram.com",
    "cdninstagram.com", "whatsapp.net", "netflix.com", "nflxvideo.net",
    "spotify.com", "scdn.co", "zoom.us", "slack.com", "github.com",
    "githubusercontent.com", "sentry.io", "mozilla.org", "mozilla.net",
    "ubuntu.com", "debian.org", "pypi.org", "npmjs.com", "docker.com",
    "docker.io", "adobe.com", "adobedc.net", "salesforce.com", "okta.com",
    "duosecurity.com", "dropbox.com", "box.com", "webex.com",
    "ringcentral.com", "crowdstrike.com", "sentinelone.net",
    "carbonblackcloud.com", "mcafee.com", "symantec.com", "trendmicro.com",
    "sophos.com", "kaspersky.com", "paloaltonetworks.com", "fortinet.com",
    "zscaler.com", "zscaler.net", "cisco.com", "umbrella.com",
}

local SKIP_SUFFIX = {}

function init(args)
    SKIP_SUFFIX = {}
    for _, suffix in ipairs(SKIP_SUFFIX_LIST) do
        SKIP_SUFFIX[suffix] = true
    end
    return {}
end

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

local function charset_ratio(value, alphabet)
    local n = #value
    if n == 0 then
        return 0.0
    end
    local hit = 0
    for i = 1, n do
        local c = value:sub(i, i)
        if alphabet:find(c, 1, true) then
            hit = hit + 1
        end
    end
    return hit / n
end

local function skip_name(name)
    local start = 1
    while true do
        if SKIP_SUFFIX[name:sub(start)] then
            return true
        end
        local dot = name:find(".", start, true)
        if not dot then
            break
        end
        start = dot + 1
        if start > #name then
            break
        end
    end
    return false
end

local function is_rfc4122(uuid)
    if #uuid ~= 36 then
        return false
    end
    if uuid:sub(9, 9) ~= "-" or uuid:sub(14, 14) ~= "-"
        or uuid:sub(19, 19) ~= "-" or uuid:sub(24, 24) ~= "-" then
        return false
    end
    local version = tonumber(uuid:sub(15, 15), 16)
    local variant = tonumber(uuid:sub(20, 20), 16)
    if not version or version < 1 or version > 5 then
        return false
    end
    if not variant or not (variant == 8 or variant == 9
        or variant == 10 or variant == 11) then
        return false
    end
    local hex = uuid:gsub("-", "")
    if #hex ~= 32 or hex:match("^%x+$") == nil then
        return false
    end
    return true
end

local function analyze_name(name)
    local depth = 0
    local sum_len = 0
    local max_len = 0
    local sum_ent = 0.0
    local max_ent = 0.0
    local encoded_total = 0
    local left = ""
    local has_service = false
    local has_punycode = false
    local hyphen_heavy = false

    for label in name:gmatch("[^.]+") do
        depth = depth + 1
        if depth == 1 then
            left = label
        end
        local len = #label
        sum_len = sum_len + len
        if len > max_len then
            max_len = len
        end
        if label:sub(1, 1) == "_" then
            has_service = true
        end
        if label:sub(1, 4) == "xn--" then
            has_punycode = true
        end
        local hyphens = select(2, label:gsub("-", ""))
        if len > 0 and hyphens / len > 0.25 then
            hyphen_heavy = true
        end
        local entropy = shannon_entropy(label)
        sum_ent = sum_ent + entropy
        if entropy > max_ent then
            max_ent = entropy
        end
        if len >= 4 and entropy >= ENTROPY_MID then
            encoded_total = encoded_total + len
        end
    end

    local avg_len = 0.0
    local avg_ent = 0.0
    if depth > 0 then
        avg_len = sum_len / depth
        avg_ent = sum_ent / depth
    end

    return {
        depth = depth,
        max_len = max_len,
        avg_len = avg_len,
        max_ent = max_ent,
        avg_ent = avg_ent,
        encoded_total = encoded_total,
        left = left,
        hex = charset_ratio(left, HEX),
        b32 = charset_ratio(left, B32),
        b64 = charset_ratio(left, B64),
        has_service = has_service,
        has_punycode = has_punycode,
        hyphen_heavy = hyphen_heavy,
    }
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

    if qtype == "PTR" then
        return 0
    end
    if #name < 6 or not name:find(".", 1, true) then
        return 0
    end
    if name:find("%.arpa$") then
        return 0
    end
    if skip_name(name) then
        return 0
    end

    local a = analyze_name(name)
    if a.has_service or a.has_punycode or a.hyphen_heavy then
        return 0
    end

    local uuid = is_rfc4122(a.left)

    -- A/AAAA 的容错更低：没有强证据就交给响应侧确认
    if qtype == "A" or qtype == "AAAA" then
        if not uuid and a.max_ent < A_ENTROPY_MIN
            and a.max_len < A_LABEL_MIN
            and a.encoded_total < A_ENCODED_TOTAL then
            return 0
        end
    end

    local score = 0.0
    if a.max_ent >= ENTROPY_HIGH then
        score = score + 2.0
    end
    if a.max_len >= LABEL_LONG then
        score = score + 1.5
    end
    if a.max_len >= ENCODED_LABEL_MIN
        and math.max(a.b32, a.b64) >= 0.90
        and a.max_ent >= ENTROPY_MID then
        score = score + 1.5
    end
    if a.depth >= DEPTH_SUSPECT then
        score = score + 1.0
    end
    if #name >= NAME_LONG then
        score = score + 1.0
    end
    if a.encoded_total >= A_ENCODED_TOTAL then
        score = score + 0.5
    end
    if qtype == "TXT" or qtype == "NULL" or qtype == "CNAME" then
        score = score + 1.0
    end
    if uuid then
        score = score + 0.5
    end

    if score >= SCORE_THRESHOLD then
        return 1
    end
    return 0
end
