-- ============================================================================
-- dns_tunnel_response.lua
-- 规则内嵌 Lua：响应侧 TXT/NULL/CNAME 载荷评分（Suricata 8.0.8）
--
-- 使用规则：9109202（响应侧线索，tier triage）
--
-- 强化点：
--   - TXT/NULL 载荷内容分类：SPF/DKIM/DMARC/域名验证前缀、人类可读文本不告警
--   - 只对高熵、base64/hex 形态的载荷给高置信
--   - CNAME target 的熵/长度分析（补 CNAME 隧道）
--   - 任意位置的服务标签、punycode、高连字符标签跳过
--   - qname 无结构特征时不因 TXT 大而告警
-- ============================================================================

local dns = require("suricata.dns")

local HEX = "0123456789abcdef"
local B32 = "abcdefghijklmnopqrstuvwxyz234567"
local B64 = "abcdefghijklmnopqrstuvwxyz0123456789-_"

local SCORE_THRESHOLD = 4.0
local TXT_SMALL = 100
local TXT_LARGE = 512
local ENTROPY_QNAME = 3.5
local ENTROPY_GUARD = 3.2
local LABEL_GUARD = 15
local LABEL_SUSPECT = 20
local DEPTH_GUARD = 4
local PAYLOAD_ENTROPY = 3.8
local CNAME_ENTROPY = 3.8
local CNAME_LABEL = 30

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

local VERIFICATION_PREFIXES = {
    "v=spf1", "v=dkim1", "v=dmarc1", "google-site-verification",
    "ms=", "facebook-domain-verification", "atlassian-domain-verification",
    "apple-domain-verification", "docusign=", "zoom-verification=",
    "adobe-idp-site-verification", "have-a-nice-day",
    "domain-verification", "site-verification",
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
    value = value:lower()
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

local function payload_is_human_readable(payload)
    local lower = payload:lower()
    for _, prefix in ipairs(VERIFICATION_PREFIXES) do
        if lower:find(prefix, 1, true) then
            return true
        end
    end
    local textual = 0
    for i = 1, #payload do
        local c = payload:sub(i, i)
        if c == " " or c == "\n" or c == "\t" or c == "="
            or c == ";" or c == "," or c == ":" then
            textual = textual + 1
        end
    end
    return textual / math.max(#payload, 1) > 0.02
end

local function analyze_name(name)
    local depth = 0
    local sum_len = 0
    local max_len = 0
    local max_ent = 0.0
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
        if entropy > max_ent then
            max_ent = entropy
        end
    end

    return {
        depth = depth,
        max_len = max_len,
        avg_len = (depth > 0 and sum_len / depth or 0.0),
        max_ent = max_ent,
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

local function analyze_target(target)
    local max_len = 0
    local max_ent = 0.0
    for label in target:gmatch("[^.]+") do
        if #label > max_len then
            max_len = #label
        end
        local entropy = shannon_entropy(label)
        if entropy > max_ent then
            max_ent = entropy
        end
    end
    return max_len, max_ent
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

    if qtype == "PTR" or qtype == "NS" or qtype == "SOA"
        or qtype == "MX" or qtype == "SRV" then
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

    local answers = tx:answers()
    if not answers then
        return 0
    end

    local answer_cnt = 0
    local txt_cnt = 0
    local null_cnt = 0
    local txt_bytes = 0
    local ttl_min = nil
    local payload = ""
    local cname_len = 0
    local cname_ent = 0.0

    for _, answer in pairs(answers) do
        answer_cnt = answer_cnt + 1
        local rtype = (answer["type"] or ""):upper()
        local addr = answer["addr"] or ""
        if rtype == "TXT" then
            txt_cnt = txt_cnt + 1
            txt_bytes = txt_bytes + #addr
            payload = payload .. addr
        elseif rtype == "NULL" then
            null_cnt = null_cnt + 1
            txt_bytes = txt_bytes + #addr
            payload = payload .. addr
        elseif rtype == "CNAME" then
            local len, ent = analyze_target(addr)
            if ent > cname_ent then
                cname_ent = ent
            end
            if len > cname_len then
                cname_len = len
            end
        end
        local ttl = answer["ttl"]
        if type(ttl) == "number" and (ttl_min == nil or ttl < ttl_min) then
            ttl_min = ttl
        end
    end

    -- 人类可读的 TXT（SPF/DKIM/域名验证）不计入大载荷
    if txt_bytes > 0 and payload_is_human_readable(payload) then
        txt_bytes = 0
        txt_cnt = 0
        null_cnt = 0
    end

    local cname_suspicious = cname_ent >= CNAME_ENTROPY or cname_len >= CNAME_LABEL
    if txt_bytes == 0 and not cname_suspicious then
        return 0
    end
    if a.max_ent < ENTROPY_GUARD and a.max_len < LABEL_GUARD
        and a.depth < DEPTH_GUARD and not cname_suspicious then
        return 0
    end

    local score = 0.0
    if txt_bytes >= TXT_SMALL then
        score = score + 2.0
    end
    if txt_bytes >= TXT_LARGE then
        score = score + 1.0
    end
    if txt_cnt + null_cnt >= 1 then
        score = score + 1.0
    end
    if txt_bytes > 0 then
        local payload_ent = shannon_entropy(payload)
        local b64 = charset_ratio(payload, B64)
        local hex = charset_ratio(payload, HEX)
        if null_cnt > 0 and payload_ent >= 3.5 then
            score = score + 1.5
        elseif payload_ent >= PAYLOAD_ENTROPY and math.max(b64, hex) >= 0.85 then
            score = score + 1.5
        end
    end
    if a.max_ent >= ENTROPY_QNAME then
        score = score + 1.5
    end
    if a.max_len >= LABEL_SUSPECT then
        score = score + 1.0
    end
    if cname_suspicious then
        score = score + 3.0
    end
    if answer_cnt <= 3 then
        score = score + 0.5
    end
    if ttl_min ~= nil and ttl_min <= 60 then
        score = score + 0.5
    end
    if (tx:rcode_string() or "") == "NXDOMAIN" then
        score = score - 1.0
    end

    if score >= SCORE_THRESHOLD then
        return 1
    end
    return 0
end
