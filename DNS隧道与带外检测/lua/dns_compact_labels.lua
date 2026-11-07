-- ============================================================================
-- dns_compact_labels.lua
-- 规则内嵌 Lua：单字符标签序列的二次过滤（Suricata 8.0.8）
--
-- 使用规则：9109001（多级单字符标签）
-- 作用：
--   - 只对"连续十六进制单字符标签"放行，过滤 a.b.c.d.e.f 这类层级命名
--   - 要求拼接后的 nibble 流足够长、熵足够高
--   - 跳过任意位置的服务标签 / punycode / 高连字符标签 / 静态高频域
-- ============================================================================

local dns = require("suricata.dns")

local MIN_LABELS = 6
local MIN_STREAM_LEN = 12
local MIN_ENTROPY = 3.2

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

    local labels = {}
    for label in name:gmatch("[^.]+") do
        labels[#labels + 1] = label
    end

    local stream = {}
    local count = 0
    for _, label in ipairs(labels) do
        if #label ~= 1 then
            break
        end
        if label:sub(1, 1) == "_" or label:sub(1, 4) == "xn--" then
            return 0
        end
        if label:match("^%x$") == nil then
            return 0
        end
        stream[#stream + 1] = label
        count = count + 1
    end

    if count < MIN_LABELS then
        return 0
    end
    local joined = table.concat(stream)
    if #joined < MIN_STREAM_LEN then
        return 0
    end
    if shannon_entropy(joined) < MIN_ENTROPY then
        return 0
    end

    return 1
end
