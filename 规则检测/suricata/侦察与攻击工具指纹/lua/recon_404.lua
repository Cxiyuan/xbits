-- ============================================================================
-- 侦察与攻击工具指纹 · 403/404 高频突发（不依赖 UA）
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 目录/路径爆破除了敏感路径，还会请求大量随机/普通路径；攻击者改 UA 后，
-- UA 规则和敏感路径规则都可能失效。本脚本只判断“当前响应是否值得计数”：
--   - 排除根路径、/.well-known/、favicon/robots/sitemap 等正常缺失资源；
--   - 排除静态资源扩展名；
--   - 其余 403/404 交给规则上的 type both 阈值限频。
-- 不做跨包聚合；计数由 Suricata threshold 完成。
-- ============================================================================

local http = require("suricata.http")

local EXACT_SKIP = {
    ["/"] = true,
    ["/favicon.ico"] = true,
    ["/robots.txt"] = true,
    ["/sitemap.xml"] = true,
    ["/apple-touch-icon.png"] = true,
    ["/apple-touch-icon-precomposed.png"] = true,
    ["/manifest.json"] = true,
    ["/manifest.webmanifest"] = true,
    ["/service-worker.js"] = true,
    ["/sw.js"] = true,
    ["/browserconfig.xml"] = true,
}

local EXT_SKIP = {
    js = true, mjs = true, css = true, map = true,
    png = true, jpg = true, jpeg = true, gif = true, svg = true,
    ico = true, webp = true, avif = true, bmp = true,
    woff = true, woff2 = true, ttf = true, eot = true, otf = true,
    mp4 = true, webm = true, mp3 = true, wav = true, ogg = true,
    pdf = true, zip = true, gz = true, tar = true, rar = true,
    txt = true, xml = true, rss = true, atom = true,
}

local function normalize_path(uri)
    uri = uri:lower()
    uri = uri:gsub("^https?://[^/]+", "")
    uri = uri:gsub("\\", "/")
    local path = uri:match("^[^?]*") or ""
    path = path:gsub("//+", "/")
    if #path == 0 then
        return "/"
    end
    return path
end

local function get_path(tx)
    local uri = tx:request_uri_normalized()
    if type(uri) ~= "string" or #uri == 0 then
        uri = tx:request_uri_raw()
    end
    if type(uri) ~= "string" or #uri == 0 then
        return ""
    end
    return normalize_path(uri)
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local path = get_path(tx)
    if #path == 0 or EXACT_SKIP[path] then
        return 0
    end
    if path:find("^/%.well%-known/") then
        return 0
    end

    local ext = path:match("%.([%w]+)$")
    if ext ~= nil and EXT_SKIP[ext] then
        return 0
    end

    return 1
end
