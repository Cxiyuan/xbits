-- ============================================================================
-- 命令与控制信标 · C2 控制面板 API 多语义 token
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 9110005 不再对 /api/file/upload 这类通用路径单独告警。
-- 要求路径中出现：
--   - 至少一个 C2 主体 token（client/agent/beacon/panel/tunnel/...）；
--   - 且至少一个任务/操作 token（task/payload/session/exec/upload/list/...）。
-- ============================================================================

local http = require("suricata.http")

local SUBJECT = {
    client = true, agent = true, beacon = true, panel = true,
    tunnel = true, bot = true, implant = true, listener = true,
}

local ACTION = {
    task = true, command = true, cmd = true, payload = true,
    session = true, job = true, file = true, upload = true,
    download = true, exec = true, shell = true, list = true,
    ls = true, info = true, add = true, del = true, status = true,
    config = true,
}

local function decode(s, rounds)
    for _ = 1, rounds do
        local before = s
        s = s:gsub("%%(%x%x)", function(hex)
            return string.char(tonumber(hex, 16))
        end)
        if s == before then
            break
        end
    end
    return s
end

local function path_of(uri)
    uri = decode(uri, 2):lower()
    local path = uri:match("^[^?]*") or uri
    return path:gsub("//+", "/")
end

local function has_subject(path)
    for segment in path:gmatch("[^/]+") do
        if SUBJECT[segment] then
            return true
        end
    end
    return false
end

local function has_action(path)
    for segment in path:gmatch("[^/]+") do
        if ACTION[segment] then
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

    local candidates = {}
    local raw = tx:request_uri_raw()
    if type(raw) == "string" and #raw > 0 then candidates[#candidates + 1] = raw end
    local normalized = tx:request_uri_normalized()
    if type(normalized) == "string" and #normalized > 0 then candidates[#candidates + 1] = normalized end

    for _, uri in ipairs(candidates) do
        local path = path_of(uri)
        if path:find("/api/", 1, true) and has_subject(path) and has_action(path) then
            return 1
        end
    end
    return 0
end
