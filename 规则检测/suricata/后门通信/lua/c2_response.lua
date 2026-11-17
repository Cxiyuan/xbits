-- ============================================================================
-- 命令与控制信标 · 响应侧任务/载荷确认
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 仅在请求侧已命中 C2 信标/面板（flowbits）后调用。
-- 要求响应体同时出现任务/命令/载荷/会话语义，而不是单独一个单词。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local COMMAND_MARKERS = {
    '"task"', '"payload"', '"command"', '"cmd"', '"job"',
    '"exec"', '"beacon"', '"session"', '"download"', '"upload"',
    '"sleep"', '"jitter"',
}

local function read_body(tx)
    local chunks = tx:response_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = MAX_BODY - total
            if remain <= 0 then
                break
            end
            if #chunk > remain then
                chunk = chunk:sub(1, remain)
            end
            out[#out + 1] = chunk
            total = total + #chunk
        end
    end
    return table.concat(out)
end

local function count_markers(body)
    local count = 0
    for _, marker in ipairs(COMMAND_MARKERS) do
        if body:find(marker, 1, true) then
            count = count + 1
        end
    end
    return count
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local body = read_body(tx):lower()
    if #body == 0 then
        return 0
    end

    -- 至少两个 C2 语义标记，避免正常 JSON 的单字段误报。
    if count_markers(body) >= 2 then
        return 1
    end
    return 0
end
