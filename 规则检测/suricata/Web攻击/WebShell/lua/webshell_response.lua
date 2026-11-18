-- ============================================================================
-- 后门通信 · WebShell 响应确认
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 仅在请求侧已命中 WebShell 文件名/命令参数（flowbits）后调用。
-- 检查命令输出、文件管理页面、脚本错误回显，避免仅凭 200 响应确认。
-- ============================================================================

local http = require("suricata.http")
local MAX_BODY = 16384

local MARKERS = {
    -- Unix/Windows command output
    "uid=", "gid=", "root:x:0:0", "www-data",
    "microsoft windows", "volume serial number", "directory of",
    "drwx", "-rw-r--r--",
    -- File manager
    "index of /", "file manager", "chmod", "symlink",
    -- Script/runtime errors
    "eval()'d code", "fatal error", "java.lang.runtime",
    "processbuilder", "warning: shell_exec",
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

    for _, marker in ipairs(MARKERS) do
        if body:find(marker, 1, true) then
            return 1
        end
    end
    return 0
end
