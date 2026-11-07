-- ============================================================================
-- 侦察与攻击工具指纹 · 敏感路径响应体确认
-- 目标: Suricata 8.0.8 / Lua 5.4 沙箱
--
-- 9101108 在 flowbits:isset,recon_sensitive_probe 且响应体非空时调用。
-- 只有出现与请求路径对应的真实泄露标记才返回 1，避免把 SPA 软 404、
-- 登录页、WAF 拦截页当成敏感文件读取成功。
--
-- 本脚本不读取超过 MAX_BODY 字节，也不做跨包聚合。
-- ============================================================================

local http = require("suricata.http")

local MAX_BODY = 8192

local GIT_MARKERS = {
    "[core]",
    "repositoryformatversion",
    "logallrefupdates",
    "[remote",
    "ref: refs/",
    "dirc",
}

local ENV_MARKERS = {
    "db_password",
    "db_name",
    "app_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "secret_key",
    "api_key",
    "jwt_secret",
    "database_url",
    "smtp_password",
    "mysql_root_password",
    "redis_password",
    "mail_password",
    "stripe_secret",
}

local KEY_MARKERS = {
    "begin openssh private key",
    "begin rsa private key",
    "begin ec private key",
    "begin dsa private key",
    "ssh-rsa",
    "ssh-ed25519",
}

local ACTUATOR_MARKERS = {
    "propertysources",
    "systemproperties",
    "spring.datasource",
    '"activeprofiles"',
    "applicationconfig",
    "java profile",
}

local SERVER_STATUS_MARKERS = {
    "apache server status",
    "total accesses",
    "server version",
}

local SERVER_INFO_MARKERS = {
    "apache server information",
}

local API_DOC_MARKERS = {
    '"swagger"',
    '"openapi"',
    '"definitions"',
    '"components"',
    '"paths"',
}

local WP_MARKERS = {
    "db_name",
    "db_password",
    "auth_key",
    "table_prefix",
}

local SQL_MARKERS = {
    "create table",
    "insert into",
    "-- mysql dump",
    "mysql dump",
    "postgresql database dump",
}

local PHPINFO_MARKERS = {
    "php version",
    "phpinfo",
}

local GRAPHQL_MARKERS = {
    "__schema",
    "querytype",
}

local CLOUD_META_MARKERS = {
    "ami-id",
    "instance-id",
    "security-credentials",
    "placement/",
}

local DOCKER_MARKERS = {
    '"auths"',
    "services:",
    "image:",
}

local KUBE_MARKERS = {
    "clusters:",
    "users:",
    "token:",
    "client-certificate-data",
}

local NPM_MARKERS = {
    "_authtoken",
    "registry=",
    "//registry",
}

local APP_MARKERS = {
    "connectionstrings",
    "spring:",
    "datasource:",
    "services:",
    "image:",
}

local ELASTIC_MARKERS = {
    "cluster_name",
    "_cat/indices",
}

local GENERIC_MARKERS = {
    "akia",
    "ghp_",
    "xoxb-",
    "xoxp-",
    "sk_live_",
    "aiza",
    "-----begin",
    "private key",
    "bud1",
}

local function normalize_path(uri)
    uri = uri:lower()
    uri = uri:gsub("^https?://[^/]+", "")
    uri = uri:gsub("\\", "/")
    local path = uri:match("^[^?]*") or ""
    path = path:gsub("//+", "/")
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

local function read_body(tx, max_len)
    local chunks = tx:response_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = max_len - total
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

local function has_any(body, markers)
    for _, marker in ipairs(markers) do
        if body:find(marker, 1, true) then
            return true
        end
    end
    return false
end

local function markers_for_path(path)
    if path:find("^/%.git") then
        return GIT_MARKERS
    end
    if path:find("^/%.env") then
        return ENV_MARKERS
    end
    if path:find("^/%.aws") then
        return ENV_MARKERS
    end
    if path:find("^/%.docker") then
        return DOCKER_MARKERS
    end
    if path:find("^/%.kube") then
        return KUBE_MARKERS
    end
    if path:find("^/%.npmrc") then
        return NPM_MARKERS
    end
    if path:find("^/%.netrc") then
        return GENERIC_MARKERS
    end
    if path:find("^/%.ssh") or path:find("^/id_rsa") or path:find("^/id_dsa") or path:find("^/server%.key") or path:find("^/server%.pem") then
        return KEY_MARKERS
    end
    if path:find("^/actuator") then
        return ACTUATOR_MARKERS
    end
    if path:find("^/server%-status") then
        return SERVER_STATUS_MARKERS
    end
    if path:find("^/server%-info") then
        return SERVER_INFO_MARKERS
    end
    if path:find("^/swagger") or path:find("^/openapi") or path:find("^/v2/api%-docs") or path:find("^/v3/api%-docs") or path:find("^/api%-docs") then
        return API_DOC_MARKERS
    end
    if path:find("^/wp%-config") then
        return WP_MARKERS
    end
    if path:find("^/backup") or path:find("%.sql$") or path:find("^/db%.sql") or path:find("^/dump%.sql") then
        return SQL_MARKERS
    end
    if path:find("^/phpinfo") or path:find("^/info%.php") then
        return PHPINFO_MARKERS
    end
    if path:find("^/graphql") then
        return GRAPHQL_MARKERS
    end
    if path:find("^/latest/meta%-data") or path:find("^/metadata/v1") or path:find("^/computemetadata/v1") then
        return CLOUD_META_MARKERS
    end
    if path:find("^/%.docker") or path:find("^/docker%-compose") or path:find("^/dockerfile") then
        return DOCKER_MARKERS
    end
    if path:find("^/appsettings%.json") or path:find("^/application%.yml") or path:find("^/application%.properties") or path:find("^/bootstrap%.yml") then
        return APP_MARKERS
    end
    if path:find("^/_cat") or path:find("^/_cluster") or path:find("^/_nodes") then
        return ELASTIC_MARKERS
    end
    return GENERIC_MARKERS
end

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil or type(tx) == "string" then
        return 0
    end

    local response_line = tx:response_line()
    if type(response_line) ~= "string" or #response_line == 0 then
        return 0
    end
    local status = response_line:match("^HTTP/%d%.%d%s+(%d%d%d)")
    local code = tonumber(status)
    if code == nil or code < 200 or code >= 300 then
        return 0
    end

    local body = read_body(tx, MAX_BODY)
    if #body == 0 then
        return 0
    end
    body = body:lower()

    local path = get_path(tx)
    if #path == 0 then
        return 0
    end

    if has_any(body, GENERIC_MARKERS) then
        return 1
    end
    if has_any(body, markers_for_path(path)) then
        return 1
    end

    return 0
end
