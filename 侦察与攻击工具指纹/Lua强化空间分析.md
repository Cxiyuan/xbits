# 侦察与攻击工具指纹 · Lua 强化空间分析

## 0. 基线

当前规则（41 条）和 Lua（8 个脚本）已通过 GitHub Actions：

- run `42374685682`（commit `288deac`），26/26 PCAP 用例通过；
- `suricata -T` 加载 Suricata 8.0.8 规则和 Lua 成功；
- 正例覆盖 26 个工具 UA、敏感路径 + 2xx/401/403、响应体确认、
  无 UA 路径高频、403/404 突发、路径编码/点段/反斜杠、包裹 UA、
  外联测绘 UA、异常方法；
- 反例覆盖 `python-httpx`、浏览器、空 UA、无 UA、健康检查、
  SPA 软 404、静态资源 404、正常 PUT。

本文件最初用于分析；P0/P1 已按建议顺序落地并通过 CI，P2（请求体 payload、
JA3/SNI 旁路）仍未实施。

---

## 1. 仍然存在的漏报

### 1.1 随机/自定义 UA 的目录爆破（高优先级）

当前：

- 9101103/9101104 只检测**敏感路径**，且要求 20 次/60 秒；
- 目录爆破经常扫描 `/admin`、`/api/v1/users`、`/word1`、`/word2` 等
  **非敏感路径**；
- 攻击者用 `-H "User-Agent: Mozilla/5.0"` 或 `--random-agent` 后，
  26 条 UA 规则和敏感路径规则都失效。

Lua 可加强：

- 新增响应侧规则：外部客户端在 60 秒内收到 **50 次以上 403/404**；
- 用 Lua `recon_404.lua` 排除静态资源（`.js/.css/.png/.woff/...`）、
  `/.well-known/`、`/favicon.ico`、`/robots.txt`、空路径、根路径；
- 不依赖 UA，能覆盖随机 UA 的 wordlist 扫描；
- tier 定为 `triage`，避免把正常 SPA/API 客户端的 404 直接升级为告警。

误报风险：

- SPA 后端缺少 API、前端资源缺失、爬虫会产生 404 突发；
- 用 `tier triage` + 静态资源排除 + 50/60 阈值控制；
- NAT 后多客户端会合并，需资产维度二次确认。

### 1.2 软 404 / SPA 回退导致“成功访问”误报（高优先级）

当前 9101102：

```text
flowbits:isset,recon_sensitive_probe
http.stat_code; pcre:"/^2[0-9][0-9]$/"
lua:recon_context.lua
```

`recon_context.lua` 在响应侧只重新检查“工具 UA + 敏感 URI”，
**完全不看响应体**。React/Vue/Angular/Next.js 等 SPA 对任意路径返回
`index.html` 和 HTTP 200，于是：

```text
GET /.git/config  ->  200 text/html "Page not found / <div id=app>"
```

会被 9101102 判为 `severity Critical` 的“敏感路径访问成功”，这是当前最明确的
机制误报。反过来，真正返回 `[core]` 的 `.git/config` 与软 404 也无法区分，
导致“成功”语义不可信。

Lua 可加强：

- 读取 `response_header("Content-Type")` 和 `response_body()`；
- 识别 HTML 软 404/登录页/WAF 拦截页：
  - `<!doctype html`、`<html`；
  - `page not found`、`not found`、`404`、`cannot get`；
  - `whitelabel error page`、`access denied`、`request blocked`；
  - `cloudflare`、`mod_security`、`login`、`sign in`；
- 如果命中软 404，`recon_context.lua` 返回 0，9101102 不告警；
- 新增 9101108：**响应体确认泄露内容**，只在出现真实暴露标记时告警，例如：
  - `.git`：`[core]`、`repositoryformatversion`、`[remote`、`ref: refs/`；
  - `.env`：`DB_PASSWORD=`、`APP_KEY=`、`AWS_ACCESS_KEY_ID=`、`JWT_SECRET=`；
  - `.aws/credentials`：`aws_access_key_id`、`aws_secret_access_key`；
  - 私钥：`BEGIN OPENSSH PRIVATE KEY`、`BEGIN RSA PRIVATE KEY`；
  - `/actuator/env`：`propertySources`、`systemProperties`、`spring.datasource`；
  - `/server-status`：`Apache Server Status`、`Total Accesses`；
  - Swagger/OpenAPI：`"swagger"`、`"openapi"`、`"paths"`、`"definitions"`；
  - SQL 备份：`CREATE TABLE`、`-- MySQL dump`、`PostgreSQL database dump`；
  - 云密钥：`AKIA`、`ghp_`、`xoxb-`、`sk_live_`。

Lua 实现要点：

- `response_body()` 返回的是**分块表**，不是字符串；必须 `ipairs` 拼接；
- 限制读取长度（建议 8 KiB），避免大响应触发 Lua 内存/指令预算；
- 先检查暴露标记，再判断软 404，避免真实 `.env` 中含 `LOGIN=` 被误判；
- 响应体为空时不要当成软 404；9101102 可以保留为“200 线索”，
  但 9101108 只在有标记时升级为 Critical。

### 1.3 路径规范化不足（高优先级）

当前 `normalize_uri` 只做：

- 小写；
- 去绝对 URI scheme/host；
- **一次** `%XX` 解码；
- 合并重复 `/`。

绕过/漏报示例：

| 请求 | 当前结果 | 原因 |
|---|---|---|
| `/%252e%2567%2569%2574/config` | 不命中 | 只解码一次，得到 `/%2e%67...` |
| `/.git%5cconfig` | 不命中 | 反斜杠未转 `/` |
| `/foo/../.git/config` | 可能不命中 | 未处理点段 |
| `/.git` | 不命中 | 规则是 `^/%.git/`，要求斜杠 |
| `/actuator` | 不命中 | 规则是 `^/actuator/` |
| `/openapi.yaml` | 不命中 | 只写了 `openapi.json` |
| `/.git/config?x=1` | 命中 | 路径前缀仍匹配 |
| `/%2e%67%69%74/config` | 命中 | 一次解码可处理 |

Lua 可加强：

- 优先读取 `tx:request_uri_normalized()`，失败再回退 `request_uri_raw()`；
- 反斜杠转 `/`；
- 最多解码两次（防止双重编码），并在解码后再次小写；
- 处理 `.`/`..` 点段；
- 保留 query 或单独处理；
- 增加根路径变体：`/.git`、`/.svn`、`/.hg`、`/actuator`、`/openapi.yaml`、
  `/swagger.json`、`/graphiql`、`/jolokia`、`/env`、`/.docker/config.json`、
  `/.kube/config`、`/.npmrc`、`/.netrc`、`/.htpasswd`、`/web.config`、
  `/appsettings.json`、`/application.yml`、`/docker-compose.yml`、`/id_rsa`、
  `/server.key`、`/server.pem`、`/phpinfo.php` 等。

注意：

- 不要把 `/admin`、`/login`、`/api` 直接放进“成功访问”高置信列表；
  它们正常返回 200 登录页/业务页，必须依赖响应体或工具 UA；
- 路径列表目前在两份 Lua 中重复，修改时要同步，否则 9101101/9101103
  会出现不一致。

### 1.4 UA 变体、重复头和空白（中高优先级）

当前 `recon_ua.lua` / `recon_context.lua`：

- 用 `request_header("User-Agent")` 取单个值；
- 工具列表大多是 `^` 开头；
- 没有 trim、没有解析多个 `User-Agent` 头；
- `Nuclei`、`sqlmap` 等被包在 `Mozilla/5.0 (compatible; ...)` 时，
  多数 `^` 模式不命中（Nmap 和 Shodan/Censys/Expanse 已特殊处理）。

Lua 可加强：

- 读取 `request_headers_raw()`，逐行找 `User-Agent:`（大小写不敏感）；
- 去掉首尾空白；
- 对每个 UA 值做小写/边界匹配，支持重复头；
- 对高特异性 token 增加“任意位置 + 词边界”匹配：
  `%f[%w]sqlmap/%f[%W]`、`%f[%w]nuclei%f[%W]`、`%f[%w]wpscan%f[%W]` 等；
- **不要**对 `httpx` 做任意位置匹配，否则 `python-httpx/` 会再次误报；
- 将“攻击工具”和“互联网测绘/通用客户端”分开返回/分规则，
  避免 9101105/9101106 把 Shodan/masscan/zgrab 当成 High 攻击工具。

### 1.5 工具专用请求头（中高优先级）

Acunetix 在部分配置下使用浏览器化 UA，但仍可能发送：

```text
Acunetix-Aspect: ...
Acunetix-Aspect-Password: ...
Acunetix-Product: ...
```

当前 9101007 只看 UA，浏览器化 UA 会漏报。Lua/规则可加强：

- `http.request_header` 缓冲区支持 HTTP/1 **和 HTTP/2**（8.0.8 文档）；
- 用 Lua 遍历 `request_headers()`，大小写不敏感检查
  `acunetix-aspect`、`acunetix-product`；
- 或直接加规则：
  `http.request_header; pcre:"/Acunetix-(?:Aspect|Product)/i";`
- 这是高特异性头，误报低；但仍可被伪造，应作为工具指纹而非攻击成功。

其他工具是否有稳定专用头，需要逐项核实，不能凭猜测写规则。

### 1.6 状态码类别与响应体（中高优先级）

当前只处理：

- 9101102：2xx；
- 9101107：401/403；
- 9101104：2xx/3xx/4xx/5xx。

漏掉：

- **2xx**：201、202、204、206（例如 API 创建、异步任务、部分内容）；
- **3xx**：301/302/307/308（可能跳转到登录/真实资源）；
- **5xx**：500/502/503（扫描触发后端错误，可能是漏洞线索）；
- 响应体中的真实泄露标记；
- `Content-Type`（`text/html` 的 200 与 `text/plain` 的 `.git/config` 意义不同）。

Lua 可加强：

- `response_line()` 解析状态码，按 2xx/3xx/4xx/5xx 分类；
- 2xx + 真实 body 标记 → Critical；
- 2xx + HTML 软 404 → 不告警；
- 3xx 且 Location 指向登录页 → 降级；
- 500 + 工具 UA + 敏感路径 → triage/alert（可能是注入/解析错误）。

### 1.7 请求方法、Host、HTTP 版本（中优先级）

当前规则完全不看：

- `TRACE`、`TRACK`、`PROPFIND`、`MKCOL`、`PUT`、`DELETE`、`OPTIONS`；
- `Host` 是 IP 字面量、`localhost`、空 Host；
- `HTTP/1.0`（部分扫描器/旧工具）；
- 请求行是否绝对 URI。

Lua 可加强（只作为组合信号，不单独告警）：

- `request_line()` 解析 method/version；
- `request_host()` 判断 IP 字面量/空/保留域名；
- 对 `TRACE`/`PROPFIND`/`MKCOL` + 敏感路径，提升到 triage；
- `HTTP/1.0` + 工具 UA + 敏感路径，提升置信度；
- 外部源 + Host 为 IP + 高频 404，作为目录爆破的辅助信号。

误报：

- 正常 WebDAV、API 客户端、健康检查会使用 `OPTIONS`/`PUT`/`DELETE`；
- 必须结合路径、来源、频率、认证状态，不能单靠方法。

### 1.8 HTTP/2 与 HTTPS（能力边界，不是简单 Lua 能补）

已确认：

- Suricata 8.0.8 的 `suricata.http` Lua API 以 **HTTP/1 事务**为主
  （`ALPROTO_HTTP1`）；
- `recon_context.lua` / `recon_path.lua` / 响应体 Lua 对 HTTP/2 事务不自动生效；
- 26 条 `http.user_agent` 规则在 HTTP/2 上是否生效取决于引擎缓冲区，
  当前未做 H2 回归，不能声称已验证；
- 加密 HTTPS 看不到 UA/URI/body；HTTP/3/QUIC 也看不到。

可选的 Lua 旁路：

- `suricata.tls` 读取 SNI/ALPN/证书信息；
- `suricata.ja3` 读取 JA3/JA3S；
- 但 Go/Java/Python 工具与正常客户端 JA3 高度重叠，
  **不能单独作为工具指纹**；只能与连接频率、SNI、端口、资产组合，
  且需要单独场景和独立回归，不能混入当前 HTTP 规则冒充“已覆盖 HTTPS”。

### 1.9 频率与唯一 URI 聚合（Lua 不能安全解决）

当前 `threshold` 只能按规则/来源计数，不能统计“唯一 URI 数”。
Lua 的状态是 **per-thread**，且项目约束明确不做跨包聚合；
`suricata.flowint`/`flowvar` 是 per-flow，无法覆盖大量短连接扫描，
用 Lua 全局表做全量计数会造成内存增长和线程不一致，不能采用。

因此：

- 分布式扫描、NAT 后多客户端、慢速扫描低于阈值的情况，
  规则内无法可靠解决；
- 应交给 SIEM/NDR 的资产维度聚合，或规则层用 `threshold: type both`
  做粗粒度频率；
- 不要用 `detection_filter` 制造告警风暴。

### 1.10 工具 UA 漂移与未知工具（中优先级）

- 工具版本升级会改默认 UA；
- 攻击者可自定义 UA；
- 新工具不在列表中；
- Lua 规范化只能减少变体漏报，不能识别未知工具。

补充手段：

- 路径 + 4xx 突发（1.1）；
- 响应体/状态（1.2/1.6）；
- 专用请求头（1.5）；
- 方法/Host（1.7）；
- 未知工具需要行为模型，不是 UA 列表能解决的。

### 1.11 请求体/查询参数 payload（边界）

sqlmap/commix/XSStrike 等工具有特征 payload：

- `UNION SELECT`、`SLEEP(`、`BENCHMARK(`、`INFORMATION_SCHEMA`；
- `;cat /etc/passwd`、`|whoami`、`$(id)`；
- `<script`、`onerror=`、`${jndi:`；
- `../../etc/passwd`。

Lua 可以读取 `request_body()` / URI query 做匹配，但这些属于**Web 攻击检测**，
不是“侦察工具指纹”；误报也更高。建议放到独立场景（如 Web 攻击/注入），
不要在侦察场景里用宽泛 payload 正则制造误报。

---

## 2. 仍然存在的误报机制

### 2.1 SPA 软 404（最明确）

见 1.2。修复前 9101102 是 `severity Critical`，会把大量 SPA 的 200 HTML
误判为敏感文件成功读取；现在 9101102 降为 High，只有 9101108 响应体确认
才升级为 Critical，软 404 会被 9101102 的 SID 分支抑制。

### 2.2 授权扫描器与健康检查

- Nessus/OpenVAS/Acunetix 可能是企业授权扫描；
- `kube-probe`、ELB/Google 健康检查已由 `recon_path.lua` 排除，
  但只覆盖 13 个 UA 前缀；
- 其他监控（UptimeRobot、Pingdom、StatusCake 已列）之外的客户端仍可能命中；
- Lua 静态列表无法覆盖所有资产/业务，最终需要 `$SCANNER_NET` / suppress。

### 2.3 NAT 与 `by_src`

- `threshold by_src` 在 NAT/代理后会合并多个真实客户端；
- 一个客户端的高频访问可能让整个出口 IP 触发；
- 反向代理/CDN 还会改变方向，使 `$EXTERNAL_NET -> $HOME_NET` 不成立；
- Lua 无法看到真实客户端/资产标签，只能依赖部署和 SIEM 关联。

### 2.4 工具名 token 碰撞

- `Nessus`、`Acunetix`、`Shodan` 等词可能出现在产品名/公司名 UA；
- 当前用锚定/边界降低了概率，但没有绝对零误报；
- 工具专用头（Acunetix-Aspect）比 UA 更稳，但也可伪造。

### 2.5 敏感路径列表过宽/过窄

- 过宽：`/backup`、`/console`、`/graphql`、`/env` 等可能正常返回 200；
  若用 9101102 Critical 会误报；
- 过窄：漏掉 `.git` 根、`/actuator` 根、`/openapi.yaml`、`/.docker/config.json`、
  `/.kube/config`、`/.npmrc`、`/.htpasswd`、`/web.config`、`/application.yml`、
  `/id_rsa`、`/server.key`、云元数据路径等；
- 建议分层：
  - “高价值秘密/配置” → 高置信；
  - “管理面/API 文档” → 只做 triage/404 突发，不因 200 登录页升级 Critical。

### 2.6 响应体关键词误报

如果只搜 `password`、`secret`、`token`，登录页/正常页面会大量命中。
必须：

- 按路径选择 marker；
- 先识别 HTML 软 404/登录页；
- 只对高特异性 marker（`[core]`、`repositoryformatversion`、`AKIA`、
  `BEGIN OPENSSH PRIVATE KEY`、`propertySources` 等）升级；
- 限制 body 读取长度。

---

## 3. Lua 强化优先级矩阵

| 优先级 | 能力 | Lua/规则手段 | 主要收益 | 主要风险 |
|---|---|---|---|---|
| P0 | 软 404/响应体确认 | `recon_body.lua` + 9101108；`recon_context.lua` 响应侧 | 消除 SPA 200 误报；真实泄露升级 Critical | body API 可用性、误判登录页 |
| P0 | 403/404 突发 | `recon_404.lua` + 9101109 | 捕获随机 UA 的目录爆破 | SPA/API 404 突发误报 |
| P0 | 路径规范化 | 双解码、反斜杠、点段、`request_uri_normalized` | 修复编码/路径绕过漏报 | 过度归一化导致误匹配 |
| P0 | Acunetix 专用头 | `http.request_header` + Lua/规则 9101110 | 浏览器化 UA 仍可识别 | 头可伪造 |
| P1 | UA 多值/空白/token | `request_headers_raw()` 解析；保留 `httpx` 排除 | 减少包裹/重复 UA 漏报 | 静态 token 碰撞 |
| P1 | 状态码类别/响应头 | `response_line`/`response_header` | 覆盖 201/204/3xx/5xx | 3xx/5xx 语义复杂 |
| P1 | 方法/Host/HTTP 版本 | `request_line()`/`request_host()` | 增加未知工具行为信号 | WebDAV/API 正常流量 |
| P1 | 扩展秘密路径 | 两份 Lua 同步列表 | 提高敏感路径覆盖 | 列表维护、误报 |
| P2 | Query/body payload | `request_body()`/URI query | 捕获改 UA 的注入工具 | 属于 Web 攻击场景，误报高 |
| P2 | JA3/SNI | `suricata.ja3`/`suricata.tls` | 对 HTTPS 做旁路线索 | 工具/正常客户端重叠，不能单独用 |
| 不可行 | 跨流唯一 URI 聚合 | 不能用 Lua 全局表/flowint 可靠实现 | — | per-thread/内存/一致性 |

---

## 4. 具体 Lua 设计草案

### 4.1 响应体读取（有限长度）

```lua
local MAX_BODY = 8192

local function read_body(tx)
    local chunks = tx:response_body()
    if type(chunks) ~= "table" then
        return ""
    end
    local out, total = {}, 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) == "string" then
            local remain = MAX_BODY - total
            if remain <= 0 then break end
            if #chunk > remain then
                chunk = chunk:sub(1, remain)
            end
            out[#out + 1] = chunk
            total = total + #chunk
        end
    end
    return table.concat(out)
end
```

注意：

- `response_body()` 无 body 时返回 `nil, err`，不能直接 `#body`；
- 分块表可能很大，必须限制总量；
- 不要用 Lua 全局缓存 body/URI。

### 4.2 软 404 判定

伪代码：

```text
body = lower(read_body(tx))
ct = lower(response_header("Content-Type") or "")

if body == "" then return false end
if has_exposure_marker(body) then return false end

if ct contains "text/html" or body starts with "<!doctype" or "<html" then
    if body contains "not found" / "404" / "whitelabel error page" /
       "access denied" / "request blocked" / "login" / "sign in" then
        return true
    end
end

if ct contains "application/json" and body contains "\"error\"" and
   (body contains "not found" or "404" or "unauthorized" or "forbidden") then
    return true
end

return false
```

原则：**先看真实泄露 marker，再看软 404**；否则 `.env` 中的 `LOGIN=` 可能被当成登录页。

### 4.3 4xx 突发（无 UA 依赖）

```text
if request_uri is empty or path is "/" -> 0
if path starts with "/.well-known/" -> 0
if path in {"/favicon.ico", "/robots.txt", "/sitemap.xml", ...} -> 0
if extension in {js,css,map,png,jpg,jpeg,gif,svg,ico,webp,avif,
                 woff,woff2,ttf,eot,otf,mp4,webm,pdf} -> 0
return 1
```

规则侧：

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (
    flow:established,to_client;
    http.stat_code; pcre:"/^(?:403|404)$/";
    lua:recon_404.lua;
    threshold: type both, track by_dst, count 50, seconds 60;
    ... tier triage ...)
```

### 4.4 Acunetix 专用头

规则可以直接使用 `http.request_header`（支持 HTTP/1 和 HTTP/2）：

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (
    flow:to_server,established;
    http.request_header;
    pcre:"/Acunetix-(?:Aspect|Product)/i";
    threshold: type limit, track by_src, count 1, seconds 60;
    ... tool acunetix ...)
```

若要避免头值中出现字符串，Lua 可遍历 `request_headers()`，
只匹配头名：

```text
for name, value in pairs(tx:request_headers()) do
    n = name:lower()
    if n == "acunetix-aspect" or n == "acunetix-product" then
        return 1
    end
end
```

### 4.5 路径规范化

```text
uri = tx:request_uri_normalized()  -- 优先
if not uri then uri = tx:request_uri_raw() end
uri = uri:lower()
uri = uri:gsub("^https?://[^/]+", "")
uri = uri:gsub("\\", "/")
-- 最多解码两次
for _ = 1, 2 do
    local before = uri
    uri = uri:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    if uri == before then break end
end
uri = uri:lower()
-- 合并斜杠、处理 . / ..
```

### 4.6 已落地 SID

| SID | 内容 | tier |
|---|---|---|
| 9101108 | 敏感路径响应体确认泄露（`.git/.env/私钥/actuator/备份/云密钥`） | alert |
| 9101109 | 外部源 403/404 高频突发（目录/路径爆破） | triage |
| 9101110 | Acunetix Aspect/Product 专用请求头 | alert |
| 9101111 | 内网外联使用测绘/资产扫描 UA | telemetry |
| 9101112 | 包裹/多值 UA 的已知工具补充规则 | triage |
| 9101113 | 异常 HTTP 方法/Host 组合 | triage |

---

## 5. 不应该用 Lua 做的事

- 不用 Lua 全局表做跨包/跨流计数：脚本状态是 per-thread，
  与流分发不一致，内存不可控；
- 不用 `flowint`/`flowvar` 冒充全局唯一 URI 统计：它们是 per-flow；
- 不读取无上限的 `request_body()`/`response_body()`；
- 不把 `/admin`、`/login` 等 200 登录页直接升级为“敏感文件读取成功”；
- 不用 `password`、`secret` 等宽泛词单独判断泄露；
- 不把 JA3/SNI 当成 HTTP 工具指纹的替代品；
- 不声称“零误报”或“已覆盖 HTTPS”。

---

## 6. 已落地的验证用例

P0/P1 已按建议顺序实现，新增验证用例均已进入 CI：

| PCAP | 期望 |
|---|---|
| `recon_body_confirmed` | sqlmap + `/.git/config` + 200 + `[core]` → 9101004/9101101/9101102/9101108 |
| `recon_soft404_negative` | sqlmap + `/.git/config` + 200 + HTML “Page not found” → 9101101，**不命中** 9101102/9101108 |
| `recon_404_burst` | 浏览器 UA + 60 个随机路径 404 → 9101109 |
| `recon_404_static_negative` | 60 个 `.png` 404 → 不命中 9101109 |
| `recon_acunetix_header` | 浏览器 UA + `Acunetix-Aspect` → 9101110，不命中 9101007 |
| `recon_path_double_encoded` | 25 次 `/%252e%2567%2569%2574/config` → 9101103/9101104 |
| `recon_path_dot_segment` | `/foo/%2e%2e/.git/config` → 9101103/9101104 |
| `recon_path_backslash` | `/.git%5cconfig` → 9101103/9101104 |
| `recon_wrapped_ua` | `Mozilla/5.0 (compatible; sqlmap/1.8.8)` → 9101112 |
| `recon_outbound_scanner_ua` | 内网 → 外部 Shodan UA → 9101111 |
| `recon_method_trace` | 外部 TRACE → 9101113 |
| `recon_method_put_benign_negative` | 正常 PUT `/api` → 不命中 9101113 |

所有用例均同时有正例/反例；CI 精确断言 `signature_id`。

---

## 7. 结论

当前规则已经解决了“UA 子串过宽、方向混乱、detection_filter 告警风暴、
无效 Wappalyzer、无路径/响应关联”等基础问题。剩余最值得用 Lua 补的，
按收益排序是：

1. **响应体软 404/真实泄露确认**（消除当前最明确的 Critical 误报）；
2. **403/404 突发**（补随机 UA 的目录爆破漏报）；
3. **路径规范化 + 秘密路径扩展**（补编码/根路径绕过）；
4. **Acunetix 专用请求头**（补浏览器化 UA 漏报）；
5. **UA 多值/空白/token 与状态码/方法/Host 组合**（中优先级）。

HTTPS、HTTP/2、HTTP/3、分布式/NAT 聚合、授权扫描器上下文不是单靠
规则内 Lua 能可靠解决的，必须明确为能力边界，交给解密、代理日志、
资产标签或 SIEM/NDR 聚合。
