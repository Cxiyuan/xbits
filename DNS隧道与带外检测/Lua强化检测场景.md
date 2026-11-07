# Lua 强化检测场景

> 范围：只讨论**规则内 Lua**（`lua:` 关键字）能做的强化。
> 不涉及规则外日志分析、独立脚本或离线工具。
> 目标：在不增加规则数量的前提下，用单事务上下文降低误报、补足纯正则看不到的特征。
>
> **状态：本文所有可由 Lua 在规则内落地的场景已实现**，对应脚本与规则见下表“实现”列。
> 仍需 `suricata -T` 与真实/回放流量验证。

---

## 一、优先场景总表

| 优先级 | 场景 | Lua 强化点 | 实现 |
|---|---|---|---|
| P0 | 合法大 TXT 响应 | 载荷字符集/熵/已知前缀分类，人类可读文本不计入 | `dns_tunnel_response.lua` → 9109202/9109203 |
| P0 | 32hex/UUID 的 A/AAAA 合法查询 | qtype 分级 + 熵/长度 + 响应确认 + 静态白名单 | `dns_tunnel_request.lua` → 9109002/3/6/9109201 |
| P0 | TXT 突发中的邮件认证查询 | 任意 `_` 服务标签、apex TXT 跳过 | `dns_txt_burst.lua` → 9109103 |
| P0 | 高熵长标签的合法 SaaS/AV/EDR | 编码字符集占比 + 熵，`xn--`/高连字符跳过 | `dns_tunnel_request.lua` → 9109006/9109201 |
| P1 | DGA 被误判为隧道 | 请求 `flowbits:dns_susp`，响应编码载荷/CNAME 才升级 | `dns_tunnel_confirm.lua` → 9109203 |
| P1 | OOB 平台根域/爬虫/MX | 子域 + 随机 token + A/AAAA/TXT/CNAME | `dns_oob_request.lua` → 9109004/5 |
| P1 | DoT 853 非 DoT/批准解析器 | `tls.alpn:"dot"` + Lua SNI 校验 | `dns_dot_policy.lua` → 9109101 |
| P1 | DoH 内容类型误报 | HTTP method/URI/host 组合校验 | `dns_doh_policy.lua` → 9109102 |
| P2 | CNAME 隧道漏检 | CNAME target 熵/长度分析 | `dns_tunnel_response.lua` / `dns_tunnel_confirm.lua` |
| P2 | IDN/punycode 长标签 | `xn--`/高连字符跳过 | 请求/响应/确认脚本 |
| P2 | 任意位置的服务标签 | 任意 label 以 `_` 开头跳过 | 全部 DNS Lua 脚本 |
| P2 | 自定义反向区 | 单字符标签要求连续十六进制流 + 熵 | `dns_compact_labels.lua` → 9109001 |

---

## 二、P0：合法大 TXT 响应

**问题**：9109202 目前按 TXT/NULL 字节量 + qname 结构评分。合法的 SPF、DKIM、域名验证、SaaS 配置也可能是大 TXT，尤其 qname 带随机子域时会误报。

**Lua 强化**：分析 `tx:answers()[i]["addr"]` 的**内容形态**，而不是只看长度。

```lua
local function payload_is_human_readable(payload)
    local lower = payload:lower()
    local known = {
        "v=spf1", "v=dkim1", "v=dmarc1", "google-site-verification",
        "ms=", "facebook-domain-verification", "atlassian-domain-verification",
        "apple-domain-verification", "docusign=", "zoom-verification=",
        "adobe-idp-site-verification", "have-a-nice-day",
    }
    for _, prefix in ipairs(known) do
        if lower:find(prefix, 1, true) then
            return true
        end
    end
    -- 人类可读文本通常有空格/换行/「=」；隧道载荷几乎只有编码字符
    local textual = 0
    for i = 1, #payload do
        local c = payload:sub(i, i)
        if c == " " or c == "\n" or c == "\t" or c == "=" or c == ";" then
            textual = textual + 1
        end
    end
    return textual / math.max(#payload, 1) > 0.02
end
```

评分时：

- 命中已知前缀或人类可读 → 不因 TXT 大而告警；
- 要求 `base64/hex 字符集占比 >= 0.85` 且熵 >= 3.8 才给高置信；
- 仍然保留“小载荷 + 低 TTL + 高熵 qname”的线索级评分。

**注意**：加密/压缩载荷仍是高熵，Lua 无法区分“加密外泄”和“合法高熵配置”；这类保留 `tier triage`。

---

## 三、P0：32hex/UUID 的 A/AAAA 合法查询

**问题**：9109002/9109003 对 A/AAAA 也生效，CDN、埋点、MDM、IoT 的哈希/GUID 子域大量误报；dataset 只能覆盖已知长尾。

**Lua 强化**：

1. **qtype 分级**：
   - TXT/NULL/CNAME：保持当前阈值；
   - A/AAAA：要求更强证据（例如 `max_ent >= 4.0` 且存在第二个编码标签，或响应侧确认）。
2. **UUID 版本/变体校验**（减少非 UUID 的连字符 token 误报）：

   ```lua
   local hex = name:gsub("-", "")
   local version = tonumber(hex:sub(13, 13), 16)
   local variant = tonumber(hex:sub(17, 17), 16)
   if not (version and version >= 1 and version <= 5) then return 0 end
   if not (variant and (variant == 8 or variant == 9 or variant == 10 or variant == 11)) then
       return 0
   end
   ```

3. **响应侧确认**：请求规则 `noalert; flowbits:set,dns_high_entropy;`，响应规则用
   `flowbits:isset,dns_high_entropy; lua:dns_tunnel_response.lua;` 只在响应出现
   TXT/NULL 大载荷、低 TTL、NOERROR 时才告警；A/AAAA + 正常 TTL 走低置信线索。

**取舍**：会延迟到响应才告警；单向 DNS/被阻断响应会漏，需要保留一条低置信请求侧线索规则。

---

## 四、P0：TXT 突发中的邮件认证查询

**问题**：9109103 的 `detection_filter` 会把邮件服务器的 `_dmarc`/`_domainkey`/`_spf` 查询算进频次。

**Lua 强化**：在 9109103 增加一个轻量 Lua 过滤：

```lua
local function is_service_name(name)
    for label in name:gmatch("[^.]+") do
        if label:sub(1, 1) == "_" then
            return true
        end
    end
    return name:find("_domainkey", 1, true) ~= nil
        or name:find("_dmarc", 1, true) ~= nil
        or name:find("_acme-challenge", 1, true) ~= nil
        or name:find("_spf", 1, true) ~= nil
        or name:find("_mta-sts", 1, true) ~= nil
end
```

任一路径命中即 `return 0`。这样邮件认证查询不会触发 TXT 突发线索。

---

## 五、P0：高熵长标签的合法 SaaS/AV/EDR

**问题**：9109006/9109201 对长标签只看长度/熵，AV/EDR 的 URL 信誉查询、IDN、长 token 会误报。

**Lua 强化**：

- 跳过 `xn--` 开头的 punycode 标签；
- 跳过连字符占比 > 25% 的标签（IDN/URL 编码常见）；
- 要求编码字符集占比 >= 0.85 且熵 >= 3.8，而不是“长度 >= 60”单独成立；
- 使用静态 AV/EDR/CDN 后缀表（脚本内已有）做安全网；
- 响应侧看到 TXT/NULL 大载荷才升级，A/AAAA 只做线索。

```lua
if left:sub(1, 4) == "xn--" then return 0 end
local hyphens = select(2, left:gsub("-", ""))
if #left > 0 and hyphens / #left > 0.25 then return 0 end
```

---

## 六、P1：DGA 被误判为隧道

**问题**：32hex A 查询既可能是 DGA，也可能是隧道；当前规则会把 DGA 报成隧道，污染告警可信度。

**Lua + flowbits 强化**：

1. 请求规则命中高熵 qname 时 `noalert; flowbits:set,dns_high_entropy;`（只打标，不告警）。
2. 响应规则检查 `flowbits:isset,dns_high_entropy`，Lua 再要求：
   - qtype TXT/NULL/CNAME，或
   - 响应 TXT/NULL 载荷 >= 100 字节，或
   - TTL <= 60 且 answer 数 <= 3。
3. 若响应是 A/AAAA、正常 TTL、无载荷 → 不升级为隧道事件；可另设低置信 DGA 线索。

> 需要验证 DNS over UDP 的 query/response 是否落在同一 flow（通常同一 flow）；若不稳定，改用 `xbits` 按客户端 IP 关联。

---

## 七、P1：OOB 平台根域/爬虫/MX 查询

**问题**：9109004/9109005 对平台根域、MX/NS 查询、搜索引擎爬虫也会告警。

**Lua 强化**：

- 要求 qname 是平台域的**子域**（至少一个 label 在平台名之前）；
- 要求 qtype 属于 A/AAAA/TXT/CNAME，排除 MX/NS/SOA/PTR；
- 要求子域 token 长度 >= 6 或熵 >= 2.5（区分“真实交互”与“泛查询”）。

```lua
-- name 已小写，platform 例如 "oast.pro"
local prefix = name:sub(1, #name - #platform - 1)
if prefix == "" or #prefix < 6 then return 0 end
```

**不能解决**：授权红队/扫描器、邮件沙箱引爆 canarytokens——这些要看来源角色，需要规则变量/抑制，不是 Lua 能判断的。

---

## 八、P1：DoT / DoH

**DoT 853**：

- 规则加 `tls.alpn; content:"dot";` 作为高置信条件；
- Lua 用 `require("suricata.tls")`、`tls.get_tx():get_client_sni()` 检查 SNI 是否为已知/批准解析器；
- 非 `dot` ALPN 且 SNI 不匹配 → 降为 telemetry。

**DoH**：

- Lua 用 `require("suricata.http")`：
  - `request_line()` 必须是 POST/GET；
  - `request_uri_raw()` 包含 `/dns-query` 或 `?dns=`；
  - `request_host()` 不在批准列表；
  - 再叠加现有 `application/dns-message` 头匹配。

这样可排除“普通应用恰好使用该 Content-Type”的误报。

---

## 九、P2：CNAME 隧道漏检

**问题**：9109202 只统计 TXT/NULL；CNAME 隧道把数据放在 target 名称里，当前漏检。

**Lua 强化**：遍历 `answers()`，对 `type == "CNAME"` 的 `addr` 做同样的熵/长度/字符集评分；要求 target 的最左标签高熵或总长度异常才命中，避免正常 CNAME 误报。

---

## 十、P2：服务标签/IDN/自定义反向区

- **任意位置的服务标签**：`foo._tcp.example.com`、`_ldap._tcp...`；Lua 遍历所有 label，任意 `_` 开头即跳过。
- **IDN/punycode**：`xn--` 长标签跳过（或单列规则），避免 9109006 误报。
- **自定义反向区**：9109001 要求单字符标签是连续十六进制流且熵足够，减少 `a.b.c.d.e.f.corp` 这类层级命名误报。

---

## 十一、Lua 不能解决的误报（需要规则变量/抑制）

| 场景 | 原因 | 正确手段 |
|---|---|---|
| 授权红队/漏洞扫描器使用 OOB | 无法从单事务判断“授权” | 源地址组 + 时间窗抑制 |
| 邮件安全沙箱引爆 canarytokens | 源是安全设备，不是受害者 | 按源抑制/资产角色 |
| NAT/代理后的高频长域名 | 需要跨客户端聚合 | 规则层不解决；`by_src` 无意义 |
| 慢速/低频隧道 | 需要 30 分钟/24 小时窗口 | 规则层不解决 |
| 资产/进程/用户上下文 | 规则层没有这些字段 | EDR/CMDB |
| 加密 DoH/DoT 内容 | 不可见 | 代理/TLS/端点遥测 |
| 读取白名单文件 | Lua 沙箱无 io | 规则内 `dataset` |

---

## 十二、落地状态

以上场景已全部落地到 `lua/` 与规则文件：

- 请求侧：`dns_tunnel_request.lua`、`dns_compact_labels.lua`、`dns_oob_request.lua`、`dns_txt_burst.lua`
- 响应侧：`dns_tunnel_response.lua`、`dns_tunnel_confirm.lua`
- 带外协议：`dns_dot_policy.lua`、`dns_doh_policy.lua`
- 规则：9109001–9109006 增加 Lua 二次过滤；9109101/2/3 增加 Lua；9109201/2/3 为 Lua 主/确认规则

上线前仍需 `suricata -T` 与真实/回放流量验证；阈值按影子期数据校准。

> 每一项都应在影子期回算误报与召回，再决定是否启用；Lua 只能降低“单事务可解释”的误报，不能消除来源角色/聚合类误报。
