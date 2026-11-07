# lua · 规则内嵌 Lua 脚本（Suricata 8.0.8）

这些脚本由 `DNS隧道与带外检测规则.rules` 直接调用，把规则层无法用正则表达的特征收进检测。
Suricata 8.0.8 的规则内嵌脚本只支持 **Lua**，不支持 Python。

## 脚本与规则

| 脚本 | 规则 | hook | 作用 |
|---|---|---|---|
| `dns_tunnel_request.lua` | 9109201；同时作为 9109002/9109003/9109006 的二次过滤 | `dns:request_complete` | 标签熵/字符集/长度/深度、qtype 分级、UUID 校验、punycode/服务标签过滤 |
| `dns_tunnel_response.lua` | 9109202 | `dns:response_complete` | TXT/NULL 载荷内容分类、CNAME target 分析、服务标签过滤 |
| `dns_tunnel_confirm.lua` | 9109203 | `dns:response_complete` | 请求+响应联合确认；只在编码载荷/低 TTL/异常 CNAME 时升级 |
| `dns_compact_labels.lua` | 9109001 | `dns:request_complete` | 只放行连续十六进制单字符流量；过滤层级命名 |
| `dns_oob_request.lua` | 9109004/9109005 | `dns:request_complete` | 拒绝平台根域/短 token；只允许 A/AAAA/TXT/CNAME |
| `dns_txt_burst.lua` | 9109103 | `dns:request_complete` | 跳过邮件认证/服务发现查询与 apex TXT |
| `dns_dot_policy.lua` | 9109101 | `tls` | DoT 853 的 SNI 二次过滤（ALPN 由 `tls.alpn` 负责） |
| `dns_doh_policy.lua` | 9109102 | `http` | DoH 的 method/URI/host 二次过滤 |

## 部署

复制全部脚本到 `default-rule-path`（通常 `/etc/suricata/rules/`），与规则同目录：

```bash
cp lua/*.lua /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml \
          -S /etc/suricata/rules/DNS隧道与带外检测规则.rules -v
```

规则里的 `lua:` 文件名会追加到 `default-rule-path`，所以**不要保留 `lua/` 子目录层级**，除非同步改规则路径。

## 关键约束

- **必须带 buffer**：DNS 请求规则用 `dns.query`，响应规则用 `dns.queries.rrname`，
  TLS 用 `tls.alpn`，HTTP 用 `http.request_header`。只有 hook 没有 buffer 的
  Lua 规则会被 Suricata 当作 straight match，脚本不会执行。
- 沙箱没有 `io/os/package`，脚本不能读 `dns_tunnel_allow.lst`；白名单由规则里的
  `dataset:isnotset,...` 完成，Lua 内只有高频域静态安全网。
- 状态是 per-thread 的；不要用 Lua 全局表做跨包聚合。
- 默认预算：约 50 万条指令 / 500KB 内存；脚本只做小循环。
- `flowbits:set,dns_susp` 由 9109001/2/3/6/9109201 设置，9109203 用
  `flowbits:isset` 做联合确认。上线前需验证 DNS query/response 是否落在同一 flow；
  若不稳定，9109202 仍提供独立的响应侧线索。

## 调优常量

```lua
-- dns_tunnel_request.lua
SCORE_THRESHOLD = 3.5
ENTROPY_HIGH = 3.8
ENTROPY_MID = 3.0
LABEL_LONG = 30
ENCODED_LABEL_MIN = 10
DEPTH_SUSPECT = 5
NAME_LONG = 60
A_ENTROPY_MIN = 3.8
A_LABEL_MIN = 40
A_ENCODED_TOTAL = 40

-- dns_tunnel_response.lua
SCORE_THRESHOLD = 4.0
TXT_SMALL = 100
TXT_LARGE = 512
ENTROPY_QNAME = 3.5
ENTROPY_GUARD = 3.2
LABEL_GUARD = 15
LABEL_SUSPECT = 20
DEPTH_GUARD = 4
PAYLOAD_ENTROPY = 3.8
CNAME_ENTROPY = 3.8
CNAME_LABEL = 30

-- dns_tunnel_confirm.lua
TXT_MIN = 100
PAYLOAD_ENTROPY = 3.8
QNAME_ENTROPY = 3.5
QNAME_LABEL = 20
CNAME_ENTROPY = 3.8
CNAME_LABEL = 30
TTL_LOW = 60
```

## 已验证逻辑（mock 事务，非 Suricata 集成）

| 脚本 | 用例 | 结果 |
|---|---|---|
| request | 32hex A / base32-20 A / UUID 合法 A / 随机 60 字符 | 1 |
| request | UUID 非法 / www / 服务标签 / punycode / 低熵长标签 / CDN | 0 |
| compact | 连续随机十六进制单字符 | 1 |
| compact | `a.b.c.d.e.f.g` / 六个单字符 / 全重复 | 0 |
| oob | `abc123.oast.pro` / `abc123.oast.pro` TXT | 1 |
| oob | `x.oast.pro` / `oast.pro` / MX | 0 |
| txt_burst | `abc.example.com` TXT | 1 |
| txt_burst | `_dmarc...` / apex / `_tcp` | 0 |
| response | 高熵 TXT / NULL / 高熵 CNAME | 1 |
| response | SPF / 域名验证 / 普通 A / DMARC | 0 |
| confirm | 高熵 TXT / 高熵 CNAME | 1 |
| confirm | SPF / 普通 A / 小 TXT | 0 |
| dot | `dns.google` / `dns.quad9.net` / 空 SNI | 1 |
| dot | `www.example.com` | 0 |
| doh | POST `/dns-query` / GET `?dns=` | 1 |
| doh | POST `/api` / GET `/` | 0 |

最终仍需在目标机用 `suricata -T` + 真实/回放流量验证。
