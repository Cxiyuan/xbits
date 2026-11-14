# 侦察与攻击工具指纹（Suricata 8.0.8）

本场景检测 HTTP 侦察/扫描工具指纹、敏感路径探测、脚本化客户端高频访问，
以及内网外联/内网横向使用攻击工具的情况。

- 规则：`侦察与攻击工具指纹规则.rules`
- Lua：`lua/recon_ua.lua`、`lua/recon_context.lua`、`lua/recon_path.lua`、
  `lua/recon_body.lua`、`lua/recon_404.lua`、`lua/recon_scanner_ua.lua`、
  `lua/recon_wrapped_ua.lua`、`lua/recon_method.lua`
- 缺陷分析：`误报分析与规则缺陷.md`
- Lua 强化空间：`Lua强化空间分析.md`
- 测试：`../../测试用例/generate_recon_pcaps.py`、`../../测试用例/recon_cases.json`

## 1. 检测分层

| tier | 含义 | 典型规则 |
|---|---|---|
| `tier alert` | 已知工具精确 UA；工具+敏感路径+响应体确认 | 9101001-9101023、9101101/9101102/9101105/9101107/9101108/9101110 |
| `tier triage` | 需要资产/授权上下文确认 | 9101103/9101104/9101106/9101109/9101112/9101113 |
| `tier telemetry` | 互联网测绘、通用脚本客户端、banner 扫描 | 9101011/9101014/9101024-9101029/9101111 |

告警消费建议：

- `tier alert` 进告警队列；
- `tier triage` 进调查队列，先确认是否授权扫描/资产归属；
- `tier telemetry` 只做统计和线索，不直接派单。

## 2. 方向约定

```text
$EXTERNAL_NET -> $HOME_NET   外部对内部服务侦察
$HOME_NET     -> $EXTERNAL_NET 内部服务响应
$CLIENT_NET   -> $EXTERNAL_NET 内网主机外联/外发扫描
$HOME_NET     -> $HOME_NET     内网横向
```

上线前必须在 `suricata.yaml` 的 `vars.address-groups` 中显式定义：

```yaml
HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
EXTERNAL_NET: "!$HOME_NET"
CLIENT_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
```

如果 `EXTERNAL_NET` 未定义或为空，所有入站规则都不会命中。

## 3. 关键规则说明

### 3.1 精确 UA 指纹

每条工具规则同时使用 `content`（MPM 快筛）和 `pcre`（边界校验）：

- `httpx`：`^httpx(?:\/|$)`，排除 `python-httpx/`；
- `Nuclei`：`^Nuclei(?:\b|[\/ -])`，排除任意包含子串；
- `Nmap NSE`：允许 `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` 包裹；
- `Shodan/CensysInspect/Expanse`：允许 `compatible; ...` 包裹。

### 3.2 敏感路径 + 响应确认

`recon_context.lua` 检查：

- 攻击工具 UA（精确边界）；
- URI 小写、百分号解码、去绝对 URI 前缀、合并重复斜杠；
- 敏感路径：`/.git/`、`/.env`、`/.aws/credentials`、`/wp-config.php`、
  `/actuator/`、`/server-status`、`/swagger-ui`、`/manager/html`、
  `/vendor/phpunit`、`/solr/admin`、`/jenkins/script` 等。

响应侧用 `flowbits`、`http.stat_code` 和响应体确认：

- 9101102：HTTP 2xx；`recon_context.lua` 读取响应体，识别 SPA/登录页/WAF 页
  造成的软 404 后返回 0，避免把 200 HTML 当成敏感文件读取成功；
- 9101107：HTTP 401/403，`tier alert`；不做 body 抑制，因为登录页/拒绝页
  仍然是“被保护但被探测”的有效线索；
- 9101108：在 `flowbits:isset,recon_sensitive_probe` 且响应体非空时，
  由 `recon_body.lua` 检查真实泄露标记（`[core]`、`DB_PASSWORD=`、
  `AKIA`、`BEGIN OPENSSH PRIVATE KEY`、`propertySources` 等），
  只有真实命中才升级为 Critical；
- 9101104：外部源敏感路径探测收到 2xx/3xx/4xx/5xx，且达到 20 次/60 秒，
  `tier triage`。

### 3.3 不依赖 UA 的路径规则

9101103/9101104 使用 `recon_path.lua`，只看 URI + 频率，不要求 UA。
用于捕获随机 UA、缺失 UA 的扫描器；请求与响应两侧都用
`threshold: type both, count 20, seconds 60` 控制，不做跨包聚合。

9101109 使用 `recon_404.lua`，在响应侧统计 403/404 突发：
排除根路径、`/.well-known/`、favicon/robots/sitemap 和静态资源扩展名，
50 次/60 秒触发；用于覆盖随机 UA 对非敏感路径的目录爆破。

### 3.4 路径规范化与工具专用头

`recon_context.lua` 和 `recon_path.lua` 现在会：

- 优先 `request_uri_normalized()`，失败回退 `request_uri_raw()`；
- 反斜杠转 `/`；
- 最多解码两次，覆盖 `%252e` 双重编码；
- 处理 `.`/`..` 点段；
- 覆盖 `/.git`、`/actuator`、`/openapi.yaml`、`/.docker/config.json`、
  `/.kube/config`、`/.npmrc`、`/.htpasswd`、`/web.config`、`/application.yml`、
  `/id_rsa`、`/server.key`、云元数据路径等。

9101110 使用 `http.request_header` 检测 Acunetix 的
`Acunetix-Aspect`/`Acunetix-Product` 请求头；该缓冲区支持 HTTP/1 和 HTTP/2，
可覆盖浏览器化 UA 的 Acunetix 扫描。

### 3.5 UA 变体与方向

- `recon_ua.lua` 解析所有 `User-Agent` 头，支持重复头、首尾空白和
  `Mozilla/5.0 (compatible; ...)` 包裹；`httpx` 仍只允许开头匹配。
- `recon_scanner_ua.lua` 单独识别 Shodan/Censys/Expanse/masscan/zgrab/l9explore，
  由 9101111 以 telemetry 处理，避免升级为 High 攻击工具。
- `recon_wrapped_ua.lua` 只对“工具 token 不在 UA 开头”的包裹变体做 triage，
  开头匹配仍由对应工具 SID 负责。
- 9101113 使用 `recon_method.lua` 对 TRACE/TRACK/PROPFIND/MKCOL，
  以及带 IP/localhost/敏感路径的 PUT/DELETE 做 triage；不单独靠方法告警。

### 3.6 限频语义

- 工具指纹：`threshold: type limit, track by_src, count 1, seconds 60`（每源每工具每分钟一条）；
- 响应侧确认：`track by_dst`（响应包源是本地服务器，目的才是外部客户端）；
- 互联网测绘：`type limit, count 1, seconds 300`；
- 高频脚本客户端/路径探测：`type both, count 50/60、20/60 或 60/60`（达到阈值后每周期最多一条）。

不使用 `detection_filter`；Suricata 8.0.8 中 `threshold` 未被弃用。

## 4. 授权扫描器与白名单

不要把整个云厂商或公共后缀写进白名单。推荐：

1. 定义 `SCANNER_NET`（授权漏扫源地址段）；
2. 在 `threshold.config` 中按 `sid` + `src` 抑制；
3. 或在上层 SIEM 按 `tier` + 资产标签抑制。

示例（仅示意，需替换为真实授权网段）：

```text
suppress gen_id 1, sig_id 9101015, track by_src, ip 10.10.20.0/24
suppress gen_id 1, sig_id 9101016, track by_src, ip 10.10.20.0/24
```

Lua 已排除常见健康检查 UA：`kube-probe`、`ELB-HealthChecker`、`GoogleHC`、
`Amazon-Route53-Health-Check-Service`、`Datadog/Synthetics`、`NewRelicPinger`、
`Prometheus`、`Zabbix`、`Nagios`、`check_http`、`UptimeRobot`、`Pingdom`、
`StatusCake`。

## 5. 能力边界

1. **HTTPS**：未解密 TLS 时看不到 UA；本规则集只覆盖明文 HTTP。
2. **UA 伪造**：改 UA 即绕过精确工具规则；由 9101103/9101104 的路径+频率兜底。
3. **HTTP/2/HTTP/3**：Suricata 8.0.8 的 `suricata.http` Lua API 以 HTTP/1 事务为主
   （`ALPROTO_HTTP1`）；Lua 规则不自动覆盖 HTTP/2 事务。HTTP/3/QUIC 加密流量
   `alert http` 也不解析。
4. **NAT/代理**：`by_src` 限频会把 NAT 后客户端合并，需结合资产维度。
5. **零误报**：不承诺；只在给定回归集上验证已知正反例。

## 6. 验证

```bash
python3 -m pip install scapy==2.6.1
python3 测试用例/generate_recon_pcaps.py --out 测试用例/recon_pcap
suricata -T -c 测试用例/suricata-recon-ci.yaml
for pcap in 测试用例/recon_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c 测试用例/suricata-recon-ci.yaml -r "$pcap" -l "测试用例/out/suricata/$name" -k none
done
python3 测试用例/assert_suricata.py --eve-root 测试用例/out/suricata --cases 测试用例/recon_cases.json
```

最终验证只认 `.github/workflows/suricata-recon-tools.yml` 的 GitHub Actions 结果。
当前已验证：commit `c6a4411`，run 42375447812，29/29 用例通过：
<https://github.com/Cxiyuan/xbits/actions/runs/42375447812>。

## 7. Zeek 关联分析

- 脚本：`zeek/recon_score.zeek`；
- 按源统计 HTTP 唯一 URI/404/403 比例，生成扫描会话 notice；
- 输出 `recon_correlation.log`，含 `community_id` 与 `related_sids`；
- 与 Suricata EVE 的 `community_id` 关联；
- CI：recon workflow 内运行 Zeek 9.0.1 + community-id 断言。
