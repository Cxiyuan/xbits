# 侦察与攻击工具指纹（Suricata 8.0.8）

本场景检测 HTTP 侦察/扫描工具指纹、敏感路径探测、脚本化客户端高频访问，
以及内网外联/内网横向使用攻击工具的情况。

- 规则：`侦察与攻击工具指纹规则.rules`
- Lua：`lua/recon_ua.lua`、`lua/recon_context.lua`、`lua/recon_path.lua`
- 缺陷分析：`误报分析与规则缺陷.md`
- 测试：`../test/generate_recon_pcaps.py`、`../test/recon_cases.json`

## 1. 检测分层

| tier | 含义 | 典型规则 |
|---|---|---|
| `tier alert` | 已知工具精确 UA；工具+敏感路径+响应确认 | 9101001-9101023、9101101/9101102/9101105/9101107 |
| `tier triage` | 需要资产/授权上下文确认 | 9101103/9101104/9101106 |
| `tier telemetry` | 互联网测绘、通用脚本客户端、banner 扫描 | 9101011/9101014/9101024-9101029 |

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

响应侧用 `flowbits` 和 `http.stat_code` 确认：

- 9101102：HTTP 200，`tier alert`；
- 9101107：HTTP 401/403，`tier alert`；
- 9101104：外部源敏感路径探测收到 200/401/403/404，且达到 20 次/60 秒，`tier triage`。

### 3.3 不依赖 UA 的路径规则

9101103/9101104 使用 `recon_path.lua`，只看 URI + 频率，不要求 UA。
用于捕获随机 UA、缺失 UA 的扫描器；请求与响应两侧都用
`threshold: type both, count 20, seconds 60` 控制，不做跨包聚合。

### 3.4 限频语义

- 工具指纹：`threshold: type limit, track by_src, count 1, seconds 60`（每源每工具每分钟一条）；
- 响应侧确认：`track by_dst`（响应包源是本地服务器，目的才是外部客户端）；
- 互联网测绘：`type limit, count 1, seconds 300`；
- 高频脚本客户端/路径探测：`type both, count 50/60 或 20/60`（达到阈值后每周期最多一条）。

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
python3 test/generate_recon_pcaps.py --out test/recon_pcap
suricata -T -c test/suricata-recon-ci.yaml
for pcap in test/recon_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-recon-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/recon_cases.json
```

最终验证只认 `.github/workflows/suricata-recon-tools.yml` 的 GitHub Actions 结果。
