# Zeek 规则归档说明

Zeek 只做**行为分析**，不承担 Snort/WAF/PVS 的 `content/pcre` 签名匹配。
签名命中全部在 Suricata；关联和误报收敛在 xbits。

## 自研行为脚本

| 脚本 | 行为 |
|---|---|
| `DNS隧道与带外检测/dns_tunnel_score.zeek` | DNS 查询突发、TXT 突发、NXDOMAIN 突发 |
| `侦察与攻击工具指纹/recon_score.zeek` | 404/403 突发、unique URI 突发、请求频率 |
| `后门通信/backdoor_c2_score.zeek` | 同源重复 URI/固定请求节奏（不再做 cmd/shell 内容匹配） |

## 数据 / 情报脚本

| 文件 | 来源 | 用途 |
|---|---|---|
| `威胁情报/white_domains.zeek` | `top100_white_domain.ini` | 业务白域名集合与 `is_white_domain()`，供误报抑制 |
| `威胁情报/public_dns_servers.zeek` | `common_dns_server.ini` | 公共 DNS 服务器集合，供 DNS 行为上下文 |
| `威胁情报/botnet_apps.zeek` | `utm_app_botnet.ini` | IRC/挖矿/Gh0st 等名称、危险等级、处置建议的归一化表 |

## 已移出 Zeek 的内容

- `Web漏洞利用/web_exploit_chain.zeek`：原脚本重新做 SQLi/XXE/Log4Shell 等 content 匹配，属于 Suricata 签名；
- `Web行为/crawler_whitelist.zeek`：UA 特征匹配属于签名，已移除；
- 自研场景 Lua 脚本：保留在 Suricata `lua/`，作为签名增强；Zeek 不承载 Lua。

## 重新生成

```bash
python 规则检测/convert_probe_zeek.py --src "C:/Users/sona/Desktop/流量检测规则"
```

生成的脚本由 `xbits-zeek` 镜像复制到 `/opt/xbits/zeek-rules/`，按需加载。