# Zeek 规则归档说明

Zeek 不承担 Snort/WAF/PVS 的 content/pcre 签名匹配，只消费**行为、状态、情报与白名单**。
本目录两类内容：

- 自研场景脚本：`DNS隧道与带外检测/`、`Web漏洞利用/`、`侦察与攻击工具指纹/`、`后门通信/`；
- 外部探针转换：`Web行为/`、`威胁情报/`（由 `规则检测/convert_probe_zeek.py` 生成）。

## 已转换（来自外部探针明文配置）

| 文件 | 来源 | 用途 |
|---|---|---|
| `Web行为/crawler_whitelist.zeek` | `utm/search_spider.ini` | 爬虫 IP/网段/UA 校验；UA 像爬虫但源 IP 不在爬虫网段 → 伪造爬虫告警 |
| `威胁情报/white_domains.zeek` | `utm/top100_white_domain.ini` | 业务白域名集合与 `is_white_domain()`，供误报抑制 |
| `威胁情报/public_dns_servers.zeek` | `utm/common_dns_server.ini` | 公共 DNS 服务器集合，供 DNS 行为上下文 |
| `威胁情报/botnet_apps.zeek` | `utm/utm_app_botnet.ini` | IRC/挖矿/Gh0st 等活动名称、危险等级、处置建议的归一化表 |

## 不适合 Zeek 的部分（保留在 Suricata/xbits）

- `sf_snort` / `waf` / `pvs` 的 `content`/`pcre` 规则：属于 Suricata 签名匹配；
- `ua_blacklist.ini` / `ua_graylist.ini`：只有哈希后的 rule id，无明文 UA，无法生成 Zeek 名单；
- `dynamic_domain.ini`：domain 字段为哈希值，无明文域名；
- `sls/*.encry`：加密黑名单，需 SLS 客户端解密；
- `dns_detect_tld.ini`：Public Suffix List，用于域名归一化而非检测；
- `conficker_detect.ini`：仅 DGA 参数，缺少 Conficker 域名生成算法，不能直接变成检测规则；
- `utm_abnormal_traffic_rules.ini`：仅 CRC/阈值参数，无明文语义。

## 重新生成

```bash
python 规则检测/convert_probe_zeek.py --src "C:/Users/sona/Desktop/流量检测规则"
```

生成的脚本由 `xbits-zeek` 镜像复制到 `/opt/xbits/zeek-rules/`，按需加载。