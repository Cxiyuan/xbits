# Zeek 规则归档说明

Zeek 只做**纯行为分析**，不承担：
- Snort/WAF/PVS 的 `content/pcre` 签名匹配（签名命中全部在 Suricata）；
- 任何名单/情报数据（威胁情报在根目录 `threat-intel/`，白名单在根目录 `allowlist/`）。

关联、误报收敛与情报/白名单查询都在 xbits：Zeek 行为脚本产出的事件经 hook
到 xbits 后，由 xbits 统一查询 allowlist（白）与 threat-intel（黑）再决策。

## 自研行为脚本

| 脚本 | 行为 |
|---|---|
| `DNS隧道与带外检测/dns_tunnel_score.zeek` | DNS 查询突发、TXT 突发、NXDOMAIN 突发 |
| `侦察与攻击工具指纹/recon_score.zeek` | 404/403 突发、unique URI 突发、请求频率 |
| `后门通信/backdoor_c2_score.zeek` | 同源重复 URI/固定请求节奏（不再做 cmd/shell 内容匹配） |

## 已移出 Zeek 的内容

- `Web漏洞利用/web_exploit_chain.zeek`：原脚本重新做 SQLi/XXE/Log4Shell 等 content 匹配，属于 Suricata 签名；
- `Web行为/crawler_whitelist.zeek`：UA 特征匹配属于签名，已移除；
- 自研场景 Lua 脚本：保留在 Suricata `lua/`，作为签名增强；Zeek 不承载 Lua；
- `威胁情报/botnet_apps.zeek`：仅“应用名→危险等级/处置建议”归一化表，无检测引擎消费（探针的应用识别引擎未转译，家族判断走 Suricata trojan/backdoor 规则族），属孤儿数据，已删除；
- `威胁情报/white_domains.zeek`、`威胁情报/public_dns_servers.zeek`：白名单/基线数据统一迁至根目录 `allowlist/` 子模块（自定义 `custom/` + 快照 `data/` + `tools/{add,refresh,query}.py`），整个 `威胁情报/` 目录已删除。

## 历史转译工具

```bash
python 规则检测/convert_probe_zeek.py --src "C:/Users/sona/Desktop/流量检测规则"
```
现仅保留解析工具函数供历史参考；**不再向 规则检测/zeek/ 输出任何数据脚本**（Zeek 纯行为分析）。