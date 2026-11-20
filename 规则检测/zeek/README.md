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

## 历史解析工具（不产出文件）

`规则检测/convert_probe_zeek.py` 现仅保留 `parse_sections` 解析函数供人工核对明文
导出；`main()` 不读取输入目录、不创建目录、不写盘，运行固定退出 0。上表 3 个
`.zeek` 行为脚本为手工维护，**不得由转换器重建**（`xbits/test/qa_zeek_file_set.py`
静态扫描写盘路径 + 文件集合守卫）。威胁情报/白名单分别在根目录 `threat-intel/`、
`allowlist/`，均不经过 Zeek 脚本。