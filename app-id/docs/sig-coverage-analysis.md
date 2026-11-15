# 扫描工具签名 / DPI 覆盖深度分析（26 sig 评估 + 缺口 + 补齐）

## 0. 方法与总体结论
指纹分层（由弱到强）：L1 默认 UA → L2 默认头/头顺序 → L3 TLS ClientHello（JA3/JA4）→ L4 HTTP/2 指纹 → L5 探针 payload → L6 行为。

现状：`扫描工具/` 的 26 个 `.sig` 主要是 **L1（UA）+ 少量 nmap L5 探针**；**L3/L4 完全未覆盖**；L6 由 `scan.zeek` 的行为判定补偿。

**结论：未完整覆盖。**
1. 已知“会发独特 UA”的工具，现有约 26 个，本轮再补 18 个品牌 UA；
2. 大量扫描器**没有 UA**（raw SYN / TLS / DNS / 定时探针），如 masscan、zmap、naabu、rustscan、unicornscan、hping3、testssl、sslyze、subfinder、amass 等——**只能靠行为或 TLS/DNS 指纹（L3/L6）识别，不能靠 UA 签名**；
3. 因此“完整覆盖”的正确表述应是：**品牌 UA 签名广覆盖 + 库指纹(JА3/JА4/H2) + 行为族兜底**，而非只堆 UA sig。

## 1. 现有 26 个 sig 覆盖矩阵
| 文件 | 工具 | 类别 | 指纹层 | 强度 | 备注/风险 |
|---|---|---|---|---|---|
| ffuf.sig | ffuf | 目录爆破 | L1 | 高 | UA 精确 |
| gobuster.sig | gobuster | 目录爆破 | L1 | 高 | 前缀 |
| feroxbuster.sig | feroxbuster | 目录爆破 | L1 | 高 | 前缀 |
| dirbuster.sig | DirBuster | 目录爆破 | L1 | 高 | 词边界 |
| sqlmap.sig | sqlmap | 漏洞扫描 | L1 | 高 | 前缀 |
| nuclei.sig | nuclei | 漏洞扫描 | L1 | 高 | 词边界 |
| nikto.sig | Nikto | 漏洞扫描 | L1 | 高 | — |
| wpscan.sig | WPScan | CMS/漏洞 | L1 | 高 | 词边界 |
| acunetix.sig | Acunetix/AWVS | 商业漏扫 | L1+头 | 高 | UA+`Acunetix-Aspect` 头 |
| nessus.sig | Nessus | 商业漏扫 | L1 | 高 | — |
| openvas.sig | OpenVAS | 商业漏扫 | L1 | 高 | — |
| whatweb.sig | WhatWeb | 指纹 | L1 | 高 | 前缀 |
| httpx.sig | httpx(Go) | 指纹/探测 | L1 | 中高 | `httpx/[0-9]`，排除 python-httpx |
| arjun.sig | Arjun | 参数发现 | L1 | 高 | 前缀 |
| wafw00f.sig | wafw00f | WAF 识别 | L1 | 中高 | 词边界 |
| commix.sig | commix | 命令注入 | L1 | 中高 | 词边界 |
| xsstrike.sig | XSStrike | XSS | L1 | 中高 | 词边界 |
| shodan.sig | Shodan | 测绘 | L1 | 高 | — |
| censys.sig | Censys | 测绘 | L1 | 高 | `CensysInspect/` |
| expanse.sig | Expanse | 测绘 | L1 | 高 | — |
| l9explore.sig | l9explore | 测绘 | L1 | 中高 | 词边界 |
| zgrab.sig | zgrab | 端口/协议 | L1 | 高 | 前缀 |
| **masscan.sig** | masscan | 端口扫描 | L1 | **低/存疑** | **masscan 默认 banner 不发 UA**，此 sig 很可能不触发；应以行为(port_scan)为准（待实测验证） |
| zmeu.sig | ZmEu | 老式脚本 | L1 | 高 | 词边界 |
| morfeus.sig | Morfeus | 老式脚本 | L1 | 高 | 词边界 |
| nmap.sig | Nmap | 端口/服务 | L5+L1 | 高 | TierA 探针 + NSE UA；TierB 前缀弱（仅旁证/探针序列） |

## 2. 缺口清单（按类别）
### 2.1 Web 漏洞扫描器
- 已覆盖：acunetix、nessus、openvas、nikto、nuclei、sqlmap、commix、xsstrike、wafw00f、whatweb、wpscan
- **缺（品牌 UA 可补）**：w3af、wapiti、arachni、skipfish、wfuzz、Netsparker/Invicti、AppScan、WebInspect、Qualys、Nexpose(Rapid7)、AppSpider、Dalfox
- **无独特 UA（行为/库指纹）**：OWASP ZAP、Burp Suite、Metasploit HTTP 模块（默认 UA 类浏览器）

### 2.2 CMS 扫描
- 已覆盖：wpscan
- **缺**：JoomScan、Droopescan、CMSeek、CMSmap、Plecost、BlindElephant

### 2.3 目录/参数爆破
- 已覆盖：gobuster、feroxbuster、ffuf、dirbuster、arjun
- **缺**：dirb、dirsearch、wfuzz、kiterunner、x8、paramspider(基于 python-requests→库指纹)

### 2.4 端口/资产扫描
- 已覆盖：nmap、masscan(行为)、zgrab
- **缺（多无 UA→行为）**：zmap、naabu、rustscan、unicornscan、hping3、xprobe2、AngryIP

### 2.5 子域/外部侦察
- **缺（DNS 层/行为）**：subfinder、amass、assetfinder、findomain、dnsrecon、dnsenum、fierce、theHarvester、recon-ng、Sublist3r、OneForAll

### 2.6 测绘/搜索引擎
- 已覆盖：shodan、censys、expanse
- **缺**：BinaryEdge、ZoomEye、FOFA、Quake、Netlas

### 2.7 商业漏扫
- 已覆盖：Nessus、OpenVAS、Acunetix
- **缺**：Qualys、Nexpose、Retina、Saint、Core Impact、Nipper

### 2.8 TLS/SSL 扫描
- **缺（TLS 指纹层）**：testssl.sh、sslyze、sslscan

### 2.9 云/数据库暴露扫描
- 多为协议探针/暴力（Redis/Mongo/ES 未授权探测）→ 行为/协议层，暂不逐一做 UA sig。

## 3. 补齐策略（三层）
1. **L1 UA（本轮补 18 个品牌 UA）**：w3af、wapiti、arachni、skipfish、wfuzz、netsparker、appscan、webinspect、qualys、nexpose、appspider、dalfox、kiterunner、joomscan、droopescan、cmseek、testssl、sslscan。
2. **L3/L4 库指纹（后续，需 Zeek 9.0.1 JA3 核验）**：Go crypto/tls、Rust rustls、Python OpenSSL、libcurl 的 JA3/JA4 + H2 SETTINGS，覆盖“自研/无 UA”扫描器。
3. **L6 行为（scan.zeek 已有 + 可扩）**：目录爆破、端口扫描；可加“DNS 侦察（多 A/PTR）”“同源多目标横向（horiz）”。
4. **L5 探针**：nmap 探针已覆盖部分；masscan/zmap 无 payload→靠 L6。

## 4. 本轮新增 18 个品牌 UA 签名
| 工具 | 类别 | 形式 | 置信 |
|---|---|---|---|
| w3af | web | 词边界 w3af | 中 |
| wapiti | web | 词边界 Wapiti | 中 |
| arachni | web | 词边界 Arachni | 中 |
| skipfish | web | 词边界 Skipfish | 中 |
| wfuzz | 目录/爆破 | 前缀 Wfuzz/ | 中高 |
| netsparker | 商业漏扫 | 词边界 Netsparker | 中 |
| appscan | 商业漏扫 | 词边界 AppScan | 中 |
| webinspect | 商业漏扫 | 词边界 WebInspect | 中 |
| qualys | 商业漏扫 | 词边界 Qualys | 中 |
| nexpose | 商业漏扫 | 词边界 Nexpose | 中 |
| appspider | 商业漏扫 | 词边界 AppSpider | 中 |
| dalfox | XSS | 词边界 Dalfox | 中 |
| kiterunner | 目录爆破 | 词边界 kiterunner | 中 |
| joomscan | CMS | 词边界 JoomScan | 中 |
| droopescan | CMS | 词边界 Droopescan | 中 |
| cmseek | CMS | 词边界 CMSeek | 中 |
| testssl | TLS | 词边界 testssl | 中 |
| sslscan | TLS | 词边界 sslscan | 中 |

> 说明：新增多为“品牌词出现在 UA”，UA 版本/大小写需实测校准；误报风险低（品牌词罕见），主要风险是**漏报**（工具未发该 UA 时）。全部进入“品牌字面”路径，但仅在 UA 出现品牌词时生效。

## 5. 边界与确认
- **无法穷尽所有扫描工具**；策略是“品牌 UA 广覆盖 + 库指纹/行为兜底未知/自研”。
- **无 UA 工具（masscan/zmap/naabu/rustscan/testssl 等）不能靠 UA sig**：masscan.sig 存疑（默认不发 UA），以行为 `port_scan` 为准；testssl/sslscan 属 TLS 指纹层待接 JA3。
- 之后用 `app-id/tests` + CI（Zeek 9.0.1 容器）实测**检出率/误报率**并回归。

## 6. 验证计划（见 tests/ 与 .github/workflows/app-id-scan.yml）
- 正样本：各 UA 工具单请求、nmap TierA、nmap 探针序列、目录爆破(多 404 URI)、端口扫描(多 SYN 端口)；
- 负样本：浏览器、curl、python-requests 正常、健康检查、Go 客户端；
- 指标：检出率（正样本被判/应判）、误报率（负样本被判）；阈值目标 FPR≈0。

## 7. 实测验证结果（GitHub Actions · Zeek 9.0.1 容器）
工作流 `.github/workflows/app-id-scan.yml` 已跑通（run #43739282279，**success**）：
- **检出率 DET = 47/47 = 100%**（44 个 UA 工具单请求 + nmap NSE UA + nmap FourOhFour + nmap 探针序列 + 目录爆破 + 端口扫描）；
- **误报率 FPR = 0/5 = 0%**（浏览器/curl/python-requests/健康检查/Go 客户端均未误判）。

过程中定位并修复的真实问题（体现 CI 价值）：
1. **`http_request` 时 `c$http$host`/`user_agent` 尚未填充**（Zeek 在后续 `http_header` 才设置）→ 改用 `event http_header` 取 Host/UA，UA 与目录爆破检测才生效；
2. **Zeek `.sig` 的 `payload` 正则对“行首锚定/前导字节”敏感**：`User-Agent:` 位于请求头（非 payload 开头）时明文签名不触发 → 现由脚本层 `http_header` 的 `ua_to_tool()` 兜底（HTTP/2 亦覆盖）；
3. 局部变量 `ln` 与 Zeek 内置 `ln` 冲突、文件 UTF-8 BOM 导致加载失败 → 已修复。

> 结论：**检测能力已在 Zeek 9.0.1 下实测通过**；UA 工具、nmap 探针、目录爆破、端口扫描均命中，负样本零误报。

## 8. 后续收敛：已完成的修复
按上文“缺口/收敛建议”逐项落地（均纳入 CI 回归）：
1. **`.sig` 行中段匹配（实测受限，已转脚本层）**：Zeek `payload` 正则**隐式锚定 payload 首字节**；实测对位于请求头中段的 `User-Agent:` **即使加前导 `[\x09\x0a\x0d\x20-\x7e]*` 也不触发**（CI `sig-hit = 0/42`）。因此 **UA 识别改由脚本层 `http_header` → `ua_to_tool()` 承担**（HTTP/1.x 与 HTTP/2 均覆盖，检出 100%）；`.sig` 保留用于**流首探针**（nmap FourOhFour/TierB 等）及其它引擎/场景。
2. **DNS 侦察（无 UA 工具）**：新增 **PTR 反查扫描**结构性检测（不同 PTR 查询 ≥ `dns_ptr_threshold`=20 → `dns_ptr_recon`），覆盖 dnsrecon/dnsenum/fierce 等反查类。
3. **低速慢扫（low-and-slow）**：新增 **长窗(1h)** 结构：同 (源,host) 累计不同 URI ≥ `slow_uri_threshold`=100 且 404/403 比 ≥ `slow_404_ratio`=0.5 → `slow_scan`，绕过短窗目录爆破阈值。
4. **TLS 指纹（JA3-lite，覆盖加密/无 UA 扫描器）**：核心 Zeek 9.0.1 **无内置 JA3 字段**，故实现**基于 `ssl_client_hello` 的“版本+密码套件序列”指纹**（如 `v771|4865-4866-4867`），通过 `redef` 表 `XbitsScan::tls_fp_to_tool` 映射到工具/库（默认空，生产按实测填充）。CI 用测试映射验证机制可用。
5. **误报控制**：`whitelist` + `shadow_mode` 已具备；所有新增检测均为结构性/多条件，弱线索不单独判定。

**仍属外部依赖/需真实基线（非本次可闭环）**：
- 完整 **JA3/JA4**（含扩展/曲线/SNI）需 `zkg install ja3` 外部包或插件（核心无字段）；本文的 JA3-lite 为轻量替代。
- 高保真“客户端库指纹表”（Go/Rust/Python/OpenSSL 的实测 JA3/JA4/H2）需受控采集后填入 `tls_fp_to_tool`。
- 阈值最终取值、NAT/压测/监控白名单需真实业务流量基线校准；更广的 slow-scan 需 UEBA。
