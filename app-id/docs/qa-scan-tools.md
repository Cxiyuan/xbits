# QA：扫描工具识别代码精准度评审（含"纯阈值触发"复审）

> 范围：`app-id/扫描工具/` 下全部 `.sig`（26 个）+ 其消费逻辑 `app-id/scripts/appid/scan.zeek`。
> 目标：评审识别精准度（误报/漏报），并**重新审视所有"仅靠阈值触发"的判定**。
> 结论：**.sig 类（工具字面）精度高但存在 h2/加密/伪造的漏报与少量边界误报；原 scan.zeek 的目录爆破/端口扫描/脚本库/version.bind 属"纯阈值触发"，已改为"多条件结构性证据"，弱线索不再单独判定。**

## 1. 结论速览
- **工具字面签名（UA/探针）**：精度最高（工具独有字面，正常流量几乎不会出现）→ 可"直判"，但**必须**：
  - 处理 **HTTP/2（HPACK，明文签名看不到）**、TCP 分片、TLS 加密 → 用**脚本层 UA 匹配**兜底（已加 `ua_to_tool()`）；
  - 对短/常见 token 加边界（避免子串误报）。
- **行为类（目录爆破/端口扫描）**：**不能只靠一个计数阈值**。已改为**多结构性条件**：
  - 目录爆破：按 **(源,host)**，需同时满足 不同URI数 + 404/403比 + 唯一比(URI/req) + 静态资源占比低；
  - 端口扫描：不同目的端口数 + **无载荷连接占比**（SYN/探测特征）。
- **弱线索（脚本库 UA、`version.bind`、nmap TierB）**：**禁止单独判定**，仅作旁证。

## 2. 逐项评审

### 2.1 工具 UA 签名（`scanner_ua_*` / `scanner_hdr_*`）
| 分组 | 工具 | token | 精度 | 已知风险 | 结论 |
|---|---|---|---|---|---|
| 目录爆破 | ffuf | `Fuzz Faster U Fool` | 高 | UA 可伪造 | KEEP |
| | gobuster | `gobuster/` | 高 | 前缀锚定，罕见误报 | KEEP |
| | feroxbuster | `feroxbuster/` | 高 | 同上 | KEEP |
| | dirbuster | `DirBuster` | 中高 | 子串，建议边界 | HARDEN（边界） |
| 漏洞扫描 | sqlmap | `sqlmap/` | 高 | — | KEEP |
| | nuclei | `Nuclei` | 中高 | 子串需 UA 限定（已限定 UA 行） | HARDEN（边界） |
| | nikto | `Nikto/` | 高 | — | KEEP |
| | wpscan | `WPScan` | 中高 | 子串 | HARDEN |
| 商业漏扫 | acunetix | `Acunetix` + 头 `Acunetix-(Aspect\|Product)` | 高 | — | KEEP |
| | nessus | `Nessus` | 中高 | 归一化 UA 可能不同 | KEEP |
| | openvas | `OpenVAS` | 中高 | — | KEEP |
| 指纹 | whatweb | `WhatWeb/` | 高 | — | KEEP |
| | httpx | `httpx/`（前缀） | 中高 | 与 python-httpx 区分靠前缀；其它 httpx 库可能误报 | HARDEN（版本号） |
| 其它 | arjun | `Arjun/` | 高 | — | KEEP |
| | wafw00f | `wafw00f` | 中高 | 子串 | HARDEN |
| | commix | `commix` | 中高 | 子串（如 commixed） | HARDEN |
| | xsstrike | `XSStrike` | 中高 | — | KEEP |
| 测绘 | shodan | `Shodan/` | 高 | — | KEEP |
| | censys | `CensysInspect/` | 高 | — | KEEP |
| | expanse | `Expanse/` | 高 | — | KEEP |
| | l9explore | `l9explore` | 高 | — | KEEP |
| | zgrab | `zgrab/` | 高 | — | KEEP |
| 端口扫描 | masscan | `masscan/` | 高 | 仅 HTTP banner 模式 | KEEP |
| 老式脚本 | zmeu / morfeus | `ZmEu` / `Morfeus` | 高 | — | KEEP |

**共性限制（必须在文档/实现中承认）：**
1. **HTTP/2**：`.sig` 匹配明文 payload，h2 头经 HPACK 编码不可见 → 靠脚本层 `http.user_agent`（已加 `ua_to_tool`）。
2. **TCP 分片/多包**：UA 跨包时明文签名可能漏 → 脚本层兜底。
3. **TLS 加密**：明文签名全失效 → 只能靠 JA3/证书/行为（当前未纳入 v2，待后续）。
4. **UA 可伪造**：字面命中≠恶意，但正常业务不会用这些工具字面 → 精度可接受；定向伪造属漏报/误报边界。

### 2.2 nmap.sig
| 签名 | 精度 | 问题 | 结论 |
|---|---|---|---|
| `nmap_tierA_*`（FourOhFour 路径 / `mstshash=nmap` / NSE UA / `sip:nm`） | 极高 | 几无 | KEEP（直判） |
| `nmap_tierB_*`（`^GET / HTTP/1.0`、`^OPTIONS / HTTP/1.0`、`^OPTIONS / RTSP/1.0`） | **低**（会命中正常 HTTP/1.0 客户端） | 前缀过宽、无法在签名层验证"无 Host/UA" | **仅作弱线索**（改为 `nmap_b` 计数，不单独判定，需结构性行为佐证） |

### 2.3 "纯阈值触发"复审（重点，已重构）
| 原逻辑 | 原触发 | 问题（误报来源） | 重构后（v2） |
|---|---|---|---|
| 目录爆破 | 同源 **≥50 URI** 且 404/403 占比≥70% | 仅按 src 聚合、API/爬虫/多租户易误报；单个计数阈值 | **按 (源,host)**，需同时满足：不同URI≥阈 + 404/403比≥阈 + **唯一比(URI/req)≥0.8** + **静态资源占比≤0.1** |
| 端口扫描 | 同源 **≥20 目的端口** | 仅端口计数；正常多服务/监控会误报 | 目的端口≥阈 **且 无载荷连接占比≥0.7**（`c$orig$size==0`，SYN/探测特征） |
| 脚本客户端 | `lib!=other` 且 请求数≥50 | 正常 requests/Go/curl 业务被误判 | **降为弱线索**，仅作旁证，**不单独触发** |
| DNS version.bind | 查询即记录 | dig/nslookup 也用 | **降为弱线索** |
| nmap TierB | 命中 | 正常 HTTP/1.0 | **降为弱线索** |
| 综合判定 | `behavior && score≥3` | 仍可能单一行为阈值判 | **只有"具体工具字面" 或 "结构性行为(目录爆破/端口扫描)" 才判**；弱线索永不单独判 |

> 结论：**已消除"单一计数阈值即命中"的路径**；行为判定改为"多条件结构性证据"，弱信号只做旁证。

## 3. 剩余误报风险（需用回归收敛）
- **端口扫描**：大量短 TLS 连接（如压测、健康检查）可能 nodata 比偏高 → 需白名单/基线；
- **目录爆破**：正常 API 网关/爬虫产生大量 URI 但静态资源低、404 低 → 由 404/403 比 + 唯一比双重约束降低；仍需负样本验证；
- **NAT 出口**：同 IP 多用户聚合可能误报 → 建议按 UA/会话细分或把 NAT 段入白名单；
- **httpx/**：其它 httpx 客户端可能误报 → 建议加版本号形态约束（`httpx/[0-9]`）；
- **子串 token**（nuclei/wpscan/dirbuster/wafw00f/commix）：建议加词边界。

## 4. 建议的加固项（后续）
1. 对子串 token 加边界（如 `(?:\A|[\s(])token(?:\b|[/ ])`），降低误报。
2. 引入 **TLS JA3/JA4** 与 HTTP/2 指纹作为"库指纹"维度（需 Zeek 9.0.1 能力核验）。
3. 建立**客户端库指纹表**（`mapping/client_libs.*`）与**负样本回归**（浏览器/curl/监控/健康检查/CDN/压测/NAT）。
4. 阈值全部可 `&redef`，上线先**影子模式**，按 evidence 抽检校准，FPR 目标≈0。

## 5. 验证计划（把"精准"落到实处）
- 正样本：nmap(-sS/-sV/-A)、ffuf、gobuster、nuclei、sqlmap、自研 python-requests/go 扫描器；
- 负样本：浏览器、curl/wget、API 客户端、监控探针、健康检查、压测、CDN 回源、NAT 多用户；
- 断言 `scan_report.log` 的 verdict/tool/evidence；要求**负样本 0 命中**、正样本召回可接受；持续回归。

## 6. 结论
- **工具字面识别**：精度高、可直接判（近零误报），补 h2/加密后识别率提升。
- **行为识别**：已从"纯阈值"改为"多条件结构性证据 + 弱线索只作旁证"，显著降低阈值型误报。
- **"完全零误报"**：在真实业务 + 严格结构性条件 + 白名单 + 影子校准下可达**近零误报**；但对抗性伪造/慢速扫描无法保证绝对 0，属客观边界。
