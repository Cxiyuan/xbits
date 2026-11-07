# 全场景检测能力评估与 Zeek 关联分析方案

## 0. 结论
## 0.1 实施状态（2026-11-08）

已按场景引入 Zeek 9.0.1 关联脚本，并与 Suricata 8.0.8 的 EVE `community_id` 联动：

- DNS：`DNS隧道与带外检测/zeek/dns_tunnel_score.zeek`
- 侦察：`侦察与攻击工具指纹/zeek/recon_score.zeek`
- Web：`Web漏洞利用/zeek/web_exploit_chain.zeek`
- 后门/C2：`后门通信/zeek/backdoor_c2_score.zeek`

联动机制：

1. 四个 Suricata CI 配置均开启 `eve-log.community-id: true`；
2. Zeek 脚本用 `community_id_v1(c$id)` 写入 `*_correlation.log`；
3. Zeek 日志同时带 `related_sids`（对应场景 Suricata SID）；
4. CI 用 `test/assert_zeek.py` 校验 Zeek 事件，并与同一 PCAP 的 Suricata EVE
   告警 `community_id` 求交集；交集为空即失败；
5. Zeek 9.0.1 以固定 Docker digest 运行，`zeek -b -Cr` 加载脚本；
6. 不在仓库根级创建 `zeek/`，脚本均在场景目录内。

已验证的 linkage CI：

- DNS：run `42390068900` success
- 侦察：run `42393276047` success
- Web：run `42390068901` success
- 后门/C2：run `42390068823` success

> 该联动是 **telemetry 层联动**：Suricata/Lua 给单事件告警，Zeek 给跨流/聚合
> notice，两者通过 `community_id` + `related_sids` 在 SIEM/日志层关联。
> Zeek 不直接读取 Suricata 的规则内存/flowbits，也不替代 Suricata 规则。


当前仓库共有 4 个场景、5 个规则文件、**74 条 Suricata 规则、33 个 Lua 脚本、102 个 PCAP 回归用例**：

| 场景 | 规则文件 | 规则数 | Lua | PCAP 用例 | 最近通过 CI |
|---|---|---:|---:|---:|---|
| DNS 隧道与带外检测 | `DNS隧道与带外检测规则.rules` | 13 | 8 | 22 | `42369802438` |
| 侦察与攻击工具指纹 | `侦察与攻击工具指纹规则.rules` | 41 | 8 | 29 | `42375447812` |
| Web 漏洞利用 | `Web漏洞利用规则.rules` | 9 | 9 | 34 | `42377078821` |
| 后门通信 / C2 信标 | `WebShell后门通信规则.rules` + `命令与控制信标规则.rules` | 11 | 8 | 17 | `42384924560` |

**结论：没有做到“极致”。**

当前实现已经把“单事务、单包/单请求”的检测能力做得比较扎实，但仍然缺少：

1. **跨流/跨时间聚合**：同一来源的扫描、爆破、信标周期、慢速隧道；
2. **跨事件关联**：侦察 → 漏洞利用 → 上传/WebShell → C2 的攻击链；
3. **响应侧/文件侧确认**：部分场景只有请求侧或局部响应侧；
4. **加密流量可见性**：HTTPS/DoH/DoT/HTTP3 载荷不可见；
5. **资产/业务上下文**：授权扫描器、正常管理 API、业务模板、合法内部 URL；
6. **可量化的检出率/误报率**：没有带标签生产语料和 shadow 结果。

Zeek 可以弥补其中一部分——尤其是 **跨流聚合、周期/抖动、唯一 URI/404 比例、文件与上传链、跨协议关联**；
但 Zeek **不能替代** TLS 解密、资产上下文和标注语料，也不能保证“零误报”。

**Zeek 脚本已开发并接入各场景 CI。**

---

## 1. 各场景现状与盲区

### 1.1 DNS 隧道与带外检测

**已有能力：**

- 结构化 DNS 规则 + Lua 熵/字符集/标签评分；
- 请求侧 + 响应侧 TXT/NULL/CNAME 分析；
- `flowbits` 请求+响应确认；
- DoT ALPN、DoH Content-Type 配套规则；
- dataset 白名单、`dns.rrtype` 排除 PTR、`tier` 分级；
- 22 个正反例 PCAP，CI 通过。

**仍存在的盲区：**

- 规则内只能做单事务评分；不能按 `client_ip + 注册域` 统计：
  - 唯一子域数量；
  - NXDOMAIN 比例；
  - 查询长度/熵分布；
  - TXT 响应大小分布；
  - 查询间隔/低频慢速隧道；
- `threshold by_src` 在 NAT/解析器出口下会合并客户端；
- 分布式、多客户端、低慢速隧道无法在规则层识别；
- DoH 只覆盖 `Content-Type: application/dns-message`；DoH GET `?dns=`、HTTP/2/3 DoH、加密 DoH 载荷仍有盲区；
- DoT 只能看 ALPN/SNI，不能看 DNS 内容；
- 域名前置/CDN/合法 SaaS 仍需资产/白名单；
- 没有 DNS 响应与进程/主机的关联。

**Zeek 适合补：**

- `dns_request` / `dns_response` 事件按 `orig_h + 注册域` 维护状态；
- 唯一子域数、NXDOMAIN 比例、长度/熵、TXT 大小、查询间隔；
- 与 `conn.log`、`ssl.log`、`http.log` 关联 DoT/DoH；
- 生成 `notice.log` 或自定义日志；
- 不能解密 DoH/DoT 内容，只能看元数据/行为。

### 1.2 侦察与攻击工具指纹

**已有能力：**

- 41 条规则：工具 UA、方向、tier、敏感路径、404/403 突发、响应体确认、包裹 UA、方法/Host；
- 8 个 Lua；
- 29 个 PCAP，CI 通过。

**仍存在的盲区：**

- 规则只能做单请求/单响应；不能按源统计：
  - 唯一 URI 数；
  - 404/403 比例；
  - 路径字典覆盖率；
  - 工具 UA 与响应码/路径的时序一致性；
- 分布式扫描、NAT、慢速扫描；
- HTTPS/HTTP2/HTTP3；
- 授权扫描器、API 网关、健康检查；
- 扫描后是否进入漏洞利用，无跨场景关联；
- 响应体软 404 已处理，但业务白名单仍需资产上下文。

**Zeek 适合补：**

- `http` 事件按源聚合唯一 URI、状态码比例、方法分布、UA 一致性；
- 与 `conn.log`/`ssl.log` 关联扫描会话；
- 生成“扫描会话”notice；
- 与 Web 漏洞利用 notice 关联成攻击链。

### 1.3 Web 漏洞利用

**已有能力：**

- 9 条类别规则：SQLi、Traversal/LFI、Log4Shell、CMDi、Deser、SSRF、XXE、SSTI、Upload；
- 9 个 Lua；
- 请求 URI/Body/Cookie/Header、部分响应体确认；
- 34 个 PCAP，CI 通过。

**仍存在的盲区：**

- 规则内不做跨请求/会话关联：
  - SQLi 尝试 → 500/报错回显；
  - 文件上传 → 随后访问 WebShell；
  - SSRF/XXE → 回连/OOB；
  - 漏洞利用 → C2；
- 请求体只读前 16 KiB；
- JSON/multipart 只是字符串搜索，不是完整结构化解析；
- HTTPS/HTTP2/HTTP3；
- 加密/压缩/多层编码 payload；
- 业务模板、文件下载、合法内部 URL、上传源代码的白名单；
- 无文件 hash、MIME、文件落地关联；
- 无数据库/命令输出确认（部分响应规则可做）。

**Zeek 适合补：**

- `http` 请求/响应/实体数据、`files.log`；
- 上传文件 hash/MIME/文件名 → 后续访问同一文件；
- 漏洞尝试 → 响应错误/文件落地 → WebShell 访问；
- 与 C2 信标 notice 串联；
- 仍不能看加密 HTTPS 内容。

### 1.4 后门通信 / C2 信标

**已有能力：**

- WebShell 文件/参数/响应/工具 UA；
- C2 样本、URI 结构、Header 异常、面板 API、单字母参数、响应任务；
- 出站方向、tier、flowbits；
- 17 个 PCAP，CI 通过。

**仍存在的盲区：**

- 规则内不能识别：
  - 信标周期/抖动/低慢速；
  - 同一源对同一 URI 的长期重复；
  - 连接时长/上下行字节比；
  - 任务下发/回传的跨流关联；
- Behinder/Godzilla AES 加密 payload 不可解；
- HTTPS/HTTP2/HTTP3、DNS/DoH C2、域名前置；
- Cobalt Strike/Sliver/Mythic/Havoc 等 profile；
- JA3/JA4/SNI/证书异常；
- 授权红队/正常管理 API；
- 失陷主机 → 横向 → C2 的跨场景关联。

**Zeek 适合补：**

- `conn.log` + `http.log` + `ssl.log` + `dns.log` 按源/目标维护状态；
- 检查间隔均值/方差、重复 URI、UA 一致性、字节/时长；
- 与 JA3/JA4/SNI/证书关联（需 9.0.1 验证具体脚本/字段）；
- 生成“疑似信标”notice；
- 与侦察/Web 漏洞利用 notice 串联成攻击链；
- 不能解密 AES/HTTPS 内容，只能行为侧。

---

## 2. 为什么当前 Suricata+Lua 不能做到“极致”

Suricata 规则 + Lua 的强项是：

- 单事务字段匹配；
- 协议解析后的 URI/Body/Header/Cookie；
- 单流 `flowbits`；
- 规则内熵/字符集/结构评分；
- 快速、可解释、可回归。

天然限制是：

1. **Lua 状态是 per-thread，不能做跨包/跨流全量聚合**；
2. **规则内不能依赖全局计数**，否则内存/一致性不可控；
3. **阈值只能粗粒度按源/目的**，不能统计唯一 URI、周期、方差；
4. **不能做跨协议/跨会话攻击链**；
5. **加密流量载荷不可见**；
6. **没有资产/业务上下文**；
7. **没有生产标注语料**，无法给出真实检出率/误报率。

所以当前实现是“**扎实的单事件检测基线**”，不是“极致”。

---

## 3. Zeek 能补什么、不能补什么

| 盲区 | Suricata+Lua | Zeek | 结论 |
|---|---|---|---|
| DNS 唯一子域/NXDOMAIN/TXT 分布 | 只能单事务 | 可按源+域聚合 | **Zeek 明显补强** |
| 扫描唯一 URI/404 比例 | 只能阈值 | 可按源聚合 | **Zeek 明显补强** |
| 信标周期/抖动/字节比 | 不能 | 可按连接序列统计 | **Zeek 明显补强** |
| 上传文件 → 后续访问 | 部分 file.data | files.log + http 关联 | **Zeek 补强** |
| 跨场景攻击链 | 规则彼此独立 | 可维护主机风险状态 | **Zeek 补强** |
| 加密 HTTPS 内容 | 不可见 | 不可见（仅元数据） | 都需解密 |
| DoH/DoT 内容 | 不可见 | 不可见（仅 SNI/ALPN） | 都需解密/端点 |
| 资产/业务白名单 | 静态 dataset/抑制 | 需 Intel/资产输入 | 都需 CMDB/SIEM |
| 分布式/慢速 | 单源阈值 | 可按多源聚合，但仍有盲区 | Zeek+SIEM 联合 |
| 零误报/真实检出率 | 不能保证 | 不能保证 | 需标注语料/shadow |

**结论：Zeek 不是 Suricata 的替代，而是行为/统计/关联层。**

---

## 4. Zeek 脚本是否需要开发

**已开发并接入 CI。**

当前四个场景均已有 `.zeek` 脚本；按项目约束：

- 不创建仓库根级 `zeek/`；
- Zeek 脚本放在对应场景的 `zeek/` 子目录；
- 只有场景包含 `.zeek` 时才创建/运行该场景的 Zeek CI；当前四个 Suricata 场景均已满足；
- CI 必须精确安装 **Zeek 9.0.1**，`zeek -b -Cr <pcap> <scripts>` 加载并断言 `notice.log`/自定义日志。

### 4.1 已落地脚本

| 场景 | 建议脚本 | 作用 |
|---|---|---|
| DNS隧道与带外检测 | `DNS隧道与带外检测/zeek/dns_tunnel_score.zeek` | 按源+注册域统计唯一子域、NXDOMAIN、长度/熵、TXT 大小、查询间隔 |
| 侦察与攻击工具指纹 | `侦察与攻击工具指纹/zeek/recon_score.zeek` | 按源统计唯一 URI、404/403 比例、UA 一致性、敏感路径序列 |
| Web漏洞利用 | `Web漏洞利用/zeek/web_exploit_chain.zeek` | 请求/响应/文件关联，上传→访问，漏洞尝试→错误/文件落地 |
| 后门通信 | `后门通信/zeek/c2_beacon_score.zeek` | 连接间隔/抖动、重复 URI、字节/时长、JA3/SNI 关联 |
| 跨场景 | 新建 `攻击链关联/zeek/attack_chain.zeek` | 侦察→利用→WebShell→C2 的主机风险状态 |

> 跨场景脚本也放在独立场景目录（如 `攻击链关联/zeek/`），不要放仓库根级 `zeek/`。

### 4.2 需要验证的 Zeek 9.0.1 API

以下不能凭记忆写，落地前必须按 9.0.1 文档/源码核对：

- `dns_request` / `dns_response` 事件字段；
- `http_request` / `http_response` / `http_entity_data` 字段；
- `conn` 事件与 `Conn::Info` 字段；
- `ssl` / `x509` / JA3/JA4 脚本；
- `Notice` 框架字段与 `notice.log`；
- `SumStats` 框架是否在 9.0.1 核心中，或需固定版本包；
- `Intel` 框架；
- 表过期/状态清理方式；
- HTTP/2、HTTP/3/QUIC 解析程度。

### 4.3 CI 要求

- 每个含 `.zeek` 的场景，单独 workflow；
- 安装精确 Zeek 9.0.1（固定 Docker digest 或源码 tag，禁止浮动 tag）；
- `zeek -b` 加载无语法/加载错误；
- `zeek -b -Cr <pcap> <scripts>` 运行正例/反例；
- 断言 `notice.log`/自定义日志字段，而不是只看“有日志”；
- 上传 Zeek 日志与测试报告 artifact；
- 没有 Zeek 内容的场景，不创建/不运行 Zeek CI，也不得声称“Zeek 已验证”。

---

## 5. 建议的关联分析架构

```text
Suricata 8.0.8 + Lua
  单事务规则：UA/URI/Body/Header/Cookie/DNS/TLS 指纹
        │
        ├── EVE alert / 线索
        │
Zeek 9.0.1（场景内脚本）
  跨流聚合：唯一 URI、404 比例、DNS 子域分布、信标周期、
            文件 hash/上传→访问、JA3/SNI、主机风险状态
        │
        └── notice.log / 自定义 risk 日志
                │
        SIEM/NDR（资产、授权扫描器、历史基线、跨主机关联）
```

分工建议：

- **Suricata/Lua**：精确签名、请求字段、单事务语义、快速回归；
- **Zeek**：跨流/时间聚合、行为/周期、文件与协议关联、攻击链；
- **SIEM/NDR**：资产、授权、历史基线、跨主机/跨场景、长期存储；
- **TLS 解密/端点**：加密载荷可见性。

---

## 6. 当前各场景“是否极致”判断

| 场景 | 单事件检测 | 跨流关联 | 加密可见性 | 资产上下文 | 判断 |
|---|---|---|---|---|---|
| DNS | 较强 | 无 | DoH/DoT 盲 | 无 | 未极致 |
| 侦察 | 较强 | 无 | HTTPS 盲 | 无 | 未极致 |
| Web 漏洞 | 较强 | 无 | HTTPS 盲 | 无 | 未极致 |
| WebShell/C2 | 较强 | 无 | AES/HTTPS 盲 | 无 | 未极致 |

“极致”至少需要同时满足：

1. 每类事件有正反例和 CI；
2. 有跨流/跨时间行为分析；
3. 有跨场景攻击链；
4. 有资产/授权上下文；
5. 有生产标注语料和 shadow 误报率；
6. 对加密流量有明确解密/端点方案。

当前满足第 1 条；第 2-6 条未满足。

---

## 7. 建议优先级

1. **先做 Zeek 的 C2 信标 + DNS 聚合**：收益最高，Suricata 规则层完全做不了；
2. **再做侦察 404/唯一 URI 聚合**：补扫描会话；
3. **再做 Web 上传/文件/响应关联**：补攻击链；
4. **最后做跨场景 `attack_chain.zeek`**：依赖前面 notice 字段稳定；
5. 同时建立 **TLS 解密/端点可见性** 与 **标注语料/shadow**，否则无法量化检出率/误报率。

---

## 8. 结论

- 当前 74 条 Suricata 规则、33 个 Lua、102 个 PCAP 用例，全部是 **单事务/单事件检测**，CI 已通过；
- **没有达到“极致”**：缺跨流/时间聚合、攻击链、加密可见性、资产上下文和真实误报率；
- **Zeek 能显著补强** DNS/扫描/信标/文件/攻击链关联；
- **Zeek 不能替代** TLS 解密、资产上下文、标注语料；
- 当前 **四个场景的 Zeek 脚本已开发并接入 Suricata CI**；
- Zeek 脚本必须放在各场景 `zeek/` 子目录（或新建 `攻击链关联/zeek/`），不得建根级 `zeek/`；
- 在 Zeek 9.0.1 CI 通过前，不能声称 Zeek 已验证，也不能声称整体“零误报”。
