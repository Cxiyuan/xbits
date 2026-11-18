# 规则质量 QA 报告

> 范围：`规则检测/` 全部 Suricata/Zeek 规则与 `xbits/rules/*.json`
> 方法：静态规则质量启发式 + 现有 CI 矩阵结果；静态结论不能替代实网流量验证。
> 数据：`规则检测/docs/规则质量QA数据.json`，可复跑 `python 规则检测/qa_rule_quality.py`。

## 1. 总览

| 项目 | 数量 |
|---|---:|
| 全部 active 规则 | 17,477 |
| 外部探针转换规则 | 17,403 |
| 自研场景规则 | 74 |
| weak tier 规则 | 2,668 |
| 静态高风险 | 0 |
| 静态中风险 | 55 |
| 无告警状态链规则（`noalert`） | 0（场景 flowbits 19 条） |
| 重复 content/pcre 组 | 742 组 / 1,564 条规则 |
| 相同 msg 组 | 1,647 组 |

现有 CI 负样本只有 5 个，且 `qa-all`/规则矩阵主要覆盖自研场景；
**不能把 CI 的 0/5 误报率当成全量规则质量结论**。

## 2. 误报风险

### 2.1 高风险（已处理）

| SID | 规则 | 问题 | 处理 |
|---|---|---|---|
| 13169997 | `WebShell Detect` | `content:"X@Y"` + `flow:to_client,established` + `$HTTP_PORTS`，没有其他锚点/上下文，普通 HTTP 响应只要包含 `X@Y` 就命中 | 已加入 `docs/false-positive-sids.txt`，转换时剔除 |

当前 active 规则中已无静态高风险规则。

### 2.2 中风险：55 条“单一短内容/无锚点”规则

典型特征：只有 1 个 `content`，长度 ≤6，且没有 `pcre`、`byte_test`、
`dsize`、`urilen`、`filemagic`、`depth/offset/within/distance` 等约束。
这些规则容易被正常业务文本触发，建议按类别抽样验证后：

- 增加协议字段绑定（`http_uri`、`http_header`、`http_server_body` 等）；
- 增加第二段 content 或 pcre；
- 或标记为 `tier=weak`，不要直接作为高置信度告警。

### 2.3 weak tier：2,668 条

| 类别 | 数量 |
|---|---:|
| `Web攻击/敏感关键词` | 1,488 |
| `Web攻击/扫描器` | 588 |
| `Web攻击/信息泄露` | 486 |
| `Web攻击/SQL注入`（弱规则） | 54 |
| `恶意URL` | 52 |

这些规则本身是“灰/弱/泛化”规则，设计目标是低置信度线索。当前它们和强规则
一起落盘；生产配置如果全量加载，会产生大量低价值告警。建议：

- 生产 Suricata 只加载强规则文件；
- weak 规则单独加载，交给 xbits 做低置信度/上下文收敛；
- **当前 xbits 尚未消费 `tier=weak`，所以不能依赖 xbits 自动降噪**。

### 2.4 状态链规则：自研场景保留 19 条 flowbits

转换规则不再注入 flowbits；自研场景保留 19 条 flowbits 状态链、41 条 Lua 规则、
63 条 threshold 条件，用于在签名阶段减少误报、提高精确度。
当前 active 规则无 `noalert`，也没有转换规则残留的 flowbits。

### 2.5 重复与近似重复

- 742 组规则使用完全相同的 content/pcre 组合，共 1,564 条；
- 最大一组仍是 PVS SQL 响应确认模板，靠不同依赖 SID 区分；
- 1,647 组规则 msg 相同，例如 `Trojan-Ransom.Cerber` 952 个 SID、
  `XSS Scripting Attack` 214 个 SID、`WebShell Detect` 207 个 SID；
  这些需要按 SID 族管理，不能按 msg 做告警去重。

## 2.6 Lua 强化

已为 **7,024 条转换规则**挂载 Lua 上下文增强脚本，覆盖：

- WebShell：3,393 条（响应 2,847 / 请求 546）
- SQLi：543 条（含扫描器内 2 条特例）
- 敏感关键词：1,488 条
- 扫描器：184 条（仅工具指纹子集）
- 信息泄露：486 条（响应 81 / 请求 405；另扫描器内 1 条特例）
- 恶意 URL：52 条
- 命令执行/注入：314 条
- 目录遍历/文件包含：104 条
- 文件上传：31 条
- XSS：428 条

自研场景另有 41 条 `lua:` 规则、33 个 Lua 脚本保留。
详见 [Lua强化方案.md](Lua强化方案.md) 与 [Lua强化清单.json](Lua强化清单.json)。

## 3. Suricata 与 Zeek 检测内容重叠

清理后按引擎拆分，**不再有 content/pcre 双写**：

| 场景 | Suricata 签名/Lua 规则 | Zeek 行为脚本 | 当前边界 |
|---|---:|---|---|
| DNS 隧道 | 13 | `dns_tunnel_score.zeek` | Suricata 用 Lua/签名判断 OOB 域名、长标签、DoH/DoT；Zeek 统计查询/NXDOMAIN 突发 |
| Web 漏洞利用 | 9 | 无 | Suricata 的 Lua 负责 SQLi/XXE/Log4Shell 等签名增强；Zeek 不再重复内容匹配 |
| 侦察/扫描 | 41 | `recon_score.zeek` | Suricata 用 Lua/UA/路径签名；Zeek 统计 404/403、unique URI 频率 |
| 后门/C2 | 11 | `backdoor_c2_score.zeek` | Suricata 用 Lua/内容签名；Zeek 只统计同源重复 URI |
| 爬虫/Web 行为 | 已移除 | 已移除 | UA 签名归 Suricata，Zeek 不再做 UA/content 匹配 |

**结论：** Suricata 与 Zeek 现在是“签名命中”和“行为统计”两个维度，
同一流量可能同时产生一条签名告警和一条行为关联日志，但不再重复做同一内容匹配。
xbits 负责按 `community_id`/5-tuple 把两类事件关联、评分、去重和成功确认。

## 4. xbits 规则评估

### 4.1 规则构成

- `xbits/rules/analysis.json`：3 条；
- `xbits/rules/default.json`：5 条（其中包含 `xb-zeek-http-request`）；
- `xbits/rules/qa-all.json`：2 条，仅供测试。

### 4.2 是否为关联性分析规则

**当前不是完整的关联分析规则，只是“简单匹配 + 同 5-tuple 上下文门槛”。**

证据：

- `analysis.json` 已改为 SID 精确选择：`xb-suricata-web-sqli` 使用 1,395 个 active SQLi SID，
  `xb-suricata-recon` 使用 41 个自研侦察 SID，不再使用 `signature_contains:"SQL"`；
- `xb-zeek-appid-scanner` 用事件 `XbitsAlert::alert` + `alert_kind=scanner`；
- 引擎的 `require_context` 只检查同一 5-tuple 是否已有 Zeek HTTP context；
- `score` 已累加，`threshold` 已接入输出判断；
- `success_rules.json`、`sid_library.json`、`rules_meta.json` 仍**没有被 xbits 引擎加载**；
- `group_by` 只用于 score key，没有多事件序列/窗口聚合逻辑。

因此它具备“同 5-tuple 上下文门槛 + SID 精确过滤”，但还不具备：
多阶段依赖、攻击成功确认、规则链、跨事件窗口、同源多告警收敛。

### 4.3 误报风险

| 规则 | 风险 |
|---|---|
| `xb-suricata-web-sqli` | 已收窄到 1,395 个 active SQLi SID，不再是 1,185 条含 SQL 的宽匹配；但 SID 数量仍大，`require_context` 只要求任意 HTTP context，`benign_uri_contains` 只有 3 个路径，仍需实网负样本验证 |
| `xb-suricata-recon` | 41 个自研侦察 SID，范围明确，但仍依赖后续上下文置信度 |
| `xb-zeek-appid-scanner` | 所有 app-id scanner 告警直接转发，没有上下文/阈值/误报抑制 |
| `default.json` 的 `xb-zeek-http-request` | 对每个 HTTP request 命中；即使 threshold 已生效，score=5、threshold=5，每个 request 仍会输出，属于 legacy/测试配置，不能生产使用 |
| `qa-all.json` | 测试用全量转发，不能进入生产 |

### 4.4 是否适合后续开发

- **框架适合**：已有 5-tuple context、pending、confidence、evidence、SID 精确匹配的基础；
- **当前规则仍不宜直接生产**：`success_rules`/`tier` 未接入，缺少窗口/冷却，default 规则仍有洪泛风险；
- 建议开发顺序：
  1. 引擎读取 `sid_library.json`/`rules_meta.json`，补全 `category/subcategory/tier`；
  2. 实现窗口/冷却，避免同一 rule+key 反复输出；
  3. 接入 `success_rules.json`，实现请求→响应成功确认；
  4. 接入 `tier=weak`，弱规则必须上下文/成功确认才输出；
  5. 用 `community_id + SID` 对 Suricata/Zeek 双写结果去重。

## 5. 本轮已处理 / 后续优先级

本轮已完成：

1. SID `13169997` 已加入 `docs/false-positive-sids.txt` 并从 active 规则剔除；
2. weak tier 已拆分为独立加载配置：`docker/probe-rules-weak.yaml`；
   生产默认配置 `docker/probe-rules-production.yaml` 不加载 weak；
3. `xbits/rules/analysis.json` 已改为 SID 精确选择，并接入 `threshold` 判断；
4. 7,024 条转换规则已挂载 Lua 上下文增强脚本；自研 33 个 Lua/41 条规则保留。

后续：

- 复核 55 条中风险单内容规则，按类别补字段/第二特征或降级；
- 742 组同 pattern、1,647 组同 msg 规则按 SID 族合并/引用化；
- Zeek 已移除 `web_exploit_chain.zeek` 的内容签名，`backdoor_c2_score.zeek` 已改为纯行为；
  后续新增 Zeek 逻辑只允许统计/频率/时序类；
- xbits 增加窗口/冷却、`success_rules`、`tier=weak` 和 `community_id + SID` 去重。