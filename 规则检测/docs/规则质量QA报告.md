# 规则质量 QA 报告

> 范围：`规则检测/` 全部 Suricata/Zeek 规则与 `xbits/rules/*.json`
> 方法：静态规则质量启发式 + 现有 CI 矩阵结果；静态结论不能替代实网流量验证。
> 数据：`规则检测/docs/规则质量QA数据.json`，可复跑 `python 规则检测/qa_rule_quality.py`。

## 1. 总览

| 项目 | 数量 |
|---|---:|
| 全部 active 规则 | 18,885 |
| 外部探针转换规则 | 18,811 |
| 自研场景规则 | 74 |
| weak tier 规则 | 2,668 |
| 静态高风险 | 0（已隔离 1 条） |
| 静态中风险 | 488 |
| 无告警状态链规则（`noalert`） | 433 |
| 重复 content/pcre 组 | 821 组 / 2,178 条规则 |
| 相同 msg 组 | 2,003 组 |

现有 CI 负样本只有 5 个，且 `qa-all`/规则矩阵主要覆盖自研场景；
**不能把 CI 的 0/5 误报率当成全量规则质量结论**。

## 2. 误报风险

### 2.1 高风险（已处理）

| SID | 规则 | 问题 | 处理 |
|---|---|---|---|
| 13169997 | `WebShell Detect` | `content:"X@Y"` + `flow:to_client,established` + `$HTTP_PORTS`，没有其他锚点/上下文，普通 HTTP 响应只要包含 `X@Y` 就命中 | 已加入 `docs/false-positive-sids.txt`，转换时剔除 |

当前 active 规则中已无静态高风险规则。

### 2.2 中风险：488 条“单一短内容/无锚点”规则

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

### 2.4 状态链规则：433 条

`flowbits:noalert` 的状态/链式规则本身不告警，不应算误报；需要确认它们都有
后续消费规则。当前 orphan `flowbits:isset` 已清理为 0，但状态链规则仍需在
变更规则时回归验证。

### 2.5 重复与近似重复

- 821 组规则使用完全相同的 content/pcre 组合，共 2,178 条；
- 最大一组是 296 条 PVS SQL 响应确认规则，共用
  `content:"HTTP/1." + pcre:"HTTP/1.[10] 200 OK"`，靠不同 flowbits 区分；
  它们不是简单的完全重复，但属于“同一模板批量生成”，可合并/引用化；
- 2,003 组规则 msg 相同，例如 `Trojan-Ransom.Cerber` 952 个 SID、
  `XSS Scripting Attack` 214 个 SID、`WebShell Detect` 207 个 SID；
  这些需要按 SID 族管理，不能按 msg 做告警去重。

## 3. Suricata 与 Zeek 检测内容重叠

当前 4 个自研场景都存在两层检测：Suricata 规则/Lua + Zeek 行为脚本。
两者都会写各自日志，但 xbits 没有自动按 SID 去重。

| 场景 | Suricata 规则数 | Zeek 脚本 | 重叠情况 |
|---|---:|---|---|
| DNS 隧道 | 13 | `dns_tunnel_score.zeek` | Zeek 50 查询/30 NXDOMAIN 阈值，与 Suricata 高频 DNS 规则、Lua 规则重叠；Zeek 引用 9109103/9109201/9109202 等 SID |
| Web 漏洞利用 | 9 | `web_exploit_chain.zeek` | Zeek `inspect()` 重新匹配 SQLi/XXE/Log4Shell/路径穿越/SSRF/SSTI/WebShell/反序列化/命令注入，与 9 条 Suricata 规则几乎一一重叠 |
| 侦察/扫描 | 41 | `recon_score.zeek` | Zeek 统计 404/403 突发、unique URI，与 Suricata 的 404 burst、scanner UA、路径规则重叠；Zeek 引用 4 个 SID |
| 后门/C2 | 11 | `backdoor_c2_score.zeek` | Zeek `inspect()` 匹配 cmd/z0/pass/exec/shell.php，与 WebShell/命令注入规则重叠；C2 重复 URI 与信标规则重叠 |
| 爬虫白名单 | 侦察/Web 扫描器规则 | `crawler_whitelist.zeek` | 白名单/伪造爬虫逻辑与 Suricata scanner UA 规则部分重叠；Zeek 更偏 FP 抑制 |

**结论：存在实质性重叠，且当前是“双写”而不是“单主检测 + 单副关联”。**
如果同时加载，同一攻击可能产生 Suricata alert + Zeek correlation log 两份结果。

建议按场景确定唯一检测 owner：

- Suricata：负责一次性 content/pcre 命中；
- Zeek：只做计数、时序、阈值、上下文富化，不再重新做内容签名；
- xbits：按 `community_id`/5-tuple/SID 去重、评分、成功确认。

如果短期不能改 Zeek 脚本，至少应在 xbits 以 `community_id + related_sids`
做 5 分钟窗口去重，避免双告警。

## 4. xbits 规则评估

### 4.1 规则构成

- `xbits/rules/analysis.json`：3 条；
- `xbits/rules/default.json`：5 条（其中包含 `xb-zeek-http-request`）；
- `xbits/rules/qa-all.json`：2 条，仅供测试。

### 4.2 是否为关联性分析规则

**当前不是完整的关联分析规则，只是“简单匹配 + 同 5-tuple 上下文门槛”。**

证据：

- `analysis.json` 已改为 SID 精确选择：`xb-suricata-web-sqli` 使用 1,768 个 active SQLi SID，
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
| `xb-suricata-web-sqli` | 已收窄到 1,768 个 active SQLi SID，不再是 1,185 条含 SQL 的宽匹配；但 SID 数量仍大，`require_context` 只要求任意 HTTP context，`benign_uri_contains` 只有 3 个路径，仍需实网负样本验证 |
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
3. `xbits/rules/analysis.json` 已改为 SID 精确选择，并接入 `threshold` 判断。

后续：

- 复核 488 条中风险单内容规则，按类别补字段/第二特征或降级；
- 821 组同 pattern、2,003 组同 msg 规则按 SID 族合并/引用化；
- Zeek `web_exploit_chain.zeek`、`backdoor_c2_score.zeek` 不再重新做内容签名，
  改为消费 Suricata alert 或只做聚合；
- xbits 增加窗口/冷却、`success_rules`、`tier=weak` 和 `community_id + SID` 去重。