# C1/C3/C4 修复对抗式静态复核（FIX_REVIEW）

- 复核人：verifier（team deep-qa-rootcause / task t9）
- 对象：t6（C1 情报闭环 V-01..V-05）、t7（C3 可观测 V-07/S-04）、t8（C4 文件 triage V-08）三批修复；工作区另含 t10（V-09 min_confidence）改动，一并纳入证据核对。
- 方法：只读静态复核（read/grep/正则统计）。**未改源码、未推送、未跑 CI、未本地运行 cargo。** 行号以当前工作区为准。
- 判定：**Verified**＝修好；**Partially**＝改了但仍有缺口（写明缺口 file:line）；**Rejected**＝没改/假改/把错误吞得更深（附反证）。
- 原则：重点找"用新兜底换旧兜底"。总体结论：**未发现系统性"把错误吞得更深"的新兜底**；7 项中 5 项 Verified、2 项 Partially（V-02、V-03 各有一处真实残留，见 §二）。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| V-01 构造器缺字段 | **Verified** | 全仓仅 3 处 `EngineAlert {`，均完整或 `..Default::default()`；`#[derive(Default)]` 已加，无 E0063 |
| V-02 情报进决策链 | **Partially** | score/confidence/是否输出/文档均真实接入；**但分析层 `reason` 会被 validator 覆盖**（analysis.rs:1230-1232） |
| V-03 哈希可达+文件事件进引擎 | **Partially** | 三算法分派 + 文件事件先经引擎已成立；**但 triage 侧仍独立再查一次 hash 情报**（triage/triage.py:496-508,677-691） |
| V-04 加载统计/四态 | **Verified** | `SetLoad` 逐类、`is_empty` 覆盖 8 集合、帮助文本删默认、四态可区分 |
| V-05 威胁域名精确+公共后缀 | **Verified** | 威胁域名精确匹配；加载期拒绝 `co.kr`（实测 threat 域拒绝 1 条＝co.kr）；与 query.py 集合语义一致 |
| V-07 审计/ES 通道可观测 | **Verified** | emit/submit/切片/解析失败/线程存活均计数+stderr+可失败；剩余 `let _ =` 仅清理与管道发送 |
| V-08 triage 语义/进程树/线程隔离 | **Verified** | `ShellOutcome` 枚举齐、`kill(-pgid,SIGKILL)` 真杀组、`stored=false` 直接 failed、外部命令移入独立 worker |

---

## 一、逐项证据

### V-01 测试构造器缺字段 / E0063 风险 —— **Verified**

- `#[derive(Debug, Clone, Default, Serialize)]` 已加：`engine.rs:26`。
- 全仓 `EngineAlert {` 仅 4 处匹配，实际字面量 2 处 + 结构体定义：
  - 定义 `engine.rs:27`；生产构造 `engine.rs:317`（`make_alert`，含 `intel`/`allowlist`/`intel_decision`：`engine.rs:339-341`，字段齐全）；
  - 测试构造 `analysis.rs:1976` 使用 `..Default::default()`（`analysis.rs:1975` 注释说明）。→ 无 E0063 风险。
- 构造入口收口：生产仅 `Engine::make_alert`；`Default` 专供测试/结构体更新语法（`engine.rs:24-25`）。

### V-02 情报是否真正影响 score/confidence/是否输出；reason/文档/文档承诺 —— **Partially**

已验证成立（核心）：
- 决策点前置：`Engine::annotations(ev, ctx)`（`engine.rs:117-124`）；`make_alert(..., intel)`（`engine.rs:253-343`）内 `score = rule.score + INTEL_THREAT_SCORE_BONUS`（`:266,272`）、`confidence += INTEL_THREAT_CONFIDENCE_BONUS`（`:273-275`，且在 `min_confidence` 门槛判定 `:281-285` **之前**）。
- 是否输出受影响：`score_for(..., intel_bonus)` 把加分并入累计分并参与 `threshold`（`engine.rs:346-351, 411-415`）——威胁加分能真实推动越过阈值。
- 白名单只降级不丢弃：`allowlist-downgraded` 时 `confidence -= INTEL_ALLOWLIST_CONFIDENCE_PENALTY`，且在门槛**之后**执行（`engine.rs:286-292`）；不新增"情报驱动丢弃"路径。
- 标签：`intel_decision` ∈ {threat-hit, threat-overrides-allowlist, allowlist-downgraded}（`intel.rs:463-475`；`engine.rs:267-292`），并写入 `evidence`（`engine.rs:314-316`）。
- 文档 schema：`normalized_document` 顶层新增 `intel`/`allowlist`、`xbits.intel_decision`（`analysis.rs:1708-1719`）；`file_triage_document` 同样携带（`analysis.rs:1788-1799`）。
- 文档承诺一致：`xbits/README.md:319-347` 写明 score+20 / confidence+15 / 白名单-25 / 精确匹配 / 公共后缀拒绝 / public_dns 不参与加权；`allowlist/README.md:46-53`、`threat-intel/README.md:26` 同步。**代码与文档一致，非"只改文档"。**

**缺口（Partially）——reason 被 validator 覆盖：**
- 初始 `decision.reason = intel_reason(alert).unwrap_or("engine-alert")`（`analysis.rs:1169`；映射表 `:282-291`）。
- 但 validator 成功返回且 `reason` 非空时直接替换：`analysis.rs:1230-1232` `if !v.reason.is_empty() { decision.reason = v.reason; }`。
- CI 的 stub validator **恰好返回非空 reason**（`xbits/test/stub_validator.py` 的 `"reason": "stub-validator"`），因此带 validator 的运行里 `reason` 不再是指 `intel-*`。`intel_decision` 仍保留在 `evidence`（`analysis.rs:1177-1185`）与文档 `xbits.intel_decision`，可区分，但**任务要求的"allowlist 命中产出可区分的 reason"在最常见（配 validator）路径下不成立**。
- 修复方向：validator 的 reason 改为追加到 evidence，或仅在 `decision.reason == "engine-alert"` 时才采用 validator reason（与 `analysis.rs:1262-1265` 已有的保守逻辑一致）。

### V-03 md5/sha1/sha256 可达 + 文件事件先经引擎 + 是否 triage 再查一次 —— **Partially**

已验证成立（核心）：
- `HashAlgo{Md5,Sha1,Sha256}` + `threat_hash(algo, value)` 按算法分派三套集合：`intel.rs:47-73, 338-345`。
- `annotate_events` 分别查 `ev.file_md5/file_sha1/file_sha256`：`intel.rs:408-419`（不再只查 sha256）。
- 文件事件先经引擎、再进 triage：`hook.rs:316-336`——`for alert in engine.process(&ev)` → `let annotations = engine.intel_annotations(&ev)` → `pipeline.submit_file(ev, annotations)`；不再有"pipeline 为空就 continue 丢弃"。

**缺口（Partially）——triage 侧仍独立"再查一次"：**
- `triage/triage.py` 仍自带 hash 情报查询：`_load_hash_intel`（`triage/triage.py:496-508`）、默认读 `threat-intel/data/file_hash.txt`（`:677-686`），命中产出 `{"id":"intel.known_bad","severity":"critical","weight":90}`（`:687-691`），且 `intel.` 属 `strong_prefixes`（`:713-714`）。
- 这与 xbits 引擎的 md5/sha1/sha256 查询是**两套实现、两个数据源**（`file_hash.txt` vs 三个独立 txt；当前内容等价但可漂移）。triage 的 `intel.known_bad` 还能独立把 verdict 抬到 malicious，绕过 xbits 的评分/置信度/文档标注。
- 因此 `hook.rs:316-317` 注释"不在 triage 侧另起一套查询语义"与实现不符。
- 修复方向：triage 改为消费 xbits 通过 stdin 传入的情报标注（或删除自带 hash 查询），保证单一决策点与单一数据源；或在文档中显式记录"两层各自查、数据源必须同源"并加同源断言。

### V-04 加载统计逐类 / is_empty 覆盖 / 默认路径 / 三态可区分 —— **Verified**

- 逐类统计：`SetLoad{name,entries,error,rejected_public_suffixes,rejected_sample}`（`intel.rs:75-87`）；`load_dataset` 为每个数据集 push 一条（`intel.rs:161-193`），threat 5 类 + allowlist 3 类（`intel.rs:243-255`）。
- `is_empty()` 覆盖全部 8 个集合（threat ip/domain/md5/sha1/sha256 + allowlist domain/ip/public_dns）：`intel.rs:311-321`。
- 默认路径：帮助文本已改为"需显式指定，未指定即不启用"（`main.rs:199-201`），代码默认仍 `None`（`main.rs:65-66` 区段）——不实默认已删。
- 三/四态可区分：`IntelState{NotConfigured,Misconfigured,Empty,Loaded}`（`intel.rs:89-111`）+ `state()`（`:266-279`）；`report()` 逐项打印（`:281-309`）；`hook.rs:258-276` 逐项 eprintln 并打印 `intel=<state>`。
- 小瑕（不影响判定）：`Misconfigured` 把"某数据集文件不存在"也计为配置错误，可能把"仅部署部分数据集"显示为 misconfigured——属展示口径。

### V-05 威胁域名精确 / 公共后缀加载期拒绝 / 与 query.py 一致 —— **Verified**

- 威胁域名精确匹配：`threat.domains: HashSet`（`intel.rs:116-117`）、`threat_domain` 用 `contains`（`intel.rs:332-335`）；`annotate_events` 用 `threat_domain`（`:398`）。
- 公共后缀加载期拒绝：`PUBLIC_SUFFIXES`（`intel.rs:34-40`，含 `co.kr`）、`is_public_suffix`（`:43-45`）、`load_dataset(reject_public_suffix=true)`（`:245`）。**实测：`threat-intel/data/domain.txt` 50000 条唯一域名中被拒绝 1 条＝`co.kr`；allowlist 域名拒绝 0 条。**
- allowlist 后缀仍最长优先：`load_suffix_list` 按长度降序（`intel.rs:195-206`），`longest_suffix_hit` 首命中（`:215-227`）。
- 与 CLI 一致：`threat-intel/tools/query.py:78-83` `lookup_domain` 为集合精确匹配；`:63-70` hash 按 32/40/64 分派——与 intel.rs 一致。
- 小瑕（不影响判定）：`query.py` 不应用"公共后缀拒绝"（仅 xbits 拒绝），两者对 `co.kr` 这种被拒条目的查询结果会不同——属防御性差异；`PUBLIC_SUFFIXES` 是硬编码子集而非完整 PSL（已在 `intel.rs:30-33` 注释声明）。

### V-07 emit/submit/切片/解析失败/线程存活可观测；是否仍有 `let _ =` 吞错 —— **Verified**

- 文档出口 `DocumentEmitter::emit`：序列化/审计文件打开/写入/ES 推送/ES 命令失败 → `record_document_error()` + 带路径 stderr（`analysis.rs:803-859`）；无 sink 文档 → `report_document_without_sink()` 计数 + 限流 stderr（`:862-869`）。
- 入队失败：`submit_job` 检查 `tx.send` 结果，失败计数 + 连续 3 次 `fail()`（`analysis.rs:1932-1947`；`SEND_FAILURE_THRESHOLD=3` `:81`）；`submit_event/submit_alert/submit_file` 均走它（`:1949-1965`），不再 `let _ =`。
- 解析失败：`load_meta`/`load_match_buffers` 返回 `(map, ok)`，读/解析失败 eprintln + 计数 `config_errors`（`analysis.rs:483-533`；`new_with_health:1103-1110`）。
- 切片防 panic：`is_hex_hash`（32/40/64 hex，`analysis.rs:207-211`）；`resolve_file_path` 用 `sha.get(0..2)`（`:1594-1599`）；`handle_file` 非法 sha 直接 failed（`:1513-1517`）。
- 线程存活：`PipelineHealth`（`analysis.rs:96-194`）`available/reason` + 计数器；`catch_unwind` 包 init/每 job/flush，panic → `fail()`（`:1852-1909`）；`PipelineHealth::fail` 置不可用（`:150-160`）；`hook.rs:169-195` `ensure_pipeline_healthy` → 返回 Err → main 非零退出。
- 剩余 `let _ =`：仅 socket/临时目录清理（`hook.rs:204`、`lib.rs:140`、测试 `remove_dir_all`）与 reader 线程 `tx.send`（`analysis.rs:658`），均为合理忽略，**不在安全链路**。
- 小瑕（不影响判定）：stdout 告警的 `write_alert` 序列化失败仅 eprintln、未计入 `document_errors`（`hook.rs:158-167`）——属 stdout 通道非审计/ES 通道。

### V-08 run_shell 枚举 / 杀进程树 / stored=false / triage 移出分析线程 —— **Verified**

- 显式枚举：`ShellOutcome{Success,Timeout{after_ms,kill_error},NonZeroExit{code,stderr},SpawnError,OutputNotUtf8,IoError}` + `describe()`（`analysis.rs:540-575`）；三处调用（es-command `:842-848`、triage worker `:966-987`、validator `:1225-1247`）均 match。
- 真杀进程树：spawn `process_group(0)`（`analysis.rs:614-621`），超时 `kill_process_group` 调 `kill(-pid, SIGKILL)`（`:588-606`），失败回退 `child.kill()` 并记录（`:687-702`）；非 Unix 显式报"不支持"（`:608-611`）。
- 阶段语义区分：timeout 计 `triage_timeouts` 且 note=`triage-timeout…`（`analysis.rs:968-981`）；`ShellOutcome` 其他 → `triage-failed: <describe>`（`:982-986`）；仅"退出 0 但非 JSON"才叫 `bad-triage-json`（`:997-1007`）；`{"ok":false}` → `triage-returned-error`（`:1010-1018`）。
- `file_stored=false` 直接 failed：`admit_file`（`analysis.rs:1506-1512`）→ `failed` 文档（`:1488-1491`），不再猜路径。
- triage 移出分析线程：独立 worker + 有界队列 `sync_channel(TRIAGE_QUEUE_DEPTH=64)`（`analysis.rs:1827-1846`）；分析线程只 `submit_triage` 非阻塞投递（`:1544-1580`），外部命令只在 `TriageWorker::process`（`:920-988`）执行。
- 小瑕（不影响判定）：队列满时丢弃文件事件（`analysis.rs:1547-1561`）——已有 `triage_dropped` 计数 + `failed(triage-queue-full)` 文档，属有界背压而非静默；非超时路径若孙进程持有 stdout 管道，`recv_timeout(1s)` 超时→空输出→`Success("")`→`bad-triage-json`（`analysis.rs:709-735`），与"超时"仍可区分但边缘场景归到了 bad-json。

---

## 二、仍需修复清单（按严重度）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R1 | **medium** | `triage/triage.py:496-508, 677-691, 713` | triage 侧仍独立再查一次 hash 情报（读 `file_hash.txt`，产 `intel.known_bad` weight 90），与 xbits 引擎的 md5/sha1/sha256 查询并存且数据源不同；triage 的该 finding 可独立把 verdict 抬到 malicious，绕过 xbits 决策链。`hook.rs:316-317` 注释与实现不符 | 让 triage 消费 xbits 传入的 intel 标注或删除自带 hash 查询；统一数据源并加同源断言；修正 hook.rs 注释 |
| R2 | **medium** | `analysis.rs:1230-1232` | validator 返回非空 reason 时覆盖 `intel-*` reason（CI stub 就返回 `stub-validator`），"allowlist 命中产出可区分 reason"在配 validator 路径不成立 | validator reason 改为追加 evidence，或仅在 `decision.reason=="engine-alert"` 时采用 |
| R3 | low | `hook.rs:158-167` | stdout 告警序列化失败仅 eprintln，未计入 `document_errors`（审计/ES 通道已全计数，stdout 通道未计） | 计入统一计数或明确记录为 stdout-only 指标 |
| R4 | low | `analysis.rs:1547-1561` | triage 队列满丢弃文件事件（已计数+落文档，属背压） | 文档化丢弃阈值/告警；或对持续满队列触发 health degraded |
| R5 | low | `analysis.rs:709-735` | 非超时但孙进程持有 stdout 管道→空输出→`Success("")`→`bad-triage-json`，与真正 JSON 错误同形 | 增加"子进程退出但读管道超时"的独立判定 |
| R6 | low | `threat-intel/tools/query.py:78-83` | CLI 不应用公共后缀拒绝，与 intel.rs 加载期拒绝不完全一致；`PUBLIC_SUFFIXES` 非完整 PSL（已注明） | 文档写明两侧差异，或用同一 PSL 数据源 |
| R7 | low/info | `intel.rs:65` | `HashAlgo::from_hex_len` 全仓无调用（死代码） | 删除或接入查询前置校验 |

**范围外提醒（不在 C1/C3/C4，本次不判）**：仓库原报告 V-06（引擎 `prune()` 静默剪枝 `engine.rs:176-181`、`flush_pending` 空实现 `engine.rs:435-438`、`scores`/`cid_uid` 无界 `:88-89,346-351`）**仍为 open**，且 `flush_pending` 仍无调用者。t10（V-09）的 min_confidence 修复已核对：`confidence()` 不再 `.max(min_confidence)`（`engine.rs:231-251`），门槛为真过滤（`:281-285`），与本次 V-02 加分口径一致。

---

## 三、是否"用新兜底换旧兜底"

- 未发现把关键错误吞得更深的改动。原先几处静默点（emit 写失败、submit 失败、解析失败、切片 panic、triage 超时/坏 JSON 同形、线程 panic 停摆）均改为"计数 + stderr + 可失败状态 + 非零退出"，方向正确。
- 新增的两处"丢弃/覆盖"属**已计数并可见**的有界策略（triage 队列满丢弃、无 sink 文档 stderr 限流），不是静默兜底。
- 唯二实质残留是 **R1（triage 双层情报查询，且注释与实现相反）** 与 **R2（validator 覆盖 intel reason）**——建议在下一轮修复。

---

## 四、核验边界

1. 未执行 `cargo test`/`cargo build`/CI；"无 E0063 风险"基于全仓 `EngineAlert {` 构造点穷举与 `Default` 推导的静态判断，最终以 CI 编译为准。
2. 计数类结论（公共后缀拒绝 1 条、workflow 等）由本地只读脚本重算，均随报告给出命令语义。
3. 本文件为唯一新增产物（qa/FIX_REVIEW.md）；未修改任何源码。

---

# 第二轮：R1/R2 收尾修复复核（t11/t12 → t13）

> **复核期间发现工作区正被并行任务 t14 实时修改**（t14 目标："xbits 把文件情报传入 triage 并在命中时推 ES"，deps=t12）。`xbits/src/analysis.rs` 在复核过程中由 102,435B / 2,579 行 → 105,409B / 2,641 行 → 111,196B / 2,759 行，mtime 从 1:11 → 1:21。因此本节：**R2 判 Verified**；**R1 拆两段**——triage 侧（t12 交付，文件稳定于 1:16）判 Verified，xbits→triage 传参闭环判 **Partially（待 t14）**，不用 t14 的进行中代码替 t12 背书。

## R2 · validator reason 不得覆盖 intel 决策依据 —— **Verified**

证据（`analysis.rs`；该段代码文本在复核期间两次读取一致，未受 t14 编辑影响）：
- `Decision` 新增 `validator_reason: Option<String>`：`analysis.rs:263`。
- 有情报决策时保留 reason：`analysis.rs:1274-1279`
  ```rust
  if !v.reason.is_empty() {
      if decision.reason.starts_with("intel-") {
          decision.evidence.push(format!("validator-reason={}", v.reason));
          decision.validator_reason = Some(v.reason);
      } else { ... }
  ```
  → `decision.reason` 在 `intel-*` 时**不被改写**，只追加 evidence + 单独字段。
- 无情报决策时保持原语义：`analysis.rs:1280-1285`（主 reason 取 validator reason，同时记 `validator_reason`）。
- 文档：`analysis.rs:1779-1780` 仅在 `validator_reason` 为 `Some` 时写 `xbits.validator_reason`；`xbits.reason` 仍取 `decision.reason`，`xbits.intel_decision` 不变。
- 单测：`analysis.rs:2478-2513` `validator_reason_does_not_override_intel_decision_reason`——用 `cat >/dev/null; printf '{"verdict":"uncertain","confidence":60,"reason":"stub-validator"}'` **真实经 `run_shell` 执行**（正是 CI stub 的触发场景），断言 `reason==intel-threat`、`validator_reason==stub-validator`、evidence 含 `validator-reason=stub-validator`、文档三字段并存、无情报时 `reason==stub-validator`。
- 4 处 `Decision` 字面量均补 `validator_reason`（`:1219, 1490, 2220, 2454`）→ 无 E0063 风险。
- 文档一致：`xbits/README.md` 的 `--validator-cmd` 与 §8.1 已写明 intel-* 优先、validator reason 记 `xbits.validator_reason`（已核对，非只改文档）。

**结论**：原缺口真实关闭，非假改。

## R1 · triage 不再二次查询、以传入为准 —— **Partially**（triage 侧 Verified；端到端闭环由 t14 进行中）

### R1-A · triage 侧（t12）—— Verified（`triage/triage.py` 稳定于 1:16）

- 优先级与"不读盘"：`triage/triage.py:743-754`——`payload_present` 用 payload；`elif orchestrated`（`--stdin`）只记 `xbits-payload(none)`，**绝不读本地**；只有 `elif opts.get("hash_intel")` 与 else 才读本地（`:754-782`）。`main()` 置 `opts["orchestrated"]=bool(args.stdin)`、`opts["payload_intel"]=payload.get("intel") if args.stdin else None`（`:913-914`）。
- 单一结论/单次计分：`triage/triage.py:783-787`——`if intel_hit:` 只 push 一条 `intel.known_bad`（weight 90）；多条哈希命中不会重复计分。
- 可观测：`info["intel_source"]` / `info["intel_hit"]` / `engines["hash_intel"]`（`:788-790`），四态 `xbits-payload / xbits-payload(none) / local-file / none` 可区分。
- 独立 CLI 仍可用：非 `--stdin` 且未给 `--hash-intel` → 默认本地名单（`:765-782`），路径与旧逻辑一致。
- 入参解析兼容且做长度/hex 校验：`_payload_threat_hashes`（`:527-571`）支持 `{"threat":[...]}` / list / `{"hashes":[...]}` / str，按 32/40/64 分派、type 与长度冲突时丢弃、同 algo+value 去重。
- 新单测 3 条（`triage/tests/test_triage.py`）覆盖"单结论不重复计分""xbits 路径不读盘""CLI stdin 端到端"，与实现一致（未复跑，仅静态核对）。

### R1-B · xbits→triage 传参闭环 —— Partially（t12 未覆盖，t14 进行中）

- **t12 完成时刻的实情（analysis.rs 为 t11 版本，mtime 1:11）**：`TriageWorker::process` 的 stdin 输入是 `{"path","sha256","name","flow_id","sid"}`（原 `analysis.rs:960-967`），**不含 `intel`**。triage 侧又按 t12 改为 `--stdin` 不读本地 ⇒ 两端叠加，文件 triage 判定上 **hash 情报完全失效**（`intel.known_bad` 不再产生，verdict 不再因 hash 命中抬到 malicious）。即当时"不会丢失 hash 覆盖"**不成立**；`hook.rs:316-319` 注释（t12 只改注释）超前于实现。
- **当前工作区已出现 t14 的进行中实现**（非 t12 交付，未完成、未验证）：
  - `triage_request_input()`（`analysis.rs:1064-1084`）：`intel` 为 `Some` 时写 `input["intel"]={"threat":[...],"allowlist":[...]}`；
  - `TriageWorker::process` 已改用该函数（`analysis.rs:960`）；
  - `file_triage_to_es()`（`analysis.rs:1091-1108`）：known-bad 命中时 `completed/failed/skipped` 均推 ES。
- t13 依赖只有 t11/t12，且 `analysis.rs` 在复核期间持续增长（2,579→2,641→2,759 行），t14 未声明完成 → 本节**不**据此判 t12 的 R1 已闭环。
- **结论**：R1 的 triage 内部改造已闭环（Verified）；R1 的"端到端以传入情报为准 + 不丢 hash 覆盖"须待 t14 completed 后复核（届时预期 Verified，需一条"文件 hash 命中 → 文档 intel + ES 推送"的 e2e 佐证）。

## 第二轮剩余缺口（供再派单）

| # | 严重度 | 位置 | 缺口 | 建议 |
|---|---|---|---|---|
| RR1 | **high（暂挂 t14）** | t12 时点 `analysis.rs:960-967`；现行 `:960,1064-1084,1091-1108` | t12 交付时 xbits 未把 intel 传入 triage stdin，"以传入为准"无生产者，hash 覆盖丢失；hook.rs:316-319 注释超前 | t14 完成后复核：断言 xbits→triage payload 含 `intel.threat`；补 hash 命中的 file_triage e2e（文档 intel + ES） |
| RR2 | low | `xbits/src/hook.rs:316-319` | 注释与 t12 时点实现不符（依赖 t14 才成立） | t14 落地后确认；否则改成"triage 独立 CLI 读本地，xbits 路径以 payload 为准（待接线）" |
| RR3 | low | `triage/triage.py:754-764` | 显式 `--hash-intel` 指向不存在/不可读文件时 `local` 为空 → `intel_source` 回落 `"none"`，看不出"名单读失败"（PY-04 残留） | 区分 `none` 与 `local-unreadable`，写 `info.intel_error` |
| RR4 | low | `triage/triage.py:503-518` `_load_hash_intel` | 仍 `except OSError: pass`（独立 CLI 路径读失败静默，PY-04 残留） | 返回 `(set, error)` 并进 `info.intel_error` |

> 第一轮 §三 曾把 R1/R2 并列为"唯二实质残留"；第二轮结论为：**R2 已关闭**，**R1 的 triage 侧已关闭、链路侧待 t14**。

**第二轮复核边界**：
1. 未运行 cargo/CI；R2 的"无 E0063"基于 4 处 `Decision` 字面量穷举与 `AnalysisConfig: Default`（`analysis.rs:50`）静态判断。
2. triage 侧仅静态核对（t12 自称本地 17 项通过，本次未复跑）。
3. `analysis.rs` 为并发编辑目标（t14）；R2 引用的是复核期间两次读取一致的代码文本，行号可能随 t14 继续变动；R1-B 的行号取自复核窗口内的快照。

---

# 第三轮：RR1 端到端情报链路（t14 → t15）

> 仅复核 RR1（R2 已在第二轮判 Verified，不重复）。复核时 t14 已完成，`analysis.rs` 稳定于 111,745B / 2,770 行（mtime 1:24:23），`triage/triage.py` 仍为 t12 版本（40,093B / mtime 1:16:06，未与 t14 冲突）。只读，未运行 cargo/CI。

## 汇总

| 检查项 | 结论 | 关键证据 |
|---|---|---|
| 1) triage stdin 确实带 `intel.threat`（含文件 md5/sha1/sha256 命中） | **Verified** | `analysis.rs:1058-1090` `triage_request_input`；调用点 `:960`；intel 源自 `hook.rs:327` → `engine.intel_annotations` → `intel.rs:408-419` 三算法分派 |
| 2) hash 命中时 `to_es=true`，文档含 `intel`/`intel_decision` | **Verified** | `analysis.rs:1097-1114` `file_triage_to_es`；两处调用 `:1053`、`:1681`；文档 `:1886`(intel_decision)、`:1890`(intel) |
| 3) triage 判 clean + 命中黑 hash → 以情报为准并标 conflict | **Verified** | `analysis.rs:1823-1844` 判定与 note；`:1881/1882/1888` verdict/triage_verdict/intel_conflict |
| 4) 单测存在且静态可编译 | **Verified（静态）** | `analysis.rs:2335-2451` 三个用例 + helper；构造/签名逐项核对 |
| 5) triage 仍不在 orchestrated 路径读本地 | **Verified** | `triage/triage.py:743-753`、`:913-914`（t12 版本未变） |

## 逐项证据

### 1) xbits → triage stdin 携带 intel —— **Verified**

- 组装函数：`analysis.rs:1064-1090` `triage_request_input(event, path, sha, intel)`：
  ```rust
  let mut input = json!({"path":…, "sha256":…, "name":…, "flow_id":…, "sid":…});
  if let Some(ann) = intel {
      input["intel"] = json!({
          "threat": ann.threat.clone().unwrap_or_else(|| Value::Array(Vec::new())),
          "allowlist": ann.allowlist.clone().unwrap_or_else(|| Value::Array(Vec::new())),
      });
  }
  ```
  仅 `Some` 时出现该键；无情报时保持旧 payload（triage 记 `xbits-payload(none)`）。
- 调用点：`analysis.rs:960` `let input = triage_request_input(&event, &path, &sha, intel).to_string();`（`TriageWorker::process`），不再有内联 json。
- intel 的来源链完整（逐段核对）：
  - `hook.rs:320-330`：`is_file_event` → `engine.process(&ev)` → `let annotations = engine.intel_annotations(&ev)` → `pipeline.submit_file(ev, annotations)`；
  - `analysis.rs:1542` `handle_file(event, intel)` → `:1557-1561` `submit_triage(TriageJob{…, intel})`；
  - `engine.rs:127-129` `intel_annotations` → `annotations(ev, None)` → `intel.rs:367-435` `annotate_events`，其中 `intel.rs:408-419` 按 `HashAlgo::{Md5,Sha1,Sha256}` 分别查 `ev.file_md5/file_sha1/file_sha256`，命中写入 `threat` 且 `json!({"type": algo.as_str(), "value": value})`。
  - → `intel.threat` 里**确实**是该文件的 md5/sha1/sha256 命中项（type 为 `md5`/`sha1`/`sha256`）。
- triage 侧消费：`triage/triage.py:527-571` `_payload_threat_hashes` 识别 `{"threat":[...]}`，按 32/40/64 hex 过滤；`:750` 与文件实际哈希求交，避免盲信 payload。

### 2) hash 命中必推 ES，文档含 intel / intel_decision —— **Verified**

- 判定函数 `analysis.rs:1097-1114`：
  - `completed` → `threat_hit || verdict∈{malicious,suspicious}`；
  - `failed` / `skipped` → `threat_hit`；
  - `received` / `analyzing` → `false`。
- 两处阶段出口都走它（无旁路）：`Analyzer::emit_file_stage` `analysis.rs:1053`、`TriageWorker::emit_stage` `analysis.rs:1681`。
- 文档字段（`file_triage_document`，`analysis.rs:1796-1892`）：
  - `xbits.intel_decision` = `intel.and_then(EventIntelAnnotations::decision)`（`:1886`）；
  - 顶层 `intel` = `intel.and_then(|i| i.threat.clone())`（`:1890`）、`allowlist`（`:1891`）；
  - `xbits.verdict`（`:1881`）、`xbits.triage_verdict`（`:1882`）、`xbits.triage`（`:1884`）。

### 3) 冲突语义：clean + 黑 hash 不得静默采用 clean —— **Verified**

- `analysis.rs:1823-1844`：
  ```rust
  let threat_hit = intel.is_some_and(EventIntelAnnotations::threat_hit);
  let intel_conflict = threat_hit && status == "completed"
      && !matches!(verdict_text, "malicious" | "suspicious");
  let effective_verdict = if intel_conflict { Value::from("malicious") } else { verdict.clone() };
  // note 追加 `intel-conflict: xbits threat hit overrides triage verdict '<v>'`
  ```
- 文档落点：`xbits.verdict` 取 `effective_verdict`（`:1881`）、`xbits.triage_verdict` 保留原始 verdict（`:1882`）、`xbits.intel_conflict`（`:1888`）、note 合并（`:1879`）。
- 即 triage 判 clean 时，对外 verdict 为 `malicious` 且标 conflict，原始结论可追溯，**不存在静默采用 clean 的路径**。

### 4) 单测存在且静态可编译 —— **Verified（静态，未运行 cargo）**

- helper `analysis.rs:2335-2341` `sha256_hit_intel` 构造 `EventIntelAnnotations{threat,allowlist,public_dns_off_baseline}` 三字段齐全。
- `triage_request_input_carries_file_intel_and_omits_when_absent`（`:2343-2365`）：断言 `input["intel"]["threat"][0]` 的 type/value、allowlist 空数组、`None` 时无 `intel` 键。
- `file_intel_hit_marks_conflict_and_pushes_to_es`（`:2367-2404`）：断言 completed+clean+命中 → `to_es=true`、verdict=malicious、triage_verdict=clean、intel_conflict=true、intel_decision=threat-hit、note 含 `intel-conflict`；failed/skipped 命中 → true；received → false；无情报时 clean 不推 ES、intel_conflict=false。
- `triage_worker_sends_intel_and_es_receives_threat_doc`（`:2406-2451`）：**真实 worker** 路径——`triage_command` 用 `tee "<tmp>/input.json"` 落 stdin 再 `printf` clean JSON，`es_command` 用 `cat >> "<tmp>/es.jsonl"`；断言 stdin 含 `"intel"` 与 sha、ES 文档含 `"intel_conflict":true` / `"intel_decision":"threat-hit"` / `"stage":"completed"`。
- 静态签名/构造核对（无 E0063/E0308 风险）：`triage_request_input(&ev, &path, &sha, Some(&ann))`（`&PathBuf→&Path`、`&String→&str` 均 deref 强制）；`TriageWorker::new(&config, docs, Arc::clone(&health))` 与签名 `(config: &AnalysisConfig, docs: Arc<DocumentEmitter>, health: Arc<PipelineHealth>)` 一致；`worker.process(TriageJob{event,path,sha,intel})` 字段齐全；`AnalysisConfig{…, ..Default::default()}` 有 `impl Default`（`analysis.rs:50` 区段）。

### 5) triage 仍不在 orchestrated 路径读本地 —— **Verified**

- `triage/triage.py` 未变（mtime 1:16:06）：`:743-753` `payload_present` → 用 payload；`elif orchestrated` → 只记 `xbits-payload(none)`，**不读盘**；本地读取只在 `:754-764`（显式 `--hash-intel`）与 `:765-782`（独立 CLI 默认名单）。
- `:913-914` `opts["orchestrated"]=bool(args.stdin)`、`payload_intel=payload.get("intel") if args.stdin else None`。
- 与 t14 改动不冲突：t14 只改 xbits 侧（`analysis.rs`）与 README，未触碰 `triage/triage.py`。

## 第三轮仍可优化（均 low，不阻塞 RR1 关闭）

| # | 严重度 | 位置 | 观察 | 建议 |
|---|---|---|---|---|
| RR5 | low | `analysis.rs:1825-1827` | `intel_conflict` 仅在 `status=="completed"` 判定；`failed`/`skipped` + 命中黑 hash 时 `to_es=true` 但 `xbits.verdict` 仍为 null、`intel_conflict=false`——消费方需读顶层 `intel` 才能识别 | 可选：failed/skipped 命中时也标 `intel_conflict=true`（或新增 `intel_only=true`）并在 `triage/README:136` 写明 verdict 语义 |
| RR6 | low | `analysis.rs:2406-2451` | worker 单测依赖 `tee/printf/cat` 与临时目录，仅 Unix 可跑（本 crate 本就 Unix-only，CI Ubuntu 满足） | 无需改；CI 上确认该测试真正执行（非 skip） |
| RR7 | low/info | `analysis.rs:1083-1086` | 传给 triage 的 `allowlist` 对 triage 判定无用（它只取 32/40/64 hex）——冗余但无害，且便于未来扩展 | 保留或注释说明 |

**第三轮结论：RR1 已闭环。** 五项全部 Verified；第一轮 R1 的"hash 覆盖丢失"缺口已由 t14 补齐（intel 传入 + 命中必推 ES + 冲突不静默采用 clean），R1 可从 Partially 升级为 **Verified**（建议在 t14 完成后的 CI 回归通过后正式翻牌）。剩余 RR5-RR7 为优化项。

**第三轮复核边界**：未运行 cargo/CI；第 4 项为静态编译核对（未执行 `cargo test`），最终以 CI 编译与该 worker 测试的实际执行结果为准；`analysis.rs` 行号以本次快照（2,770 行）为准。
