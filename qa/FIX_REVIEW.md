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

---

# 第四轮：C7（CI paths + 元测试）与 C2（pending 状态机/状态表）复核

> 对象：t16（C7）、t17（C2）。复核时文件稳定（workflow 12:28-12:33、`qa_workflow_paths.py` 12:36、`analysis.rs` 12:26 / 2,902 行、`engine.rs` 12:29 / 951 行）。只读：未改源码、未推送、未跑 CI、未运行 cargo。
> **例外说明**：本轮用仓库自带 Python 解释器**执行了只读静态门禁** `xbits/test/qa_workflow_paths.py`（非 cargo/非 CI、不写仓库），并在系统临时目录做了 4 个对抗性用例（合成 workflow + 空壳资源，不触碰仓库）。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| C7-1 paths 覆盖新模块与测试资源 | **Verified** | 7 个 workflow 全部 push==PR；triage/threat-intel/allowlist 已在 ci+images；`测试用例/*.json` 进 images、`*.config` 进两者、`*.yaml.in` 进 ci；4 个自研场景目录按实际 `cp` 的文件精确加入 |
| C7-2 元测试能抓"新增目录未进 paths" | **Verified（有已记录盲区）** | 实跑 exit 0（164 资源）；对抗用例：未覆盖新目录→rc1 并点名、push≠PR→rc1、paths 解析失败→rc2；`os.path.join` 动态路径实测漏报（rc0，文档已声明） |
| C7-3 未引入重复触发 / 无 YAML 语法问题 | **Partially（成本，非正确性）** | 无 tab、单 `on/push/pull_request/jobs`、push/PR 集合一致；但 triage/intel/allowlist 同时触发 ci+images，4 场景目录同时触发 ci+场景 workflow（刻意，但增加重跑成本） |
| C2-1 analysis pending 过期与 recv 解耦 | **Verified** | 每条 job 之后与 Timeout 分支都调 `maintenance()`；单测"无空闲"注入 2 条→maintenance→计数 2 且落 2 条 fail-closed 文档 |
| C2-2 pending 容量上限 + 可见超限策略 | **Verified** | `PENDING_LIMIT=1024`；超限即 `process_now`（fail-closed）+ 计数 + 限流日志；单测有界/计数/落文档 |
| C2-3 engine prune 超时计数可见 | **Partially** | 三类 TTL 清理均计数+eprintln（`engine.rs:247-296`）；但引擎 pending 仍**只丢弃、无判定输出**；引擎计数访问器**仅测试使用**，未接入 hook/健康输出 |
| C2-4 flush_pending 真实现或已删除 | **Verified** | 全仓（源码/README/workflow/测试）`flush_pending` 0 命中，无残留注释承诺 |
| C2-5 scores/cid_uid 治理 | **Verified（含设计残留）** | `ScoreEntry{score,at}`+TTL+`MAX_SCORES` 重置、计数+日志；`cid_uid` 0 命中；残留：整表重置丢失全部累计分、60s TTL 改变累积语义 |
| C2-6 README 与实现一致 | **Partially** | 284-292 与实现一致；292-293 把"引擎侧计数"与"hook 故障消息"连写，但消息里的两个计数是**分析层**的 |

## 逐项证据

### C7-1 paths 覆盖 —— **Verified**

- `xbits-ci.yml:6-58` push 20 条 / `pull_request` 20 条：新增 `triage/**`、`threat-intel/**`、`allowlist/**`（`:14-16`、`:41-43`）、`测试用例/*.config`、`测试用例/*.yaml.in`（`:18-19`、`:45-46`）、4 个自研场景的 `*.rules`/`lua/**`/`dns_tunnel_allow.lst`（`:22-30`、`:49-57`）。
- `xbits-images.yml:6-46` push 14 / PR 14：新增 `测试用例/*.json`、`*.config`、3 个 `generate_*.py`、`triage/**`、`threat-intel/**`、`allowlist/**`（`:12-24`、`:33-45`）。
- `app-id-scan.yml:8-11`：PR paths 补 `.github/workflows/app-id-scan.yml`，与 push `:4-7` 对齐。
- 独立重算（本地只读脚本，逐 workflow 解析）：7 个 workflow `push` 与 `pull_request` **集合完全一致**（app-id 2/2、4 个场景 11-13、xbits-ci 20/20、xbits-images 14/14）；覆盖矩阵：`triage/**`/`threat-intel/**`/`allowlist/**` → ci+images；`测试用例/*.json` → images；`测试用例/*.config` → ci+images；`测试用例/*.yaml.in` → ci；4 场景 rules/lua → ci+对应场景 workflow。
- 与 workflow 实际读取对齐抽查：`xbits-ci.yml:372-387` 只 `cp` 那 4 个目录的具体 rules/lua/lst 与 `测试用例/*.config`；`:399-403` 用 `测试用例/suricata-*-ci.yaml.in`；`:395` 用 `xbits/testdata/suricata-unix-stream.yaml.in`（`xbits/**` 覆盖）。→ 新增 paths 不多不少，未整目录监听 `规则检测/**`。

### C7-2 元测试的检出能力 —— **Verified（含已声明盲区）**

- 规则（`qa_workflow_paths.py`）：
  - 自覆盖：`collect_resources()` 扫 workflow 文本 + 它引用的脚本/Dockerfile（`MAX_SCAN_DEPTH=3`，`:68-69,266-284`），归一化（`normalize` `:146-174`，支持 `"a"/"b"` 拼接、`--flag=path`、`dir/*.ext`），要求被**本 workflow 自己**的 `push.paths` 覆盖（`:314-316`）；被别的 workflow 覆盖不算。
  - 事件一致：`:245-252` 比对 push/PR 集合。
  - 反静默：有 `paths:` 却解析为空 → exit 2（`:238-244,300-304`）。
  - 生成物忽略清单 `:43-59`；动态目录兜底 `REQUIRED_DIR_ROOTS` `:62-66`。
- **实跑结果**（仓库自带 Python，只读）：`exit=0`，
  `app-id-scan 5 resources OK / 4 个场景 12-15 OK / xbits-ci 48 OK / xbits-images 57 OK`，合计 164 个被读路径、164 条 paths，`CI PATHS: PASS`。
- **对抗用例**（系统临时目录合成，不触仓库）：
  1. 新增 `newmod/data/x.txt` 被 workflow 读取但 paths 只有 `other/**` → **rc=1**，报错点名 `读取 newmod/data/x.txt ... 未覆盖`（能抓"新增目录未进 paths"）。
  2. push=`mod/**`、PR=`other/**` → **rc=1**，报 `push 与 pull_request 的 paths 不一致`。
  3. `paths:` 存在但缩进不可解析 → **rc=2**（拒绝静默通过）。
  4. **盲区**：资源仅由 `os.path.join(ROOT, "mod","data","x.txt")` 动态拼出、workflow 只 `python3 mod/tool.py` → **rc=0（漏报）**。与文件头 `:18-26` 的声明一致：变量拼接扫描不到，只能靠 `REQUIRED_DIR_ROOTS` 手工兜底（新动态目录不会被发现）。
- 结论：核心不变量成立且可执行；盲区已文档化，建议后续补 `os.path.join(...)` 字面量序列扫描或"资源声明清单"。

### C7-3 重复触发 / YAML 语法 —— **Partially（成本）**

- YAML 体检：7 个 workflow 均无 tab；`on/push/pull_request/jobs` 各 1 处；列表缩进正常；push/PR 集合一致（解析结果同上）。未发现语法级问题（未用 actionlint，属静态体检）。
- 重复触发（实测覆盖矩阵）：
  - `triage/**`、`threat-intel/**`、`allowlist/**` → 同时触发 `xbits-ci` 与 `xbits-images`（images 自述为"保底触发"，`xbits-images.yml:19-24`）；
  - 4 个场景的 rules/lua → 同时触发 `xbits-ci`（suricata-live，含 rust/docker 重作业）与对应 `suricata-*` 场景 workflow。
  - 影响：数据/规则小改会跑两条重链路。属**刻意设计**（t16 已量化说明），不是缺陷；但 CI 成本与并发占用需注意。
- 小瑕：`xbits-images.yml:63-64` 的 paths 门禁步骤位于 `Set up Python`（`:66-69`）**之前**，依赖 runner 预装 `python3`（ubuntu-22.04 有，故可用），建议下移或改用 setup 后的 python。

### C2-1 analysis 过期与 recv 解耦 —— **Verified**

- 循环：每条 job 处理完立即 `analyzer.maintenance()`（`analysis.rs:2045-2054`），`Timeout` 分支同样调用（`:2056-2067`）；两处均包 `catch_unwind` 并 `fail()`。
- `maintenance()` → `flush_expired_pending()`（`:1499-1501`）；后者按 `pending_context_timeout` 分流，过期者**逐条 `process_now`**（`:1469-1494`），计数 `pending_expired` + 汇总日志，不是丢弃。
- 单测 `pending_expiry_is_scanned_without_idle_and_counted`（`:2364-2393`）：连续注入 2 条（无空闲）→ `maintenance()` → `pending.len()==0`、`pending_expired()==2`、**分析文件恰好 2 行**（每条都产出 fail-closed 文档）。→ 持续流量下不再饿死。

### C2-2 pending 容量上限与可见超限 —— **Verified**

- `PENDING_LIMIT=1024`（`:88`）；`process()` 在入队前判 `len >= pending_limit` → 计数 + 前 5 次/每 1000 次日志 + `process_now`（fail-closed，不建 key）（`:1369-1380`）。
- 单测 `pending_overflow_is_bounded_visible_and_fail_closed`（`:2396-2421`）：limit=2、注入 4 条 → `pending.len()==2`、`pending_overflow()==2`、分析文件 2 行。

### C2-3 引擎 prune 超时"可见" —— **Partially**

- 已做：`prune_at()`（`engine.rs:247-296`）对 contexts/pending/scores 三类 TTL 清理分别累加 `contexts_expired`/`pending_expired`/`scores_expired` 并 eprintln；`scores` 超 `max_scores` 整表重置并计 `scores_reset`；`process()` 入口调用 `prune()`（`:239-241,480`）。测试 `ttl_prune_reports_expired_state_instead_of_silent_retain`（`:915-924`）断言三类计数。
- **缺口 1（语义）**：引擎 pending 过期仍是 `retain` 丢弃，日志原文 "dropped … **without a decision**"（`:276`），**不产出任何降级告警**。分析层已做 fail-closed 判定并落文档，引擎层仍是无输出丢弃——两层语义仍不一致，属"加了计数/日志"而非"可见判定"。
- **缺口 2（导出）**：`pending_expired()`/`pending_overflow()`/`contexts_expired()`/`scores_expired()`/`scores_reset()`/`contexts_len()`/`scores_len()` **只在 `engine.rs` 测试里被调用**（全仓 grep 无生产调用点）；`hook.rs:186-195` 故障消息里的 `pending_expired`/`pending_overflow` 来自分析层 `PipelineHealth`。即引擎计数未进入健康输出/退出码。
- 建议：① `prune_at` 对过期 pending 走与 analysis 层一致的 fail-closed 判定（产出 `context_missing` 降级告警）或明确写"引擎层丢弃=有意 fail-open"；② 给 `Engine` 加 `health_snapshot()` 并在 hook 启动/故障/退出时打印，别让计数只活在测试里。

### C2-4 flush_pending —— **Verified**

- 全仓 grep `flush_pending`（`xbits/src/*.rs`、`xbits/README.md`、`xbits/test/*.py`、`.github/workflows/*.yml`）= **0 命中**；原"清空返回空 Vec"的实现与注释均无残留。

### C2-5 scores / cid_uid 治理 —— **Verified（含设计残留）**

- `scores: HashMap<String, ScoreEntry>`（`engine.rs:102`），`ScoreEntry{score, at}`（`:87-90`）；`score_for` 每次累加并刷新 `at`（`:462-474`）；`prune_at` 按 TTL 清理（`:262-264`）；超 `MAX_SCORES=100_000`（`:81`）整表 `clear()` + `scores_reset` + 日志（`:287-295`）。
- `cid_uid`：字段与写入点均删除，全仓 grep = 0 命中。
- 单测：`engine_pending_overflow_is_bounded_and_counted`（`:926-937`）、`engine_score_table_resets_when_over_cap`（`:939-950`）。
- **设计残留（低）**：① 超限是**整表清空**，全部累计分清零（会短暂抑制依赖累积的规则；已日志 + README 说明 "threshold accumulation restarts"）；② `scores` 也用 60s（`self.ttl`）TTL，**慢速累积型规则**（threshold > score 且间隔 >60s）将永远达不到阈值——当前 `xbits/rules/analysis.json` 三条规则均 `threshold == score`（20/20、10/10、30/30），暂不受影响，但未来加此类规则会被静默削弱。建议容量压力改 LRU/单键淘汰，并在规则生成/校验阶段约束 `threshold > score` 必须显式声明累积窗口。

### C2-6 README 一致性 —— **Partially**

- 一致部分：`xbits/README.md:284-292` 明确"不承诺绝不丢事件"、分析层"过期即 fail-closed 判定 + 计数/日志"、容量上限与引擎侧 TTL/整表重置/FIFO，均与代码吻合。
- 不一致：`:292-293` 写"这些计数随健康状态一并输出（hook listener 的故障消息里包含 `pending_expired` / `pending_overflow`）"——hook 消息里的这两个计数是**分析层** `PipelineHealth` 的；**引擎层**同名计数并未输出（见 C2-3 缺口 2）。建议改为"分析层计数进故障消息；引擎层计数见 stderr 日志"。

## 回归检查（C1：情报决策 / min_confidence）

- **Verified**：`engine.rs` 仍保留 `INTEL_THREAT_SCORE_BONUS=20` / `INTEL_THREAT_CONFIDENCE_BONUS=15` / `INTEL_ALLOWLIST_CONFIDENCE_PENALTY=25`（`:11-19`）；`confidence()` 只做 `min(100)`、无 `.max(min_confidence)`（`:349-366`）；`make_alert` 情报加分在门槛前、白名单降级在门槛后（`:382-405`）；`annotations`/`intel_annotations`（`:145-160`）；`intel_decision` 写证据与字段（`:429-456`）；`score_for` 加分参与 threshold（`:462-474,519-529`）。测试 `threat_intel_boosts_score_and_confidence`、`min_confidence_filters_*`、`threat_intel_from_context_applies_to_deferred_alert` 等仍在（`:696-880`）。
- `analysis.rs` 侧 `intel_reason`（`:311`）、`validator_reason` 不覆盖 intel（`:1312`）、`normalized_document` 的 `intel`（`:1835`）与 `file_triage` 的 `intel_conflict`（`:1949`）均未回退。
- 结论：t17 未触碰 C1 语义，无回退。

## 第四轮仍需修复项（按严重度）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R4-1 | **medium** | `engine.rs:247-296`（尤其 `:276`）；`hook.rs:186-195` | 引擎 pending 过期仍"丢弃且无判定输出"，只有计数+日志；引擎计数访问器仅测试使用，未接入健康/退出输出 | prune 时按分析层同口径 fail-closed 判定并产出降级告警（或明确记录为有意 fail-open）；新增 `Engine::health_snapshot()` 并在 hook 启动/故障/退出打印 |
| R4-2 | **medium/low** | `engine.rs:262-264,287-295` | scores 整表清空 + 60s TTL 会让 `threshold > score` 的慢速累积规则永久达不到阈值（当前规则恰好 threshold==score，未暴露） | 容量压力改 LRU/单键淘汰；对 `threshold > score` 规则在生成/校验阶段要求显式累积窗口；README 写明 TTL 语义 |
| R4-3 | low | `qa_workflow_paths.py:18-26,62-66` | `os.path.join` 动态路径盲区（实测 rc0 漏报），`REQUIRED_DIR_ROOTS` 需手工维护，新增动态数据目录不会被发现 | 增加 `os.path.join("a","b",...)` 字面量序列扫描，或引入"QA 资源声明清单"并要求脚本注册 |
| R4-4 | low | `.github/workflows/xbits-ci.yml:6-58`、`xbits-images.yml:6-46` | triage/intel/allowlist 触发 ci+images；4 场景 rules 触发 ci（含重作业）+场景 workflow | 可接受（刻意）；若成本敏感，把 paths 门禁拆独立轻量 workflow，images 侧只保留真正构建输入 |
| R4-5 | low | `xbits-images.yml:63-69` | paths 门禁步骤早于 `Set up Python`，依赖 runner 预装 python3 | 下移门禁或使用 setup-python 提供的解释器 |
| R4-6 | low | `xbits/README.md:292-293` | 把引擎侧计数与 hook 故障消息连写，实际消息只含分析层计数 | 改为"分析层计数进故障消息；引擎层计数见 stderr 日志（或接入后更新）" |

**第四轮结论**：C7 的"paths 覆盖 + 元测试"与 C2 的"分析层 pending 解耦/有界/可见"**已实质修好**（可实跑的元测试 exit 0，且对抗用例能抓新增目录）；但 **C2 的引擎层仍是"丢弃 + 计数/日志"而非可见判定，引擎计数未导出**，README 相应表述需收口 → C2 整体判 **Partially**（分析层 Verified、引擎层 Partially），C7 整体判 **Verified（含成本型 Partially：重复触发/门禁顺序）**。

**第四轮复核边界**：未运行 `cargo test`/CI；C7-2 的"实跑"是仓库自带 Python 执行**只读静态门禁**（exit 0）与系统临时目录的对抗用例（合成文件，不写仓库）；C2 结论为静态代码+单测断言核对，最终以 CI 编译/测试为准。

---

# 第五轮：C2 收尾（R4-1/R4-2）复核

> 对象：t19（C2 收尾）。复核时文件稳定（`engine.rs` 12:55 / 1,100 行、`analysis.rs` 13:02 / 2,936 行、`hook.rs` 12:56 / 370 行、`model.rs` 12:51、`README.md` 13:01）。只读：未改源码、未推送、未跑 CI、未运行 cargo。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| R4-1 引擎 pending 过期可观察 + hook 消费 | **Verified** | 过期 pending → `degraded=context-missing` 降级告警，经 `process()` 返回给 hook 写 stdout + 送分析；分析层 `reason=degraded-*`、文档 `xbits.degraded`、不二次挂起、validator 不覆盖；engine 计数以 `engine_` 前缀进故障消息 |
| R4-2 scores 窗口/重置语义 | **Verified** | `score_window_sec` 按条目窗口过期；超上限**只淘汰最旧**并计 `scores_evicted`；`threshold>score` 行为被单测双向断言（默认窗口永不达标 / 显式 3600s 第 5 次达标） |
| 回归（C1/min_confidence/C3） | **Verified** | 情报加分/门槛/白名单降级/`intel_decision`/`intel_reason` 原样；`min_confidence` 仅对普通路径生效；分析层健康计数仍在故障消息里 |
| 残余（本轮新发现，不影响 R4-1/R4-2 字面闭合） | **R5-1 medium / R5-2 medium / R5-3~R5-5 low** | 引擎 prune 只在有事件时触发（静默期无及时性）；引擎 pending **溢出**仍是"计数+日志式丢弃"；跨规则同 key 时窗口可被短窗口规则缩短 |

## 逐项证据

### R4-1 引擎 pending 过期 → 可见降级告警，且真被消费 —— **Verified**

- 产出：`prune_at()` 把过期 pending 收集后逐条 `make_alert_with(..., Some("context-missing"))` 返回（`engine.rs:259-322`，调用点 `:311-320`）；`process()` 以 `let mut out = self.prune();` 与正常告警合并返回（`:572-573`、`:656`）。
- 告警内容：`degraded=context-missing`、`reason=context-missing`、`evidence` 追加 `degraded=…: require_context rule waited out its ttl without context (fail-closed, no suppression key)`（`engine.rs:503-507`、`:522-524`、`:535`）；新增字段带 `skip_serializing_if`（`:64-67`），正常告警 JSON 形状不变。
- 门槛例外：`degraded` 路径**不套用** `min_confidence`（`engine.rs:464-471`），单测 `expired_pending_emits_degraded_alert_even_below_min_confidence`（`:1086-1099`）用 `min_confidence=99` 断言仍产出；普通路径门槛测试仍在（`:902-…`）。
- hook 消费：两处 `ensure_pipeline_healthy(pipeline, Some(&engine))`（`hook.rs:308,330`）；告警统一走 `for alert in engine.process(&ev)` → `pipeline.submit_alert` + `write_alert`（`hook.rs:342-360`），降级告警因此进 stdout 与分析流水线。
- 分析侧：`decide()` 决策依据优先级 `intel-* > degraded-* > engine-alert`（`analysis.rs:1245-1250`），evidence 追加 `degraded=`（`:1259-1261`），validator reason 不得覆盖 `degraded-*`（`:1316-1320`）；`process()` 对 `alert.degraded` 不再二次挂起（`:1378-1399`）；归一化文档新增 `xbits.degraded`（`:1846`）；单测 `degraded_alert_is_visible_in_reason_and_document`（`:2634-2651`）。
- 计数导出（不再混指）：`hook.rs:169-215` 明确两层字段——分析层 `pending_expired`/`pending_overflow`（`:212-213`），引擎层 `engine_pending_expired`/`engine_pending_overflow`/`engine_contexts_expired`/`engine_scores_expired`/`engine_scores_evicted`（`:190-201`）。
- README：`xbits/README.md:290-299` 明确"不再丢弃、也不再只是计数"、降级告警语义、`min_confidence` 例外、`engine_` 前缀区分两层——与实现一致。

### R4-2 scores 窗口/淘汰语义 —— **Verified**

- 规则字段：`Rule.score_window_sec: Option<u64>`，`#[serde(default)]`（`model.rs:151-157`），文档写明 `threshold>score` 必须显式声明（`:153-155`）。
- 条目窗口：`ScoreEntry{score, at, window}`（`engine.rs:93-97`）；`score_for` 每次命中刷新 `at` 与 `window`（`:545-566`）；`prune_at` 按**条目自身** `window` 过期并计 `scores_expired`+日志（`:277-304`）。
- 容量：`enforce_score_cap()` 超上限按 `at` 升序淘汰 `excess` 条（**不再整表清空**），计 `scores_evicted`+日志（`:324-350`）；插入后（`:564`）与 prune 时（`:305`）都执行 → 表始终有界。
- 单测：`slow_accumulating_rule_needs_explicit_score_window`（`:1062-1084`）双向断言——默认 60s 窗口跨 90s → `fired==0` 且 `scores_expired>=5`；显式 3600s → 第 5 次达标 `fired==1` 且 `scores_expired==0`。`engine_score_table_evicts_oldest_when_over_cap`（`:1039-1050`）断言 `scores_len()==2` 且 `scores_evicted>=1`。
- README：`:301-306`、`:394-396` 写明窗口语义、默认窗口、`threshold>score` 要求与两个计数——与实现一致。

### 回归检查 —— **Verified**

- C1：`INTEL_*` 常量（`engine.rs:11-19`）；`confidence()` 仅 `min(100)`（`:349-366`）；情报加分在门槛前、白名单降级在门槛后（`:451-478`）；`intel_decision`/`intel`/`allowlist`（`:532-535`）；测试 `alert_default_covers_intel_fields`/`threat_intel_boosts_score_and_confidence`/`threat_intel_from_context_applies_to_deferred_alert`/`min_confidence_*` 全在（`:779-…`）。
- C3：分析层健康计数（`send_failures`/`document_errors`/`documents_without_sink`/`config_errors`/`triage_dropped`/`triage_timeouts`/`pending_expired`/`pending_overflow`）仍在故障消息（`hook.rs:205-213`），未回退。
- 构造/编译静态检查：`EngineAlert` 仍 `Default` 可派生（新字段 `Option`），字面量仅 `engine.rs:508`（含 `degraded`）与 `analysis.rs:2152`（`..Default::default()`）；`prune()` 返回类型变更后调用点只有 `process()`（`:573`）与测试（`:1002,1009,1094`），无遗漏。

## 本轮新发现（不影响 R4-1/R4-2 字面闭合，建议后续处理）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R5-1 | **medium** | `engine.rs:247-259`、`hook.rs:299`（`listener.incoming()`） | 引擎 prune **只在收到事件时**触发（`process()` 入口），hook 线程无定时器；若挂起告警后再无流量，降级告警与计数/日志会**无限期推迟**到下一条事件（README 只说"挂起超过 TTL → 产出降级告警"，未说明是事件驱动） | 给 hook 加周期性 tick（如 `listener.set_nonblocking` + poll，或复用分析线程 tick 定时调 `engine.prune()`），或在 README 明确"下次事件到达时判定" |
| R5-2 | **medium** | `engine.rs:628-641` | 引擎 pending **溢出**仍是"FIFO 删最旧 + 计数 + 限流日志"，**不产出任何可见告警**——与 R4-1 要修的"换个名字的静默丢弃"同类；README:293 如实写"FIFO 挤掉最旧并计数"，但没有可见判定 | 溢出淘汰时也走 `make_alert_with(..., Some("pending-overflow"))`（或至少 `process_now` fail-closed），与 TTL 路径统一 |
| R5-3 | **medium/low** | `engine.rs:561`（`entry.window = window;`）、`:545-566` | 累计分按 `group_by` 共享；同 key 下**短窗口规则命中会覆盖长窗口规则的 window**，使长窗口累积提前过期 → 可能永不达标（`scores_expired` 有计数，但无法区分"规则累积被截断"）。当前 `analysis.json` 三条规则均未设窗口（同默认 60s），未暴露 | `entry.window = entry.window.max(window)`（窗口单调）或 key 纳入 `rule.id`；补跨规则同 key 用例 |
| R5-4 | low | `model.rs:151-157`、`engine.rs:545-566` | `threshold>score` 且未声明窗口只靠文档+测试约束，加载期无校验/告警；误配只能通过 `scores_expired` 间接察觉 | 启动时对 `threshold > score && score_window_sec.is_none()` 打 warning 或拒绝加载（规则生成器同步校验） |
| R5-5 | low | `hook.rs:169-215` | 引擎计数只在"pipeline 不可用"故障消息里导出；正常运行/正常退出不输出快照（仅事件发生时 stderr 日志） | 启动打印一次窗口/容量配置，退出（或定期）打印两层计数快照 |
| R5-6 | low/info | `analysis.rs:1245-1250` | 降级告警同时命中情报时 `reason` 取 `intel-*`（设计优先级），`degraded` 只落字段/evidence；消费方需同时读 `xbits.reason` 与 `xbits.degraded` | 保留设计，文档注明两字段并读即可 |

**第五轮结论**：R4-1、R4-2 的**原缺口已真实闭合**（引擎 pending 过期不再是静默丢弃，而是带 `degraded` 标记的可见告警且被 hook/分析消费；scores 不再整表清空、窗口语义可配且被双向单测锁定）。C1/min_confidence/C3 无回退。但残留两类**同类风险**需继续盯：**R5-1（事件驱动导致的及时性缺口）** 与 **R5-2（溢出路径仍是无输出丢弃）**——二者都是"可见但不等价于判定"，建议下一轮优先；R5-3 的跨规则窗口覆盖属潜在检测回归，建议一并修。

**第五轮复核边界**：未运行 `cargo test`/CI；结论为静态代码 + 单测断言 + 文档一致性核对；"事件驱动无定时器"基于 `hook.rs` 全文件 grep（仅 `listener.incoming()`，无 `recv_timeout`/`thread::sleep`）。

---

# 第六轮：C2 再收尾（R5-1/R5-2/R5-3）复核

> 对象：t21。复核时文件稳定（`hook.rs` 13:15 / 458 行、`engine.rs` 13:16 / 1,189 行、`README.md` 13:16）。只读：未改源码、未推送、未跑 CI、未运行 cargo。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| R5-1 维护与事件解耦 / 半行不丢 | **Verified（engine 有单测；hook 接线为静态核对）** | accept 非阻塞+200ms 节流维护、连接 read_timeout(200ms)→维护；`pending: Vec<u8>` 残行缓冲只在 `\n` 切行、EOF 处理尾行；README 与实现一致 |
| R5-2 溢出可见判定 | **Verified** | 满队列挤出的最旧挂起告警 → `make_alert_with(..., Some("pending-overflow"))` 进本次输出，计数保留；单测锁定 2 条 degraded |
| R5-3 窗口单调 | **Verified** | `entry.window = entry.window.max(window)`；单测锁定"长窗口不被短窗口截断" |
| 回归（C1/min_confidence/R4-1/R4-2/C3） | **Verified** | 均未回退 |
| 本轮新发现 | **R6-1 medium/low、R6-2~R6-4 low** | process() 丢弃降级 pair 的原始事件→hook 用当前事件重配；hook 无集成测试；连接洪泛可饿死 tick；单行无长度上界 |

## 逐项证据

### R5-1 维护与事件到达解耦 + 半行 JSON —— **Verified（含静态核对项）**

- 定时维护：
  - `hook.rs:13-15` `MAINTENANCE_TICK=200ms` / `ACCEPT_IDLE_SLEEP=20ms`；
  - `hook.rs:438` `listener.set_nonblocking(true)`；`:440-456` accept 轮询：`WouldBlock` 且 `last_maintenance.elapsed() >= MAINTENANCE_TICK` → `maintenance(...)`（`:447-453`），无连接也推进；
  - 连接内：`hook.rs:305-306` `set_nonblocking(false)` + `set_read_timeout(MAINTENANCE_TICK)`；`:338-344` `WouldBlock|TimedOut` → `maintenance(engine, pipeline, writer)`，不再等下一事件；
  - `maintenance()`（`hook.rs:229-241`）消费 `engine.maintenance()` 的 `(event, alert)` 对：`pipeline.submit_alert(event, alert)` + `write_alert`，并复查流水线健康。
- 引擎侧接口：`engine.rs:251-257` `pub fn maintenance() -> Vec<(HookEvent, EngineAlert)>`，与 `process()` 解耦；单测 `maintenance_runs_without_new_events_and_returns_degraded_alerts`（`engine.rs:1173-1188`）用 `ttl=0`、**不调用 process**、仅 `maintenance()` 即得到 `degraded=context-missing` 且 `pending_len()==0`、计数递增。
- 半行 JSON 不丢（逐行核对 `hook.rs:299-354`）：
  - `pending: Vec<u8>` 残留缓冲（`:308`），每次 `read` **只追加**（`:325`）；
  - 仅在 `b'\n'` 处切行、`drain(..=pos)`（`:326-336`）——超时/分段读取都不会丢半行；
  - `Ok(0)` EOF 时把无换行的尾部行也处理（`:312-322`），保持旧 `lines()` 语义；
  - UTF-8 在**整行**上解码（`:330`），避免多字节被读边界切断；`trim()` 兼容 CRLF；
  - `Interrupted` 重试（`:345`），其它读错误只结束当前连接（`:346-350`）。
- README：`xbits/README.md:296-298` 明确 read_timeout/非阻塞轮询/200ms 节流/"残留半行缓冲，超时或分段读取都不会丢半行 JSON"——与实现一致。

### R5-2 溢出可见判定 —— **Verified**

- `engine.rs:642-672`：`pending.len() >= limit` 时 `remove(0)` 取最旧 → `pending_overflow += 1` + 限流日志（`:653-659`）→ 对**被挤出的挂起告警**调用 `make_alert_with(..., Some("pending-overflow"))` 并 `out.push`（`:660-671`）；随后才 push 新挂起（`:673-678`）。
- 降级通道与 `context-missing` 相同：`degraded=pending-overflow`、`reason` 同为该值、evidence 追加 `degraded=…`（`engine.rs:512-516`、`:531-533`、`:544`），且不套 `min_confidence`（`:474-480`）。
- 单测 `engine_pending_overflow_emits_degraded_alert`（`engine.rs:1062-1086`）：`max_pending=2` + 4 次挂起 → `pending_len()==2`、`pending_overflow()==2`、**degraded 恰好 2 条且全为 `pending-overflow`**、evidence 含该串。
- README：`:293-294` 写明"队列满同样产出可见降级告警 `degraded=pending-overflow` 并计数，不再只计数/打日志"——一致。

### R5-3 窗口单调 —— **Verified**

- `engine.rs:554-575`：`entry.window = entry.window.max(window)`（原 `entry.window = window` 已改），同 `group_by` 共享条目只增不减。
- 单测 `score_window_is_monotonic_max_across_rules_sharing_a_key`（`:1150-1171`）：long(3600s) 与 short(60s) 同 key，命中后推进 120s（> 短窗口、<< 长窗口）→ `scores_expired()==0` 且 `scores_len()==1`。
- README：`:305-307` 写明"窗口取单调最大值——短窗口规则不会把长窗口规则已累积的分提前清掉"——一致。

### 回归检查 —— **Verified**

- **C1**：`make_alert_with` 情报路径完整（`engine.rs:444-487`：score/confidence 加分、`intel_decision`、白名单降级在门槛后）；测试 `threat_intel_boosts_score_and_confidence`（`:819`）、`min_confidence_*`（`:933`、`:963`）均在；`EngineAlert` 新字段 `degraded` 仍 `Option` + `skip_serializing_if`（`:64-67`），构造点仍只有 `engine.rs` 的 `make_alert_with` 与 `analysis.rs` 的 `..Default::default()`。
- **min_confidence**：`:474-480` 仅 `degraded.is_none()` 时应用，普通路径语义未变（`:933-1006` 测试）。
- **R4-1 context-missing**：`engine.rs:316-330` + 测试 `:1136-1148`（`min_confidence=99` 仍产出降级）；hook 经 `maintenance()`/`handle_line()` 两路都写 stdout + 送分析。
- **R4-2 淘汰最旧**：`engine.rs:333-359` 未回退（仍按 `at` 升序淘汰 excess）；测试 `:1088-1099`。
- **C3 健康计数**：`hook.rs:181-220` 仍输出分析层 8 项 + 引擎层 `engine_` 前缀 5 项，未混指。

## 本轮新发现（不阻塞 R5-1/R5-2/R5-3 字面闭合）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R6-1 | **medium/low** | `engine.rs:585-589` + `hook.rs:286-291` | `process()` 把 `prune()` 的 `(event, alert)` **丢弃事件只留告警**；hook 随后用**当前事件** `ev.clone()` 投递给分析流水线。于是事件驱动路径下，过期/溢出降级告警在 `decide(event, alert)` 里拿到的是**别的事件的 payload/sid**（定时维护路径 `maintenance()` 则配对正确）。当前 context-missing 告警的 suppression key 恒 None，不会造成误抑制，但 evidence/payload 会错配 | `process()` 也返回 `(HookEvent, EngineAlert)`（与 `maintenance()` 统一），`handle_line` 按对投递；或 process 内不再 prune，完全交给维护 tick（需保留每事件 prune 的时效） |
| R6-2 | low | `hook.rs:299-354`、`:438-456` | R5-1 的 **hook 接线无自动化测试**（单测只覆盖 `Engine::maintenance`）；半行缓冲/EOF 尾行/超时维护均靠静态核对 | 加 Unix socket 集成测试：发半行→sleep > tick→补全行（断言事件被处理）、空连接挂起 > TTL（断言产出 degraded）、无换行 EOF（断言尾行处理） |
| R6-3 | low | `hook.rs:440-456` | accept 分支只在 `WouldBlock` 时维护；若客户端**持续 connect/close 但不发数据**，`serve_stream` 立即 EOF 返回，accept 永不空闲 → 定时维护可能被饿死（事件驱动路径也会 prune，但空连接无事件） | accept 成功分支也按 `last_maintenance` 节流调用一次 `maintenance()` |
| R6-4 | low | `hook.rs:308,325` | `pending` 无单行长度上界：客户端持续发送无换行数据可无界增长（socket 0666）。旧 `lines()` 同样会整体缓冲，属既有风险 | 设最大行长度（如 8MB），超限丢弃该连接并计数/日志 |

**第六轮结论**：R5-1/R5-2/R5-3 **原缺口均已真实闭合**（定时维护与事件到达解耦且有引擎级单测、半行 JSON 有 carry-over、溢出产出可见 `degraded=pending-overflow`、窗口单调且被单测锁定），C1/min_confidence/R4-1/R4-2/C3 无回退。剩余 4 项为**接线级/防御性**问题，其中 **R6-1（降级告警事件错配）** 建议优先修（改动小：`process()` 返回 pair 即可）。

**第六轮复核边界**：未运行 `cargo test`/CI；R5-1 的 hook 部分为静态核对（无集成测试可跑）；"半行不丢"结论基于 `serve_stream` 逐行代码审查，未做运行时注入验证。

---

# 第七轮：R6-1 与已知限制记录复核（t23）

> 只复核 R6-1 与 README 已知限制记录（R5-x/R4-x/C1 前几轮已 Verified，本轮仅做回归确认）。复核时文件稳定（`engine.rs` 13:29 / 1,238 行、`hook.rs` 13:28 / 460 行、`README.md` 13:31 / 440 行）。只读：未改源码、未推送、未跑 CI、未运行 cargo。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| R6-1 process() 降级告警配对自身事件 | **Verified** | `process()` 返回 `(HookEvent, EngineAlert)`；四个发射点分别用挂起/被挤掉/当前事件；hook 两分支按 pair 投递；单测锁定 sid/payload |
| 已知限制记录 | **Verified** | README §10 如实列出 R6-2/R6-3/R6-4/R5-4/R5-5/R5-6，标题即写"尚未修复" |
| 回归（R5-1/R5-2/R5-3、R4-1/R4-2、C1） | **Verified** | 锚点与单测均在，未回退 |
| 本轮低项 | **R7-1 low、R7-2 low** | 新单测未断言 flow_id（夹具无值）；README R6-3 括注略不精确（方向偏保守） |

## 逐项证据

### R6-1 事件驱动路径的降级告警携带自身事件 —— **Verified**

- 接口：`engine.rs:586` `pub fn process(&mut self, ev: &HookEvent) -> Vec<(HookEvent, EngineAlert)>`；`maintenance()` 仍返回同构 pair（`:251-257`），两条路径语义一致。
- 四个发射点逐一核对：
  1. **prune 过期降级**：`let mut out = self.prune();`（`:592`），`prune_at()` 内 `out.push((pending.event, alert))`（`:327`）→ 被降级挂起告警自己的事件；
  2. **上下文结算挂起告警**：`out.push((pending.event, alert))`（`:617`），注释明确"不再使用触发结算的 zeek 上下文事件"；
  3. **pending 溢出降级（R5-2）**：`out.push((evicted.event, alert))`（`:674`）；
  4. **本轮规则直接命中**：`out.push((ev.clone(), alert))`（`:689`）。
- hook 消费：`handle_line` 的文件分支与普通分支均改为 `for (event, alert) in engine.process(&ev)` 并用 pair 的 `event` 调 `pipeline.submit_alert(event, alert.clone())`（`hook.rs:269-277`、`:288-293`）；stdout 仍只写 `alert`（字段不变）。`maintenance()` 本就消费 pair（`hook.rs:234-239`）。
- 单测：`event_driven_degraded_alert_carries_its_own_event`（`engine.rs:1206-1237`）——`ttl=0`、first(sid=9103001,payload=first-payload) 挂起，later(sid=9999001,payload=later-payload,community_id=later-cid) 触发 prune；断言 pair 长度 1、`event.sid==9103001`、`event.payload=="first-payload"`、`event.sid != later.sid`、`alert.degraded==context-missing`。
- 其他调用点：全仓 `engine.process(` 仅 `hook.rs:272/288` 与 `engine.rs:1215/1222`（测试）；`lib.rs:115-132` 的 stdin 桥不使用 Engine，故返回类型变更无遗漏调用点。测试内改用 `process_alerts()` 折叠辅助（`:723-731`）。

**行为影响（非回退，附说明）**：上下文结算的告警投递给分析层的事件由"zeek 上下文事件"改为"suricata 告警事件"。`suppression_key()` 的 `event.source` 前缀随之由 `zeek` 变为 `suricata`，与 `match_context` 缓存 key 的构造口径（suricata）一致（`analysis.rs:453-475`、`:479-489`）；buffer 值仍可经 `alert.context` 回退取得（`analysis.rs:424-451`、`:493-498`）。白名单为内存态 `SuppressionStore`（无持久化），同一运行内生成/查询对称，因此**不构成回退**，反而修正了此前 zeek/suricata 前缀不一致的隐患。

### 已知限制记录 —— **Verified**

- `xbits/README.md:422-438` 新增 `## 10. 已知限制（low，尚未修复）`，开篇明写"**尚未修复**，在此如实记录（不隐藏，也不冒充已修）"。
- 六项逐一在列且措辞为"遗留/不会/没有"：
  - R6-2 hook 缺 Unix socket 集成测试（`:426-427`）；
  - R6-3 accept 持续连接可饿死 tick（`:428-429`）；
  - R6-4 pending 单行长度无上限（`:430-431`）；
  - R5-4 `threshold > score` 无加载期校验（`:432-433`）；
  - R5-5 引擎计数仅故障消息导出（`:434-435`）；
  - R5-6 degraded+intel 同时命中时 reason 取 intel（`:436-438`）。
- 未在其它章节把上述项写成"已修复"：全文 `R6-`/`R5-` 引用仅在 §10 与 R5-1/R5-3 的实现说明处（`:296`、`:305`），后者描述的是已修复项，无冲突。

### 回归检查 —— **Verified**

- R5-1：`engine.rs:251-257` maintenance pair 接口 + `hook.rs:234-239` 消费；单测 `maintenance_runs_without_new_events_and_returns_degraded_alerts`（`:1189-1203`）。
- R5-2：溢出降级 `:664-676`；单测 `engine_pending_overflow_emits_degraded_alert`（`:1078-1102`）。
- R5-3：`entry.window = entry.window.max(window)`（`:572`）；单测 `score_window_is_monotonic_max_across_rules_sharing_a_key`（`:1166-1187`）。
- R4-1：`prune_at` 过期降级 pair（`:268-331`）；单测 `ttl_prune_*`（`:1023-…`）、`expired_pending_emits_degraded_alert_even_below_min_confidence`（`:1151-1164`）。
- R4-2：`enforce_score_cap()` 淘汰最旧（`:333-359`）；单测 `engine_score_table_evicts_oldest_when_over_cap`（`:1104-1115`）。
- C1：`INTEL_THREAT_SCORE_BONUS`（`:11`）与加分位置（`:464`、`:632`）；`min_confidence` 仅非 degraded 生效（`:474-480`）；单测 `threat_intel_boosts_score_and_confidence`（`:834`）、`min_confidence_*`（`:948`、`:978`）。

## 本轮低项（不阻塞 R6-1 关闭）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R7-1 | low | `engine.rs:1206-1237`、夹具 `:707-721` | 任务要求核对 sid/payload/**flow_id**，但夹具 `alert_event()` 未设置 `flow_id`（默认 `None`），单测只断言 sid/payload；实现上事件整体搬移必然携带 flow_id，属**测试覆盖**缺口而非功能缺口 | 夹具补 `flow_id: Some("first-flow")`，测试断言 pair 的 `event.flow_id` 与后续事件不同 |
| R7-2 | low | `xbits/README.md:428-429` | R6-3 括注"该连接的 `read_timeout` 仍提供维护"仅在**空闲**时成立；若数据持续不断，read_timeout 不触发（实际由每事件 `process()` 内 prune 覆盖）。表述偏保守、不构成"冒充已修"，但措辞可更准确 | 改为"持续有数据时由每事件 process() 的 prune 覆盖；空闲时由 read_timeout 维护；仅 accept 侧 tick 被推迟" |

**第七轮结论**：R6-1 **已真实闭合**（四个发射点都配对自身事件、hook 两分支按 pair 投递、单测锁定，且行为变化对抑制链路是修正而非回退）；README §10 如实记录 6 项已知限制、未冒充已修；R5-1/R5-2/R5-3、R4-1/R4-2、C1 均未回退。仅剩 R7-1/R7-2 两个低项。

**第七轮复核边界**：未运行 `cargo test`/CI；R6-1 结论为静态代码 + 单测断言核对；"flow_id 必然携带"基于 `HookEvent` 整体搬移的代码路径判断，未运行验证。

---

# 第八轮：C8（测试与 CI 断言真实化）/ C9（Python 三态·签名·IPv6）复核

> 对象：t25（C8）、t26（C9）。只读：未改源码、未推送、未跑 CI、未运行 cargo；**跑了 Python 单测与只读门禁**（DSH 内置 Python 3.12.14），并用系统临时目录做了对抗用例。工作树 `git diff --stat` 共 17 个文件；**`xbits/src` 无改动**（`git diff --stat -- xbits/src` 为空），因此 C1/C2/C3/C4 的 Rust 断言与实现未被本轮触碰。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| C8-1 覆盖门禁如实化 | **Verified** | 实跑输出 `covered 74/17477 (0.4%) \| excluded 11 dirs / 17403 SIDs` + 每目录排除原因；未分类目录/列表腐烂都 FAIL |
| C8-2 hook 矩阵口径 | **Verified（R8-1）** | exact = 场景内命中集合 == require（负例与 web 默认 exact）；subset 的未声明/跨场景命中 → `::warning::`；`--strict-warnings` 可升级；CI 目前仍 warning 模式 |
| C8-3 CI 弱断言替换 | **Verified** | 5 处 sleep+grep+kill||true 断言改为 `assert_hook_output.py` 轮询+字段+exit/stderr 校验；stdin 回声测试改 `assert_xbits` 精确计数 |
| C8-4 双空用例 | **Verified（R8-2）** | `assert_suricata.py` 双空直接 FAIL（对抗实测 exit 1）；4 个 cases 文件 104 个用例均无双重空；c2_periodic 补 forbid+note |
| C8-5 pefile/YARA 值断言 | **Verified** | PE 断言 machine/subsystem/sections/import_count；ELF 断言 machine/type/entry/statically_linked；YARA 正例必中+负例不中；缺依赖时断言 engines=false 并 skip，CI 双跑 0/1 |
| C9-1 engines 三态 | **Verified（R8-3/R8-4）** | 10 个工具全部走 `_set_engine(present, ok, error)`；rc!=0/超时/解析失败 → present=True ok=False → `degraded=true`；局部 yara 编译失败与 semgrep JSON errors 仍只记录 |
| C9-2 signed 拆分 | **Verified** | `signed_present` 存在性 / `signature_verified` 恒 False；降级闸门改用 `signature_verified`（不可达）；测试断言伪证书不洗白 |
| C9-3 canonical_ip | **Verified** | `allowlist/tools/ipnorm.py` 单一实现；add/refresh/query 全部 import；8 个 IPv6/zone 用例通过 |
| 回归（C1/C2/C3/C4/C7） | **Verified** | Rust 零改动；C7 门禁实跑 PASS；4 个 cases 文件无双重空 |

## 逐项证据

### C8-1 覆盖门禁 —— **Verified**

- 实跑（只读）：`python xbits/test/qa_rule_coverage.py` → exit 0，逐目录行 `dns/recon/web/backdoor rule_sids=named_by_cases / cases / pcaps`，随后
  `covered 74/17477 unique SIDs (0.4%) | excluded 11 dirs / 17403 SIDs`，再逐条打印 11 个排除目录的 `files/sids` 与原因；PASS 文案为 "74 of 17477 … excluded by policy … not silently ignored"（`qa_rule_coverage.py:168-187`）。
- 反隐藏：`on_disk - covered - excluded` 非空 → FAIL（`:98-106`）；`EXCLUDED_RULE_DIRS` 中登记但磁盘不存在 → FAIL（`:100,107-108`）；每类还检查 `uncovered/unknown sid`、`missing/extra pcap`（`:133-151`）。
- 口径对照：`COVERED_CATEGORIES` 4 项（`:26-51`）、`EXCLUDED_RULE_DIRS` 11 项（`:54-67`）与磁盘目录一一对应；CI 步骤名改为 "Rule coverage gate (asserted sids exercised; excluded dirs printed with reasons)"（`xbits-images.yml:130-131`），不再出现 "all sids"。

### C8-2 hook 矩阵 —— **Verified（含 R8-1）**

- 判定核心 `evaluate_case()`（`qa_suricata_hook_matrix.py:151-212`）：
  - 基础不变量：`require ⊆ engine`、`forbid ∩ engine = ∅`（`:176-179`）；
  - `exact`：`set(engine) & 场景SIDs == require`（`:187-192`）；
  - `subset`：场景内未声明命中与跨场景命中分别进 warnings（`:194-210`），PASS 文案带 warning 数量（`:458-460`）；
  - `known_extra` 必须带 `known_extra_reason`，否则失败（`:180-181`），且登记项消失也告警（`:208-210`）；
  - 丢告警（EVE≠engine）与 engine stderr 异常仍失败（self-test `:346-350`）。
- 实跑 `--self-test` → **PASS 10/10**（含"exact 多命中→失败""subset→warning""跨场景→warning""负例默认 exact""丢告警→失败"）。
- 默认 exact 的分配：负例（`require` 空）与 `web` 全量默认 exact，其余正例 subset（`:403-406`）——理由写在注释与文件头（forbid 未穷举）。
- CI 以默认 warning 模式运行（`xbits-images.yml:201-206` 未传 `--strict-warnings`）→ **R8-1**。

### C8-3 CI 弱断言替换 —— **Verified**

- 已替换（grep 全 workflow：断言处无 `sleep 1`+`grep -q 子串`+`kill … || true` 组合）：
  - `xbits-ci.yml:124-137`：`assert_hook_output.py --file … --timeout 30 --rule-id … --reason … --allow-zero-signature-id --require-fields rule_id,reason,src,dst,proto`，随后断言退出码 ∈ {0,143}、并 grep stderr 的 `bad hook event|hook accept error|hook read error|panicked` → 失败；
  - `xbits-ci.yml:227-232`：stdin 回声测试改 `assert_xbits.py --source alert-json --expect-count 1 --require-fields signature_id,signature,src,dst,proto,community_id`（第 2 行 flow 不得产生输出 → 计数 1 即证）；
  - `xbits-ci.yml:465-478`：live 链路 `assert_hook_output.py` + 退出码/stderr 检查；
  - `xbits-images.yml:272-290`：suricata 与 zeek 两路 `assert_hook_output.py`（分别断言 `signature_id=9103001` 与 `--allow-zero-signature-id`）+ 退出码/stderr。
- 新脚本 `assert_hook_output.py`：轮询到匹配条数或超时（`:82-99`）；每条匹配行校验必填字段非空（`:114-118`）、`signature_id` 必须 int（`:119-121`）、默认拒绝 0（`:122-123`）；文件缺失/无匹配 → exit 1。
- 对抗实测（临时目录，非仓库）：zero sid 默认 **FAIL**；加 `--allow-zero-signature-id` **PASS**；`src=""` **FAIL**；无输出超时 **FAIL**。
- 保留的 `sleep 0.1` 仅在 socket 出现等待循环（有 50/100 次上限，超时明确报错 `xbits-ci.yml:113-119`）与 teardown/log 收集；`kill||true` 只在清理阶段，不再承担断言。

### C8-4 双空用例 —— **Verified（含 R8-2）**

- `测试用例/assert_suricata.py:56-62`：`require` 与 `forbid` 都为空 → 直接 FAIL 并点名（文案说明"恒真"）；`note` 会被打印（`:55,86`）。
- 对抗实测：合成双空用例 → `c1 FAIL reason=empty require/forbid`，exit 1；合成 `require=[9103001]` + 正确 eve → exit 0。
- 用例数据：4 个 cases 文件共 23+29+34+18=104 个用例，`double-empty=[]`（脚本核对）；`backdoor_cases.json` 的 `c2_periodic` 已带 `forbid=[9104001..4]` 与 note（UTF-8 JSON 校验通过）。
- 负例对照：`qa_xbits_context.py` 的 missing/benign 负例已改为"必须有对照告警 xb-zeek-appid-scanner 恰好 1 条 + 不得出现 real rule"，并用轮询替代 `sleep(0.25)`（diff 见 `:110-183`）。

### C8-5 pefile/ELF/YARA 值断言 —— **Verified**

- `triage/tests/test_triage.py`：`minimal_pe()`（`:43-77`）构造合法 PE（含 `.text` 节、Subsystem=3、Machine=I386），`test_pe_enhanced_path_asserts_parsed_fields`（`:178-194`）断言 **值**：`machine=="IMAGE_FILE_MACHINE_I386"`、`subsystem==3`、`sections==[".text"]`、`import_count==0`、`signed/signed_present/signature_verified` 全 False；`minimal_elf()`（`:78-90`）+ `:217-230` 断言 `machine=="x64"`、`type=="ET_EXEC"`、`entry==hex(0x400000)`、`statically_linked`。
- 缺依赖防空绿：`EXPECT_ENHANCED` 为 1 时先断言依赖存在（`:28-40`）；未装时测试先断言 `engines[tool] is False` 再 skip（`:182-184`、`:221-223`）。CI 双跑 `XBITS_EXPECT_ENHANCED=0` 与 `=1`，增强步骤安装 pefile/pyelftools/yara-python（`xbits-ci.yml:295-302`）。
- YARA：`validate_rules.py:67-101` 正例必须命中 `webshell_php_eval_superglobal`、负例不得命中任何规则；`total==0` 也失败（`:64-65`）；缺 yara → exit 2（`:27-38`），仅显式 `--allow-missing-yara` 才跳过。
- 实跑（本机已装 yara）：`validated 6 rule files, 0 bad`；`positive hits: [webshell_common_markers, webshell_php_eval_superglobal]`；`negative hits: []`；exit 0。

### C9-1 engines 三态 —— **Verified（含 R8-3/R8-4）**

- 单一写入口 `_set_engine(engines, status, name, present, ok, error)`（`triage/triage.py:145-149`）：写 `engine_status[name]={present,ok,error}`，`engines[name]=present and ok`。
- 全工具覆盖（grep `_set_engine(` 共 10 个工具）：pefile（`:265-279`）、pyelftools（`:367-396`）、yara（`:458-505`）、oletools（`:515-548`）、ssdeep/tlsh（`:561-577`）、capa（`:661-692`）、clamav（`:699-734`）、semgrep（`:741-776`）、binwalk（`:783-802`）；not-applicable 的 capa/binwalk 也写 `present=False` + 原因（`:869-878`）。
- 失败与"未检出"不再同形：
  - clamav：`FOUND`→ok=True；`rc==0`→ok=True（未检出）；`rc!=0`→ok=False + error（`:709-727`）；超时/异常→ok=False。
  - capa/binwalk：rc!=0 直接 ok=False（`:670-674`、`:791-794`）；超时/异常 ok=False。
  - semgrep：`rc!=0 且无输出`→ok=False；有 JSON→ok=True；超时/异常 ok=False（`:750-777`）。
  - yara：规则目录缺失/读失败/无规则可编译/匹配异常→ok=False（`:460-503`）。
  - oletools：解析失败→ok=False + `oletools_error` + `office.analysis_failed` 低危 finding（`:520-530`）；扫描异常→ok=False（`:545-548`）。
- 顶层汇总：`engine_errors = {present and not ok}`，`degraded=bool(...)`（`:979-981`），输出 `degraded`/`engine_errors`/`engine_status` 并追加 `degraded=true` evidence（`:991-1010`）。
- 单测实跑：`test_engine_status_schema_and_backcompat_summary`、`test_clamav_failure_is_degraded_not_clean`、`test_external_engine_true_only_after_real_success` 等 **26 tests OK (skipped=1)**。

### C9-2 signed 语义 —— **Verified**

- 字段：`info["pe"]["signed_present"]` 仅证书表非空；`signature_verified` 恒 False；旧 `signed` = `signed_present`（`:332-341`）。
- 降级闸门：`if signature_verified and not has_strong:`（`:957-964`）——当前不可达，证书表存在**绝不**触发 clean/分数封顶；高危证据（`pe.inject_*` 等）不再被伪造 blob 洗白。
- 测试 `test_signed_present_never_dampens_high_evidence`（`test_triage.py:290-305`）断言 `signature_verified is False` 且 verdict 不为 clean。
- 文档：`triage/README.md:82-85` 已改写为两字段语义并说明旧 `signed` 仅兼容。

### C9-3 canonical_ip —— **Verified**

- 单一实现 `allowlist/tools/ipnorm.py:21-27`：空/含 `%`（含 `%25`）→ None；否则 `str(ipaddress.ip_address(v)).lower()`（IPv6 压缩式小写、IPv4 原样）。
- 三处共用：`add.py:20,61-62`、`refresh.py:27,51-52`、`query.py:23,51-61,80-81`（加载与查询双侧同一归一）；旧 `str(ipaddress…)`/`exploded.lower()` 已删除。
- 单测实跑 `allowlist/tests/test_allowlist.py` → **8 tests OK**（IPv6 小写/v4-mapped、zone 拒绝、add→data→query 三层一致、refresh 拒绝 zone 行）。
- 文档：`allowlist/README.md:45-46`。

### 回归（C1/C2/C3/C4/C7） —— **Verified**

- **Rust 零改动**：`git diff --stat -- xbits/src` 为空 → C1（intel/min_confidence）、C2（pending/score）、C3（健康计数）、C4（file triage 三态）的实现与单测未被 C8/C9 触碰（这些模块在第五~七轮已逐项 Verified）。
- **C7**：实跑 `xbits/test/qa_workflow_paths.py` → `CI PATHS: PASS`，exit 0；workflow 的 `paths` 与新增测试文件（`xbits/test/assert_hook_output.py`、`triage/tests/*`、`allowlist/**`）仍在覆盖内。
- 未被放宽的抽查：`qa_xbits_context.py` 负例从 `len==0` 改为"only control + no real rule"，属**加强**；`assert_suricata.py` 从"双空恒真"改为 FAIL；`test_triage.py` 从"键存在"改为"值断言"——均为收紧而非放宽。

## 本轮新发现（残留，均不阻塞 C8/C9 主结论）

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R8-1 | **medium/low** | `xbits-images.yml:201-206`、`qa_suricata_hook_matrix.py:448-450` | hook 矩阵 CI 仍用默认 warning 模式：subset 口径下"场景内未声明命中/跨场景命中"只告警不失败，`--strict-warnings` 未启用（代码里已写 TODO） | 收集一轮基线后把 CI 切到 `--strict-warnings`，或把当前 warnings 清单固化为 known_extra+reason |
| R8-2 | **medium/low** | `测试用例/assert_suricata.py:52-88` | `forbid`-only 负例（如 c2_periodic 与 3 个 c2_negative_*）在"规则完全没加载"时也会通过（eve.json 存在但零告警）；目前靠 `suricata -T` 加载校验步骤间接兜底，用例本身无"必中对照" | 给负例加一条场景内必中控制 SID（或全局断言 suricata.log 的 loaded rules 数），与 `qa_xbits_context` 的 control 模式一致 |
| R8-3 | medium/low | `triage/triage.py:473-507` | yara **部分**规则文件编译失败（`failed_count>0` 但仍有 compiled）时 `_set_engine(..., ok=True)`，`degraded` 不置位；只在 `info.yara_rules_failed/failed` 计数——检测覆盖面已缩小但顶层仍称证据完整 | `failed_count>0` 时置 `ok=False`（或至少 `degraded=true`），让消费方知道规则集不完整；新增单测 |
| R8-4 | low | `triage/triage.py:755-768` | semgrep JSON 里的 `errors[]` 只写入 `info.semgrep.errors`，`ok=True`；若 semgrep 以 rc≠0 返回带 errors 的 JSON，会被当成"真实执行成功" | `errors` 非空时按失败计（ok=False/degraded），或明确区分 warning 级 errors 并计数 |
| R8-5 | low | `triage/triage.py:145-149`、`triage/README.md:75-80` | `engines[tool]` 语义由"已安装"变为"present and ok"；Rust 侧不读该字段（`xbits.triage` 原样透传，`analysis.rs:1958`），但外部脚本若按旧语义读会误判"组件缺失" | 保留三态为主，外部消费统一读 `engine_status`；README 已说明，建议再加一行迁移提示 |
| R8-6 | low | `xbits/test/assert_hook_output.py:48-51` | 坏 JSON 行被静默跳过，只有在匹配数不足时才失败；若告警行被截断，报错是"0 matched"而非"行损坏" | 统计 `json_errors` 并在 >0 时打印/失败（或至少 `::warning::`） |

**第八轮结论**：C8 **已实质修好**（覆盖门禁不再自称全覆盖、hook 矩阵有了纯函数判定与自测、CI 弱断言换成轮询+字段校验、双空用例被拒绝、PE/ELF/YARA 从"存在/可编译"升级为"值/命中"）；C9 **已实质修好**（三态覆盖全部扫描器、失败与未检出不再同形、签名降级只认不可达的 `signature_verified`、IPv6 归一单一实现且三工具共用、单测全过）。剩余 6 项中 **R8-1/R8-2/R8-3** 建议下一轮处理（分别是"warning 未 gate""负例无对照""yara 局部失败不降级"），R8-4~R8-6 择机。

**第八轮复核边界**：未运行 `cargo test`/CI、未跑 docker/pcap e2e；已实跑 Python 单测与只读门禁（结果见上）；对抗用例只写系统临时目录、不触仓库。CI 实际通过与否仍以 GitHub Actions 为准。

---

# 第九轮：R8-1~3 复核（t28 / t29）

> 只复核 R8-1（strict 门禁）、R8-2（forbid-only 必中对照）、R8-3（YARA 部分编译失败）与回归。只读：未改源码、未推送、未跑 CI、未运行 cargo；跑了 Python 门禁/单测与临时目录对抗用例。工作树另有 `CLAUDE.md` 删除等无关改动，不在本单范围。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| R8-1 strict 门禁 | **Verified** | CI 矩阵步骤实传 `--strict-warnings`（未拆分降级）；9 处基线 warning：8 处补进 `require`、1 处 `known_extra`+reason；self-test 12/12；stale 登记项 strict 下失败 |
| R8-2 forbid-only 必中对照 | **Verified** | 每个 forbid SID 必须出现在同文件其它非 pending 用例的 require 中，否则 FAIL 点名；pending 需 note 且可见 SKIP；pending 的 require 不进对照池；self-test 7/7；4 份 cases `--cases-only` 全 PASS |
| R8-3 YARA 部分编译失败 | **Verified（含 R9-1 缺陷）** | 部分失败 → `ok=False` + `error=compile-failed: <文件>` + `failed_files` + `degraded=True`，合法规则照常命中；match-errors 计数；28 例单测过。但 stat 失败分支引用未初始化变量会崩（R9-1） |
| 回归（C8/C9/C7） | **Verified** | 覆盖门禁 74/17477 PASS、triage 28 例、validate_rules PASS、allowlist 8 例、C7 paths PASS；本轮无"删断言/降 strict"式放宽 |
| 本轮新发现 | **R9-1 medium/low、R9-2~R9-5 low** | stat 失败分支 UnboundLocalError；in-scope known_extra 成为可用的"免断言"通道；8 处 require 扩写缺逐条语义依据；对照门禁是静态的；strict PASS 文案小瑕 |

## 逐项证据

### R8-1 hook 矩阵 strict 门禁 —— **Verified**

- CI 实传 strict：`xbits-images.yml:205-214` 步骤名 "…strict warnings"，命令显式 `--strict-warnings`，没有拆成 warning/失败两步，也没有 `|| true`。
- 门禁语义：`qa_suricata_hook_matrix.py:469-476`——只要有 warnings 即 `SURICATA HOOK MATRIX: FAIL`；warning 来源见 `:194-220`（场景内未声明命中、跨场景命中、known_extra 未再出现），三者都不再"只拼进 OK 文案"。
- 9 处基线 warning 的处置（JSON 逐条核对，无 `pending`、无 `match` 覆盖、无删除用例）：
  - dns `cname_tunnel` require 含 `[9109002,9109201,9109202,9109203]`；`highfreq_long_positive` require 含 `[9109007,9109201]`；
  - recon `recon_curl_rate` require 含 `[9101028,9101109]`；
  - backdoor `c2_header_anomaly` `[9110002,9110004,9110006]`、`c2_response` `[9110002,9110004,9110006,9110007]`、`c2_sample` `[9110001,9110002,9110003,9110006]`、`c2_singleletter` `[9110004,9110006]`、`c2_variant` `[9110002,9110006]`；
  - web `web_deser_fastjson`：`known_extra=[9104002]` + 详细 `known_extra_reason`（跨场景真实重叠；9104002 由 backdoor `ws_cmd_post/ws_cmd_query/ws_cookie/ws_z0_base64` 的 require 断言）。全仓 cases 中 `known_extra` **仅此一处**（脚本扫描确认）。
- 机制本身未被放宽：`in_scope - require - forbid - known_extra`（`:197-201`）仍把未声明命中变 warning；`known_extra` 必须带 reason 否则 failure（`:180-181`）；stale 登记项仍 warning（`:218-220`）。
- self-test 实跑 **12/12 PASS**，新增两项正好覆盖"场景内命中用 known_extra 登记"与"known_extra 未再出现 → warning（strict 下失败）"（`:370-379`）。

### R8-2 forbid-only 必中对照 —— **Verified**

- 纯函数 `analyze_cases()`（`测试用例/assert_suricata.py:51-88`）：
  - 对照池 = **非 pending** 用例的 require 并集（`:67`）；pending 用例的 require 不进池（防自我证明）；
  - 非 pending 且 `require` 为空的 forbid-only 用例：`forbid - control_pool` 非空 → FAIL 并点名 case+SID（`:82-87`）；
  - 双空仍 FAIL（`:74-79`，C8 的收紧未被回退）；
  - `pending=true` 必须带 note，否则 FAIL（`:61-66`）；跳过时打印 `SKIP (pending) note=…`（`:65`、`:183-184`）——可见而非静默。
- `--cases-only` 模式（`:150,168-173`）：只做用例自洽性检查，不读 eve；CI 新增独立步骤对 4 份 cases 全部执行（`xbits-images.yml:216-222`）。
- 实跑：
  - `--self-test` → **7/7 PASS**（有对照通过 / 无对照 FAIL / 整文件只有负例 FAIL / 双空 FAIL / pending+note 可见跳过 / pending 缺 note FAIL / pending 的 require 不进池）；
  - 4 份 cases `--cases-only` 全 PASS：23/29/34/18 例，**pending 均为 0**，对照池 13/41/9/11 个 SID。
- 说明：该门禁是**静态自洽**检查；运行时"规则确实加载"由正例 require 实际通过 + `suricata -T` 加载步骤共同保证（见 R9-4）。

### R8-3 YARA 部分编译失败 —— **Verified（功能）/ R9-1 缺陷**

- 三类失败可区分：`_compiled_yara_rules()` 返回 `(compiled, failed_files, unreadable_errors)`（`triage/triage.py:414-465`）；walk 失败 → unreadable（`:438-440`）；编译失败（含 source 回退）→ failed_files（`:449-463`）。
- 结论在匹配循环**之后**判定（`:503-542`）：部分失败时已编译规则照常 match（可用部分生效），随后
  `problems` 组合 `compile-failed: <文件名,…>` / `unreadable: <原因> (+N more)` / `match-errors: <n>`，
  任一非空 → `_set_engine(present=True, ok=False, error=..., failed_files=..., unreadable_errors=...)`（`:528-540`）；`engines["yara"] = present and ok = False`（`:145-156`）；顶层 `degraded` 由 `engine_errors`（present and not ok）推导为 True（`analyze()` 原逻辑）。
- info 侧保留/新增：`yara_rules_failed`、`yara_unreadable_errors`、`yara_match_errors`、`yara_rules{loaded,failed}`（`:491-494,523-524,534-536`）。
- 单测实跑 **28 例 OK (skipped=1)**；新增 `test_yara_partial_compile_failure_is_degraded_and_valid_rules_still_hit`（`test_triage.py:369-414`）断言：合法规则仍命中、`ok is False`、`degraded is True`、`engine_errors` 含 yara、error 含 `broken_rules.yar`、`failed_files==["broken_rules.yar"]`、loaded=1/failed=1、engines 摘要 False；`test_yara_unreadable_rules_dir_is_reported`（`:416-424`）断言 rules-dir 缺失 → ok=False + degraded。
- README：`triage/README.md:84-91` 写明 error 组合与 `failed_files/unreadable_errors` 字段及两条测试。
- **缺陷 R9-1**（见下表）：stat 失败分支在变量初始化之前引用 `failed`/`unreadable_errors`，实际会抛 `UnboundLocalError`，与"stat 失败 → unreadable_errors"的声明不符（已用 monkeypatch `os.stat` 复现）。

### 回归（C8/C9/C7） —— **Verified**

- 实跑：`qa_rule_coverage.py` → PASS（74/17477）；`test_triage.py` → 28 OK；`validate_rules.py` → PASS（6 文件 0 bad，正例 2/负例 0）；`test_allowlist.py` → 8 OK；`qa_workflow_paths.py` → PASS。
- 无"删断言式放宽"：`git diff -- triage/tests/test_triage.py` **无删除行**（纯新增）；`assert_suricata.py` 的删除行都是把逻辑搬进 `analyze_cases()`（双空检查仍在 `:74-79`）；`qa_suricata_hook_matrix.py` 的删除行是把 in-scope 警告计算升级为 known_extra 抵扣 + 拆分 note，检查项未减少（self-test 从 10 增到 12）。
- C8/C9 的收紧项仍在：双空 FAIL、zero-sid 默认拒绝、`engine_status` 三态、`signature_verified` 闸门、canonical_ip 单实现（本轮未触碰这些文件/行）。

## 本轮新发现

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R9-1 | **medium/low** | `triage/triage.py:429-436`（变量定义在 `:447-448`） | walk 循环里单个 `.yar` `os.stat` 失败时执行 `failed.append(...)` / `unreadable_errors.append(...)`，但这两个列表此时尚未定义 → `UnboundLocalError`（已复现）。声明中的"stat 失败 → unreadable_errors"实际不成立，且异常会穿透 `_yara_scan`/`analyze`（triage 直接崩，而非降级） | 把 `compiled/failed/unreadable_errors` 初始化提到 walk 之前；stat 失败只记 `unreadable_errors`（不要混入 `failed_files`）；补一条 monkeypatch `os.stat` 的单测 |
| R9-2 | low | `xbits/test/qa_suricata_hook_matrix.py:197-201` | `known_extra` 现在可抵扣**场景内**未声明命中，只要求一个自由文本 reason；虽然当前只有 1 处跨场景用法，但机制上给"漏断言"留了免检通道 | 对 in-scope 的 known_extra 要求同时进 `forbid`（或额外要求 `known_extra_scope: cross-scenario` 才允许抵扣），并打印 `::notice::` 区分 |
| R9-3 | low/info | `测试用例/{cases,recon_cases,backdoor_cases}.json` 8 处新增 require | 这些 require 是把 CI 基线（run 44702632926）观测到的命中固化为断言，仓库内没有逐条"为何该 SID 应命中"的语义说明（仅 c2 系列有部分 note）；若其中某条本是规则误报，测试会把误报锁死 | 给新增 require 的用例补 `note`（命中原因），或引用规则文件行号；后续规则调整时同步复核 |
| R9-4 | low | `测试用例/assert_suricata.py:67,82-87` | 对照门禁是**静态**的：只证明"该 SID 在别处被 require"，运行时是否真的加载/命中仍靠那些正例与 `suricata -T` 步骤；单看负例本身仍无法区分"规则没加载" | 可再加一条全局断言（如解析 suricata.log 的 loaded rules 数 / 至少一个 control SID 实际出现），把运行时证据补上 |
| R9-5 | low | `xbits/test/qa_suricata_hook_matrix.py:478-482` | strict 模式下 PASS 文案仍打印 "0 warnings not asserted as failures — run with --strict-warnings to gate"，易误读为"未启用 strict" | strict 时改文案为 "0 warnings (strict gate enabled)" |

**第九轮结论**：R8-1/R8-2 **已真实关闭**（strict 真启用且 9 处基线命中全部落进断言或带 reason 的 known_extra，未通过拆分/降级/删除换取绿灯；forbid-only 负例有了同 SID 的必中对照，pending 显式可见）；R8-3 的**主语义已修好**（部分编译失败 ok=False + degraded + 坏文件名可见，合法规则仍生效，match-errors 计数）。但 R8-3 的 stat 失败分支存在 **R9-1 崩溃缺陷**，属"声明了三类失败但其中一类会抛异常"，建议随下一轮修掉；R9-2~R9-5 为低项。

**第九轮复核边界**：未运行 `cargo test`/CI、未跑 docker/pcap（因此无法本地复跑 strict 矩阵；其语义由 self-test 12/12 + 代码路径 + cases JSON 核对）。已实跑 coverage/triage/validate/allowlist/C7 门禁与 assert_suricata、hook matrix 自测；R9-1 用 monkeypatch `os.stat` 复现，未修改仓库。

---

# 第十轮：R9-1 复核（t31）

> 最小复核：只验 R9-1（YARA stat 失败分支）与 R8-3 其余断言未被改动。只读：未改源码、未推送、未跑 CI；跑了 triage 单测与独立 monkeypatch 复现。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| ① 初始化前置 + stat 失败只记 unreadable | **Verified** | `failed`/`unreadable_errors` 已提到 walk 之前（`triage.py:424-425`）；stat 失败只 `unreadable_errors.append("stat-failed: …")`（`:437`），不再写 `failed`；walk 失败返回 `([], [], [walk-failed…])`（`:442`） |
| ② monkeypatch 单测真实复现 | **Verified** | 新增 2 例（`test_triage.py:427-512`）：不崩溃 + unreadable 含文件名 + `failed_files==[]` + `ok=False` + `degraded=True` + 合法规则仍命中；直测返回契约 `(compiled, failed, unreadable)`。实跑 30 例 OK |
| ③ R8-3 其余断言未改动 | **Verified** | `git diff` 测试文件 **0 删除行**（+145 纯新增）；partial-compile 用例仍在（`:370-414`，断言 `failed_files==["broken_rules.yar"]`/`ok=False`/`degraded`）；triage.py 只改目标分支 |
| 独立复现 | **Verified** | 自写 monkeypatch 脚本（不依赖其单测）：直测无异常返回 `([], ['stat-failed: …cursed.yar…'])`；`analyze()` → `yara.ok=False`、`error=unreadable: stat-failed…`、`degraded=True`、`engine_errors=['yara']`、`loaded=1` 且 `yara.demo_ok` 命中 |
| 新发现 | **R10-1 low** | mtime 缓存键不含"不可读"状态：坏文件被删除后，缓存仍返回旧的 `stat-failed`，`ok=False/degraded` 会滞留到其它规则文件变化或进程重启 |

## 逐项证据

### ① 代码修复 —— **Verified**

- 初始化前置：`triage/triage.py:424-425` `failed: list[str] = []` / `unreadable_errors: list[str] = []` 位于 walk 循环（`:426-440`）之前——原先在 `:447-448`，而 stat 失败分支在 `:434-435` 先引用（第九轮已复现的 `UnboundLocalError`）。
- 语义收窄：stat 失败只 `unreadable_errors.append(f"stat-failed: {fp}: {exc}")`（`:437`），**不再** `failed.append`；`failed` 仅在编译失败时追加（`:462-463`），与 docstring 的"编译失败文件名"一致（`:417-422`）。
- 目录不可读：walk 抛 OSError → `return [], [], [f"walk-failed: {rules_dir}: {exc}"]`（`:442`），不再吞成 `([], 0, [])`。
- 缓存契约同步：`_YARA_CACHE[key] = (sig, compiled, failed, unreadable_errors)`，返回 `(compiled, failed, unreadable_errors)`（`:464-465`），缓存命中路径 `cached[1..3]` 与之一致（`:443-445`）。

### ② 单测 —— **Verified**

- `test_yara_stat_failure_is_reported_without_crash`（`test_triage.py:427-482`）：`mock.patch("triage.triage.os.stat")` 只对 `cursed.yar` 抛 `OSError(13)`；断言不崩溃（核心）、`unreadable_errors[0]` 含 `cursed.yar` 与 `stat-failed`、`failed_files==[]`、`info.yara_rules_failed==[]`、`info.yara_rules.failed==0`、`ok is False`、`degraded is True`、`engine_errors` 含 yara、error 含 `unreadable`、`loaded==1`、`yara.probe_stat_good_rule` 命中。
- `test_yara_stat_failure_isolated_via_direct_call`（`:484-512`）：直测 `_compiled_yara_rules` → `([], [], ['stat-failed: …only_good.yar…'])`，无异常，锁定返回契约。
- 实跑：`python triage/tests/test_triage.py` → **Ran 30 tests — OK (skipped=1)**（28 原有 + 2 新增）；`validate_rules.py` → PASS（6 文件 0 bad，正例 2/负例 0）。
- 独立复现（本次自写，非复用其单测）：直测无异常、返回 `([], ['stat-failed: …cursed.yar…'])`；`analyze()` 结果 `{"present":true,"ok":false,"error":"unreadable: stat-failed: …cursed.yar…"}`、`degraded=True`、`engine_errors=['yara']`、`loaded=1`、命中 `yara.demo_ok` —— 与单测断言一致。

### ③ R8-3 其余断言未改动 —— **Verified**

- `git diff --stat -- triage/tests/test_triage.py`：145 插入 / **0 删除**；新增两例插在 partial-compile 用例之后，未改动既有断言。
- partial-compile 用例仍在：`test_yara_partial_compile_failure_is_degraded_and_valid_rules_still_hit`（`:370-414`），仍断言 `failed_files==["broken_rules.yar"]`、`ok is False`、`degraded is True`、合法规则命中、`loaded=1/failed=1`。
- `triage.py` 的 diff 仅限 `_set_engine` 的 R8-3 字段（上一轮已验）与 `_compiled_yara_rules` 的本次修复；`_yara_scan` 的"先匹配后判定、problems 组合、ok=False"逻辑未变（`:503-542` 上一轮行号，内容未动）。

## 本轮新发现

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R10-1 | low | `triage/triage.py:441-465` | 缓存键只含"可枚举文件的 (path, mtime, size)"，不含 `failed/unreadable` 状态。已复现：坏文件 stat 失败 → 缓存写入含 `stat-failed` 的结果；随后**删除**该坏文件，剩余文件集合与缓存签名相同 → 命中缓存，仍返回 `stat-failed: <已删除文件>`，`ok=False/degraded` 滞留（直到其它规则文件 mtime/size 变化或进程重启）。同理，坏文件修复后若签名恰好不变（同尺寸同 mtime 边界）也可能短暂滞留 | `unreadable_errors`/`failed` 非空时不写缓存（或把失败文件名集合纳入 key）；至少加一条"删除坏文件后重跑应恢复 ok=True"的用例 |

**第十轮结论**：R9-1 **已真实关闭**（初始化前置、stat 失败只记 unreadable、walk 失败显式返回；单测与独立复现都证明不崩溃且 `ok=False/degraded/unreadable` 可见，合法规则仍生效），R8-3 其余断言未被改动。仅剩 R10-1（缓存对"不可读状态"不敏感，low）。

**第十轮复核边界**：未运行 `cargo test`/CI；结论为代码 diff + 单测 + 独立 monkeypatch 复现；CI 以增强步骤（XBITS_EXPECT_ENHANCED=1 + yara，30 例）为准。

---

# 第十一轮：R10-1 复核（t33）

> 最小复核：缓存失败状态是否滞留、正常路径是否仍命中缓存、单测是否真实覆盖、R9-1/R8-3 是否回退。只读：未改源码、未推送、未跑 CI；跑了 triage 单测与独立复现。

## 汇总

| 项 | 结论 | 一句话 |
|---|---|---|
| ① 失败状态不再滞留 | **Verified** | 缓存键改为"枚举到的每个 .yar"（stat 失败条目也入键，含 errno/类型）；坏文件删除或恢复后签名改变 → 重编译，`ok=True`/`degraded=False`（独立复现） |
| ② 正常路径仍用缓存 | **Verified** | 规则全好时键结构稳定；连续两次 `_compiled_yara_rules` 返回**同一 compiled 对象**（`assertIs` + 独立复现） |
| ③ 单测真实覆盖序列 | **Verified** | `test_yara_stat_failure_does_not_linger_in_cache`（`test_triage.py:515-591`）覆盖"失败→删除→恢复 ok=True/degraded=False→缓存复用"；`test_cache_key_covers_stat_failed_entries`（`:593-637`）断言失败条目进键且删除后签名变化；32 例 OK |
| ④ R9-1/R8-3 未回退 | **Verified** | stat 失败仍只记 unreadable（`triage.py:442-448`）；partial-compile/stat 两旧用例仍在且通过（`:370-414`、`:427-512`）；test 文件无删除行；`_yara_scan` 的 problems/ok=False 逻辑未动（`:537-553`） |
| 新发现 | 无阻塞；**R11-1 low（信息性）** | 缓存键仍不含 `include` 外部依赖文件；若被 include 的文件在规则目录之外且内容变化（mtime/size 不变），缓存不会失效（既有设计，非本轮引入） |

## 逐项证据

### ① 缓存键覆盖失败状态 —— **Verified**

- `_compiled_yara_rules()`（`triage/triage.py:414-476`）：
  - `candidates` 记录**枚举到的每个 .yar**（`:432`）：stat 成功 → `(rel, mtime, size, "ok")`（`:437-441`）；stat 失败 → `(rel, None, None, "stat-failed:<errno>:<ExcName>")`（`:442-448`），同时只记 `unreadable_errors`（R9-1 语义保持）；
  - `candidates.sort(key=lambda c: c[0])` 后 `sig = tuple(candidates)`（`:450,455`），缓存键 = `abspath(rules_dir)` + 该签名（`:454-457`）；
  - walk 失败仍直接返回且**不写缓存**（`:451-453`）。
- 于是：坏文件被删除 → 该条目从 candidates 消失 → 签名变化 → 缓存不命中 → 重新编译，`unreadable` 清空、`ok=True`；坏文件恢复可读 → 条目从 `stat-failed` 变 `"ok"` → 同样失效旧缓存。
- 独立复现（自写脚本，非复用其单测）：
  1) mock stat 失败：`yara.ok=false`、`error="unreadable: stat-failed: …vanishing.yar…"`、`degraded=true`、`loaded=1`；
  2) 删除坏文件后再分析：`ok=true`、`error=null`、`unreadable=null`、`degraded=false`、`engine_errors={}`、`loaded=1`，且合法规则 `yara.probe_good` 命中；
  3) 坏文件恢复可读（不删除）：`ok=false→true`、`degraded=false`、`loaded=2`。

### ② 正常路径缓存命中 —— **Verified**

- 规则全好时 candidates 恒为 `(rel, mtime, size, "ok")` 序列；文件未变 → 签名不变 → 命中 `_YARA_CACHE` 并返回同一 `compiled` 列表（`:457-458`）。
- 单测：`test_triage.py:578-585` 连续两次直调 `_compiled_yara_rules`，`assertIs(compiled_a, compiled_b)` 且 `(failed, unread)==([],[])`。
- 独立复现：`c1[0] is c2[0]` → `True`（同一编译对象），`len=1`。
- 代价评估：键多了一个 `"ok"` 标记与 relpath 计算，O(规则文件数) 的元组构造，与旧实现同阶；编译缓存命中行为不变。

### ③ 单测真实覆盖 —— **Verified**

- `test_yara_stat_failure_does_not_linger_in_cache`（`:515-591`）：第一次 mock 失败断言 `ok=False/degraded=True/unreadable 含 vanishing.yar`（`:552-557`）；`os.remove(cursed)` 后第二次分析断言 `ok=True`、`error is None`、`degraded=False`、`engine_errors=={}`、`unreadable_errors is None`、`failed==0`、`loaded==1`、合法规则命中（`:560-576`）；随后断言缓存对象复用（`:578-585`）；finally 恢复 `_YARA_CACHE` 原状（`:586-591`）。
- `test_cache_key_covers_stat_failed_entries`（`:593-637`）：失败态签名含 `stat-failed`（`:623-625`），删除坏文件后签名不同（`:626-632`），直接锁住"机制"而不只是"现象"。
- 实跑：`python triage/tests/test_triage.py` → **Ran 32 tests — OK (skipped=1)**；`validate_rules.py` → PASS（6 文件 0 bad，正例 2/负例 0）。

### ④ R9-1 / R8-3 未回退 —— **Verified**

- R9-1：stat 失败分支仍只 `unreadable_errors.append("stat-failed: …")`（`:442-448`），不写 `failed`；初始化仍在 walk 之前（`:428-429`）。
- R8-3：`_yara_scan` 的 `problems` 组合与 `ok=False` 判定未改（`:537-553`）；`failed_files`/`unreadable_errors` 仍写入 `engine_status`（`:548-551`）。
- 用例仍在：`test_yara_partial_compile_failure_is_degraded_and_valid_rules_still_hit`（`:370-414`）、`test_yara_stat_failure_is_reported_without_crash`（`:427-482`）、`test_yara_stat_failure_isolated_via_direct_call`（`:484-512`）。
- `git diff -- triage/tests/test_triage.py`：**无删除行**（纯新增）；32 例全过。

## 本轮新发现

| # | 严重度 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| R11-1 | low（信息性） | `triage/triage.py:414-476` | 缓存键只覆盖规则目录内枚举到的 `.yar`；若某规则 `include` 了目录外的文件，被 include 文件变化而自身 mtime/size 不变时，缓存不会失效（既有设计，非 R10-1 引入） | 如需彻底，可在规则文件里禁止跨目录 include，或把 include 依赖也纳入签名；当前 triage/rules 未使用跨目录 include，风险低 |

**第十一轮结论**：R10-1 **已真实关闭**——失败状态（stat-failed）进入缓存键，坏文件删除/恢复后旧结果不再滞留（`ok=True`/`degraded=False` 可复现），同时正常路径仍命中同一编译对象（无性能回退）；新增两例分别锁定"行为序列"与"缓存键机制"，R9-1/R8-3 未回退。无阻塞项，仅 R11-1 一条信息性提示。

**第十一轮复核边界**：未运行 `cargo test`/CI；结论为代码 diff + 32 例单测 + 独立脚本复现；CI 以增强步骤（XBITS_EXPECT_ENHANCED=1 + yara）为准。
