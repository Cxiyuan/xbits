# xbits Rust 核心审计（审计员：rust-auditor / task t1）

审计对象：工作区分支 `xbits-event-bridge` 的未提交改动（`git status`/`git diff`）。
范围：`xbits/src/{engine.rs,hook.rs,analysis.rs,intel.rs,model.rs,main.rs,lib.rs}`、`xbits/README.md`、`docker/`、以及驱动这些改动的 `xbits/test/qa_file_triage.py`、`triage/README.md`、`allowlist/README.md`、`threat-intel/{README.md,tools/query.py,data/domain.txt}`。
方法约束：只读静态分析（read/grep/glob + git diff/status），未执行 cargo/docker/suricata，未联网，未修改任何源码；本轮只新增本文件。
行号均以当前工作区文件为准。

**结论先说**：本轮三块新能力——统一情报（intel/allowlist）、文件静态 triage 编排、docker file-store——都"接上了线但没有形成闭环"：
情报只做字段标注且不进 ES 文档、不参与评分/抑制；triage 的失败与超时在唯一审计通道上是静默的；docker 侧新增的 file-store 没有任何消费者。
另外工作区当前状态 **无法通过 `cargo test` 编译**（见 R1），"CI 绿"与现状不符。

严重度统计：blocker 2 / high 9 / medium 4，共 15 条。

| ID | 严重度 | 分类 | 一句话 |
|----|--------|------|--------|
| R1 | blocker | 测试掩盖 | 测试里 `EngineAlert` 缺 `intel/allowlist` 字段，测试模块编译不过 |
| R2 | blocker | 表面处理 | 情报命中只写字段，不参与评分/抑制/告警，且归一化文档直接丢弃 |
| R3 | high | 表面处理 | md5/sha1 情报永不查询；文件事件绕过引擎，hash 情报路径不可达 |
| R4 | high | 表面处理 | `is_empty()` 漏检 → 启动日志 `intel=empty` 误报；`intel=off` 分支不可达 |
| R5 | high | 兜底绕过 | 情报目录无默认值（帮助文本声称默认 `data/`），路径错/读失败一律静默空集合 |
| R6 | high | 未根治 | 威胁域名用后缀匹配，名单含公共后缀 `co.kr`，与 CLI 精确语义不符 |
| R7 | high | 未根治 | 挂起告警的超时判定只在"空闲 500ms"时触发，持续流量下永久挂起 |
| R8 | high | 兜底绕过 | 引擎 pending 超时直接丢弃无记录，`flush_pending` 是清空式死代码 |
| R9 | high | 兜底绕过 | 审计/ES 唯一通道静默丢文档；分析线程 panic 后全量静默停摆 |
| R10 | high | 表面处理 | triage 超时被报成 `bad-triage-json`；只杀 `sh` 不杀子进程；`stored` 从不校验 |
| R11 | high | 表面处理 | `min_confidence` 门槛不可达：先被 `.max(minimum)` 抬升，过滤条件永远为假 |
| R12 | medium | 未根治 | 30s 的 triage 同步跑在唯一分析线程上，阻塞全部告警与超时判定 |
| R13 | medium | 文档与实现不符 | docker 开启 file-store + files 事件但无人消费，镜像里也没有 triage/python3/情报 |
| R14 | medium | 测试掩盖 | "suricata fileinfo → xbits → triage" 的 QA 全程自造 spool 与事件，未过 Suricata |
| R15 | medium | 兜底绕过 | `match_buffers`/`sid_library` JSON 解析失败被 `unwrap_or_default()` 静默变空表 |

---

## R1 · 测试模块编译失败，却声称已跑过单元测试

- **严重度/分类**：blocker / 测试掩盖
- **证据**
  - `xbits/src/engine.rs:39-44` 给 `EngineAlert` 新增两个字段：
    ```rust
    pub intel: Option<serde_json::Value>,
    pub allowlist: Option<serde_json::Value>,
    ```
  - `xbits/src/analysis.rs:1177-1201` 的测试构造器仍是旧字段集，`context: None,` 之后直接 `}`，没有 `intel`/`allowlist`：
    ```rust
    fn alert() -> EngineAlert {
        EngineAlert {
            ...
            uid: Some("C1".into()),
            context: None,      // ← 到此结束，缺 2 个字段
        }
    }
    ```
  - CI 声称执行 `cargo test --manifest-path xbits/Cargo.toml --locked`（`.github/workflows/xbits-ci.yml:98-105`），并作为 `qa_xbits_match_context` 等作业的前置 `needs: rust`（同文件 `:196`）。
- **为什么是绕过而非根治**：这是 Rust 的硬编译错误（E0063 missing fields），不是运行时瑕疵。说明本轮改动**没有跑过 `cargo test`**；所有下游"绿色"作业（match_context、file triage、images）都建立在"rust 作业会先通过"这一前提上，因此当前任何"测试通过"的表述都是不可信的。
- **正面修复方向**：补齐字段（或改用 `..Default::default()` / 构造函数收口），并让 `EngineAlert` 的构造集中在 `make_alert` 一处，测试只经由该入口构造；CI 上把 `cargo test` 作为不可跳过的 fail-fast 门禁，PR 未通过不允许任何依赖作业启动。

## R2 · 情报"查了但没用"：不参与评分/抑制/告警，还被归一化文档丢弃

- **严重度/分类**：blocker / 表面处理
- **证据**
  - `xbits/src/engine.rs:95-110` 唯一出口就是赋字段：
    ```rust
    fn annotate(&self, alert: &mut EngineAlert, ev: &HookEvent) {
        if let Some(ref svc) = self.intel {
            let ann = svc.annotate_event(ev);
            alert.intel = ann.threat;
            ...
            alert.allowlist = Some(serde_json::Value::Object(obj));
        }
    }
    ```
  - 告警的分数/置信度在此之前已经定死，从不回读情报：`engine.rs:276-277`（`score: rule.score.max(1)`）、`engine.rs:238`（`Self::confidence(...)`）、`engine.rs:292-297`（`score_for` 只累加 `rule.score`）；`make_alert` 里没有任何 `self.intel` 引用。
  - 白名单命中不产生任何抑制/降级：`engine.rs:199-210`（`benign()` 只看规则的 `benign_uri_contains/benign_host_contains`）、`engine.rs:235-237`。
  - 归一化文档（写 `--analysis-file` 与 ES 的唯一形态）根本没有这两个字段：`analysis.rs:1009-1051` 的 `json!` 只到 `"zeek": alert.context.clone()`，全文件搜索 `intel` 为 0 命中。
  - 文档却按"参与决策"宣传：`xbits/src/intel.rs:4-5`（"黑方向，命中加重；白方向，命中降级/放行"）、`xbits/README.md:313-317`（"自动携带标注字段…异常加权提示"）、`allowlist/README.md:47-48`（"命中则降级/抑制（误报刹车）"、"异常加权因子"）。
- **为什么是绕过而非根治**：命中已知 C2 IP 的告警与未命中的告警在 score/confidence/是否输出/是否进 ES 上完全等价；连"仅供参考"的标注都进不了 ES 文档。整套情报链路对检测结果零影响，却给出"已统一查询再决策"的结论。
- **正面修复方向**：把情报查询前移到决策点：威胁命中 → 明确的分数/置信度增量 + 独立的 intel 告警事件；白名单命中 → 显式"抑制/降级"决策并记录 `reason=intel-allowlist`；`normalized_document` 必须携带 `intel`/`allowlist` 与决策依据。然后补一条端到端断言：命中情报与未命中情报的同一事件，产出必须不同。

## R3 · md5/sha1 情报加载后永不查询；文件事件绕过引擎使 hash 情报路径不可达

- **严重度/分类**：high / 表面处理
- **证据**
  - `intel.rs:92-97` 把 md5/sha1/sha256 三个集合合并进同一个 `hashes`；但查询端只取 sha256：
    ```rust
    // intel.rs:193-198
    if let Some(h) = ev.file_sha256.as_deref() {
        if self.threat_hash(h) { ... json!({"type": "sha256", ...}) }
    }
    ```
  - `hook.rs:133-135` 明明解析了 `file_sha1`/`file_md5` 并放入事件，却没有任何消费者。
  - 更关键：唯一会带 `file_sha256` 的事件（EVE `fileinfo` → `kind="file_stored"`，`hook.rs:129-144`）在 `hook.rs:264-270` 就被 `continue` 掉了，**永远到不了 `engine.process`**：
    ```rust
    if is_file_event(&ev.kind) {
        if let Some(pipeline) = pipeline { pipeline.submit_file(ev); }
        continue;   // ← 不进引擎，annotate 不会执行
    }
    ```
  - 数据侧：`threat-intel/data/md5.txt` 79KB、`sha1.txt` 83KB 被加载进内存，却没有任何可达的查询路径（`intel.rs:136-139` 的 `threat_hash` 只在上面那一处调用）。
- **为什么是绕过而非根治**：加载 md5/sha1 情报制造了"三种哈希都覆盖"的错觉；而真正带文件哈希的事件被改道到 triage，triage 文档又不做情报查询，于是"文件哈希情报"整条链路事实上为空。
- **正面修复方向**：把哈希查询收口成一个按算法分派的接口（md5/sha1/sha256 各查对应集合），在文件事件与告警事件两条路径上都调用；`fileinfo` 事件应先进引擎（标注/评分），再进 triage，而不是在 hook 层分叉丢弃。补一条断言：造 md5 命中事件必须产出 intel 标注。

## R4 · `is_empty()` 漏检导致启动自检 `intel=empty` 双向误报，`intel=off` 是死分支

- **严重度/分类**：high / 表面处理
- **证据**
  - `intel.rs:125-129`：
    ```rust
    pub fn is_empty(&self) -> bool {
        self.threat.ips.is_empty()
            && self.threat.hashes.is_empty()
            && self.allowlist.domains.is_empty()
    }
    ```
    漏掉了 `threat.domains`（`threat-intel/data/domain.txt`，50000 条 / 1.0MB，是最大的一份情报）、`allowlist.ips`、`allowlist.public_dns`。
  - `hook.rs:218-222` 以此决定运维可见的唯一状态行：
    ```rust
    Some(svc) if !svc.is_empty() => "intel=on",
    Some(_) => "intel=empty",
    None => "intel=off",
    ```
  - `main.rs:254-258` 永远传 `Some(intel)`，所以 `None => "intel=off"` 从 CLI 启动路径不可达；`hook.rs:178-185` 的 `run_hook_listener_with_analysis` 也只在测试里走。
- **为什么是绕过而非根治**：只加载了 5 万条恶意域名（domain 情报在工作），启动行却打印 `intel=empty`；反过来只加载 ip.txt 而 domain.txt 缺失时打印 `intel=on`——运维据此判断情报是否生效，方向正好相反。这是"状态自检替代真实校验"的典型：用一行布尔近似代替"每个数据集是否真的加载了多少条"。
- **正面修复方向**：让 `IntelService::load` 返回结构化统计（每类文件的条目数/失败原因），启动时逐项打印并纳入健康检查；`is_empty()` 要么删除，要么覆盖全部集合；`intel=off` 与"未配置/配置错/数据为空"三态区分，而不是一个布尔。

## R5 · 情报目录没有默认值（帮助文本却说有），路径错误或读取失败一律静默空集合

- **严重度/分类**：high / 兜底绕过
- **证据**
  - 帮助文本承诺默认路径：`main.rs:199-200`
    ```
    --threat-intel-dir DIR(默认 data/: ip/domain/md5/sha1/sha256.txt)
    --allowlist-dir DIR(默认 data/: domain/ip/public_dns.txt)
    ```
  - 实际默认值是 `None`，代码里没有任何默认路径解析：`main.rs:65-66`、`main.rs:254-258`（`threat_intel_dir.as_ref()` 直接透传 `None`）。
  - 加载端把"文件不存在/权限错/IO 错"全部吞成空集合，且不打印任何信息：`intel.rs:19-30`
    ```rust
    fn load_set(path: &Path) -> HashSet<String> {
        let mut out = HashSet::new();
        if let Ok(text) = std::fs::read_to_string(path) { ... }
        out   // 读失败 = 空集合，无日志、无计数、无返回错误
    }
    ```
  - `xbits/README.md:305-309` 只给显式目录示例；`threat-intel/README.md:26` 还写着 xbits"（规划中）…作关联置信度加权"。
- **为什么是绕过而非根治**：生产上少写一个 `--threat-intel-dir`，或路径写错（相对路径、容器内未挂载），引擎照常启动、照常告警，威胁情报静默为"永不命中"，唯一的痕迹是 R4 那行本身就会误报的 `intel=empty`。这是"软依赖"式的兜底，掩盖了配置错误。
- **正面修复方向**：实现真实的默认路径（或要求显式配置），目录不存在/不可读时启动即失败或至少 error 级日志 + 健康端点置为 degraded；`load_set` 返回 `(集合, 读取结果)` 并让调用方汇总统计；删除帮助文本里不存在的默认值。

## R6 · 威胁域名用"后缀匹配 + 线性扫描"，名单含公共后缀 `co.kr`，且与 CLI 声称的"精确语义"不符

- **严重度/分类**：high / 未根治（逻辑+数据）
- **证据**
  - `intel.rs:49-60` 的 `suffix_hit` 对每条候选做 `v == w || v.ends_with(".{w}")`，并从**排序结果的第一个**命中返回：
    ```rust
    for w in suffixes {
        if v == *w || v.ends_with(&format!(".{w}")) { return Some(w.clone()); }
    }
    ```
  - 注释声称的"最长后缀匹配"实际不成立：`intel.rs:32-37` 的注释写着"排序保证最长后缀匹配稳定"，但升序排序后 `suffix_hit` 返回的是**最短**后缀；且该函数 `load_suffixes` 全仓库无调用者（排序实际发生在 `intel.rs:104`、`intel.rs:115` 的内联代码里），注释与死代码一起误导读者。对 50000 条逐条 `format!` 分配，每次告警最多 3 个域名字段 → 最坏 15 万次分配/事件。
  - 威胁域名也走这套后缀语义：`intel.rs:186`（`suffix_hit(&self.threat.domains, domain)`）。
  - 名单里含有公共后缀：`threat-intel/data/domain.txt:49400` 就是 `co.kr`。后缀匹配意味着 `naver.co.kr`、`*.co.kr` 全部被判为威胁域名。
  - 文档承诺与 CLI 一致：`xbits/README.md:317`（"查询语义与子模块 CLI 一致（`threat-intel/tools/query.py`…）"），但 `threat-intel/tools/query.py:68` 是集合精确匹配（`if v in self._load()[algo]`）。
- **为什么是绕过而非根治**：用"域名后缀"近似"恶意域名列表"，在名单含公共后缀时会整片误判；同时又和自家 CLI/文档的精确语义不一致——两边对同一数据给出不同答案。当前因 R2 情报不参与决策而暂未爆发，一旦按文档接入决策就是成规模的误报/告警噪声。
- **正面修复方向**：统一语义：威胁域名按精确匹配（或明确"仅域名字典 + 排除公共后缀"），allowlist 才做后缀匹配；加载时用公共后缀表校验并拒绝/告警；用反向后缀排序 + 二分（或后缀树）取最长匹配，取代 O(n) 全表扫描和逐条分配；`co.kr` 这类条目应在数据校验阶段被拦下。

## R7 · 挂起告警的超时只在"通道空闲 500ms"时判定：持续流量下永久挂起

- **严重度/分类**：high / 未根治（状态机）
- **证据**
  - `analysis.rs:1134-1150` 的唯一分析线程：
    ```rust
    loop {
        match rx.recv_timeout(tick) {
            Ok(Job::Event(event)) => analyzer.observe(event),
            Ok(Job::Alert(event, alert)) => analyzer.process(event, alert),
            Ok(Job::File(event)) => analyzer.handle_file(event),
            Err(mpsc::RecvTimeoutError::Timeout) => analyzer.flush_expired_pending(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    ```
  - `flush_expired_pending`（`analysis.rs:681-698`）只能在 `Timeout` 分支被调用；`tick` 就是 `pending_context_timeout`（默认 500ms，`main.rs:243`）。
  - 只要事件持续到达（真实流量下常态），`recv_timeout` 每次都返回 `Ok`，`flush_expired_pending` 永不执行；`pending`（`analysis.rs:453-454`）没有容量上限。
  - 与之矛盾的设计声明：`analysis.rs:590-593`（"超时则按 fail-closed 处理…绝不丢弃事件"）、`xbits/README.md:254-256`。
- **为什么是绕过而非根治**：把"超时"实现成"空闲时才检查超时"，等于把超时语义交给流量形态。事件密集时挂起的告警既不判定也不输出，直到有匹配的 `match_context`（可能永不到来）或流量静默；同时无界增长。这是状态机层面的假完成：测试 `defers_alert_until_match_context_arrives`（`analysis.rs:1355-1378`）与 `expired_pending_fails_closed`（`analysis.rs:1381-1403`）都只测单线程顺序调用，无法暴露该饥饿。
- **正面修复方向**：超时判定与消息处理解耦——每轮循环先用 `Instant::now()` 扫一遍过期 pending（或独立计时线程/`select` 超时分支），并为 pending 设置容量上限 + 超时计数指标；测试改为"持续注入事件 + 时间推进"验证过期仍被处理。

## R8 · 引擎层 pending 超时静默丢弃、`flush_pending` 是清空式死代码、状态表无界

- **严重度/分类**：high / 兜底绕过
- **证据**
  - `engine.rs:157-162` 每次 `process` 开头按 TTL 剪掉挂起告警，无日志、无计数、无降级输出：
    ```rust
    fn prune(&mut self) {
        self.contexts.retain(|_, c| now.duration_since(c.at) <= self.ttl);
        self.pending.retain(|p| now.duration_since(p.at) <= self.ttl);
    }
    ```
  - `engine.rs:320-334` 命中 key 后若 `make_alert` 返回 `None`（benign/confidence）直接丢弃，注释一句"Rejected benign/confidence cases are dropped."了事；TTL=60s 写死在 `engine.rs:84`，CLI 无对应参数（`--pending-context-ms` 只作用于 analysis 层，`main.rs:143-145`）。
  - `engine.rs:369-372` 的 `flush_pending` 把 pending 清空却返回空 `Vec`，且全仓库无调用者（grep 仅此定义）：
    ```rust
    pub fn flush_pending(&mut self) -> Vec<EngineAlert> { self.pending.clear(); Vec::new() }
    ```
  - 状态表同样无界：`engine.rs:68-69`（`scores`、`cid_uid`）只增不减；`engine.rs:304-308` 只写 `cid_uid`，全仓库无读取；`engine.rs:292-297` 的 `scores` 只累加不衰减，阈值一旦越过就永久越过。
- **为什么是绕过而非根治**：README 说"上下文缺失时不输出高置信度告警"（`xbits/README.md:330`），实现却是"60 秒后静默蒸发"，且与 analysis 层的 fail-closed 输出路径不一致——同一个告警走哪层 pending 决定了它是"可见但低置信"还是"彻底消失"。`flush_pending` 更是伪装成"flush"的丢弃接口，任何后续调用者都会静默丢告警。
- **正面修复方向**：引擎 pending 超时也必须产生可见结果（降级输出 + `context_missing` 记录/指标），或与 analysis 层统一到同一个 pending 状态机；删除 `flush_pending` 或实现真正的 flush（返回待判定告警）；为 `scores`/`cid_uid` 加 TTL/容量上界，并删掉只写不读的 `cid_uid`。

## R9 · 审计/ES 唯一通道静默丢文档；分析线程 panic 后全量静默停摆

- **严重度/分类**：high / 兜底绕过
- **证据**
  - `analysis.rs:936-961` 的 `emit` 是告警与 file_triage 唯一的落盘/推 ES 通道：
    ```rust
    if let Some(path) = self.config.analysis_file.as_ref() {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");   // 打开失败/写入失败都被吞掉
        }
    }
    if !to_es { return; }                       // 未配 analysis-file 且 to_es=false → 文档直接消失
    ```
    而 `handle_file` 的 `received/analyzing/failed/skipped` 全部 `to_es=false`（`analysis.rs:931-933`）。
  - 提交端忽略发送失败：`analysis.rs:1154-1166`（`let _ = self.tx.send(...)`）。分析线程若 panic，接收端被丢弃，此后 `send` 返回 `Err` 却无人观察——引擎仍向 stdout 写告警，ES/分析文件永久静默无输出。
  - 一条可达的 panic 路径：`analysis.rs:905-906` 用字节切片取 sha 前两位：
    ```rust
    if sha.len() >= 2 { let nested = dir.join(&sha[0..2]).join(sha); ... }
    ```
    `sha` 来自事件 JSON（`model.rs:87-88` 的 `sha256` 别名、`hook.rs:133`）。hook socket 权限是 `0666`（`hook.rs:209`），任意本机用户可发一条含多字节字符的 `file_sha256`，`&sha[0..2]` 落在非 char 边界 → 分析线程 panic → 之后所有分析静默停止。
- **为什么是绕过而非根治**：文档把 analysis-file 描述为"全程跟踪/唯一告警落盘入口"（`triage/README.md:97-99`、`xbits/README.md:226-228,345`），实现却把"写不进去"和"没配"都当成正常路径；分析线程没有任何存活探测，单次 panic 就永久降级，且降级不可观测。
- **正面修复方向**：写失败/打开失败必须上报（错误计数 + stderr + 健康端点 fail）；未配 `analysis_file` 时对 `to_es=false` 的文档给出明确去向（stderr 或强制要求二选一）；`submit_*` 必须检查 `send` 结果并在失败时标记流水线不可用；`file_sha256` 先做 hex 校验（`[0-9a-f]{32,64}`）后再切片（`get(0..2)`），并给分析线程加心跳/重建。

## R10 · triage 超时被报成 `bad-triage-json`，只杀 `sh` 不杀子进程，`stored` 从不校验

- **严重度/分类**：high / 表面处理
- **证据**
  - `run_shell`（`analysis.rs:381-401`）超时后 kill 子进程并 break，随后把"读不到东西"当成成功：
    ```rust
    let (out, err) = rx.recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|_| (String::new(), String::new()));
    ...
    Ok(out)          // 超时 → Ok("")
    ```
  - `handle_file`（`analysis.rs:842-893`）对空串走 JSON 解析失败分支：
    ```rust
    Err(err) => self.emit_file_stage(&event, "failed", None,
        Some(format!("bad-triage-json: {err}"))),
    ```
    即 `--triage-timeout-ms` 超时在文档里显示为"JSON 坏了"；validator 超时同理被记成 `validator-output-error`（`analysis.rs:562-566`）。
  - `analysis.rs:386-387` 的 `let _ = child.kill(); let _ = child.wait();` 只杀 `sh`（命令经 `sh -c` 启动，`analysis.rs:354-356`），真正的 `python3 triage/triage.py` 孙进程继续跑，且 stderr/stdout 管道仍被占用；kill 失败也被 `let _` 吞掉。
  - 失败原因失真：`analysis.rs:802` 的 note 声称 `file-not-locatable (stored=false or not found in spool dir)`，但 `resolve_file_path`（`analysis.rs:897-916`）从不读 `event.file_stored`；`file_stored=false` 只要 spool 里有同名 sha 仍会被 triage。
- **为什么是绕过而非根治**：超时、空输出、坏 JSON、文件缺失四种截然不同的故障被压成两个字符串，运维无法区分"triage 太慢"和"triage 输出格式错"；杀进程只杀壳，超时根本约束不住资源（孙进程继续消耗 CPU/读取样本），"超时保护"名存实亡。
- **正面修复方向**：让 `run_shell` 返回显式的 `Timeout`/`NonZeroExit` 结果（用进程组 `setsid` + `killpg` 杀整棵树），阶段文档区分 `timeout` 与 `bad-json`；校验 `file_stored`（false 时直接 `failed(stored=false)`，不要猜路径），note 文案与代码路径一一对应。

## R11 · `min_confidence` 门槛不可达：先 `.max(minimum)` 抬升，过滤条件永远为假

- **严重度/分类**：high / 表面处理
- **证据**
  - `engine.rs:228` 计算时就把置信度抬到下限：
    ```rust
    confidence.min(100).max(rule.min_confidence.unwrap_or(0))
    ```
  - 紧接着的门槛判断（`engine.rs:239-243`）要求 `confidence < minimum` 才丢弃：
    ```rust
    if let Some(minimum) = rule.min_confidence {
        if confidence < minimum { return None; }
    }
    ```
    由于上一步已经保证 `confidence >= minimum`，该条件恒为假。
  - 文档承诺它是过滤器：`xbits/README.md:325`（"`min_confidence`: 只输出达到置信度阈值的告警"）、`model.rs:141-142`。
- **为什么是绕过而非根治**：一个"策略门槛"被实现成"标签抬升"：无上下文事件（基础置信度 50）配 `min_confidence: 90` 的规则，不会被过滤，而是**以 90 的置信度输出**——比不设门槛更危险。测试集里没有任何一条针对 `min_confidence` 的用例（`engine.rs:375-473`），所以这个死条件从未被发现。
- **正面修复方向**：删掉 `.max(min_confidence)`，让门槛真正执行过滤（或明确改名 `confidence_floor` 并同步文档/告警字段语义）；补一条单测：`min_confidence=90` + 无上下文 → 必须不输出。

## R12 · 30 秒的 triage 同步跑在唯一分析线程上，阻塞全部告警判定与超时

- **严重度/分类**：medium / 未根治
- **证据**
  - 单线程消费所有 Job：`analysis.rs:1136-1150`；`Ok(Job::File(event)) => analyzer.handle_file(event)` 直接在该线程里执行。
  - `handle_file` 内同步调用外部命令：`analysis.rs:842`（`run_shell(&cmd, &input, self.config.triage_timeout)`），默认 30s（`main.rs:56`、`analysis.rs:61`）。
  - 同一线程还负责 `observe`（match_context → `flush_ready_pending`）与 `flush_expired_pending`（`analysis.rs:1143-1146`）。
- **为什么是绕过而非根治**：只要有一个文件在跑 triage，队列里的所有告警都被推迟最多 30s；期间到达的 `match_context` 不被消费，`pending` 超时也不被判定（叠加 R7），抑制 key 与判定结果整体错位。设计上把"外部不可控耗时操作"和"有超时语义的状态机"放进了同一个执行体，缺乏隔离。
- **正面修复方向**：triage 走独立 worker/线程池 + 有界队列（或异步子进程回调），分析线程只做决策；为 triage 并发度、队列深度、丢弃策略提供显式配置与指标。

## R13 · docker 侧新增 file-store + files 事件没有任何消费者，镜像里也没有 triage/python3/情报数据

- **严重度/分类**：medium / 文档与实现不符
- **证据**
  - `docker/suricata-test.yaml:24-31` 开启 `file-store`（`dir: /opt/xbits/filestore`、`force-filestore: yes`），`:43-45` 增加 `files` EVE 类型。
  - 但 CI 里运行 xbits 时没有传任何新参数：`.github/workflows/xbits-images.yml:204-207`
    ```bash
    xbits/target/release/xbits --hook-socket /tmp/xbits-hook.sock --rules xbits/rules/default.json
    ```
    于是 `fileinfo` 事件走到 `hook.rs:265-270` 时 `pipeline` 为 `None`，被 `continue` **静默丢弃**；`hook.rs:218-228` 的状态行也不涉及文件 triage。
  - 文件落盘目录在容器内（`docker/xbits-suricata.Dockerfile:21` 创建 `/opt/xbits/filestore`），而 CI 的容器只挂载 `/tmp`（`xbits-images.yml:215-223`），宿主上的 xbits 即使配置 `--file-spool-dir` 也看不到。
  - 镜像里没有 triage 与 python3：`xbits-suricata.Dockerfile:16-19` 的 apt 列表无 python3，`:28-46` 的 COPY 只有插件/规则/配置；但 `triage/README.md:87-88` 写的生产命令是 `--triage-cmd "python3 /opt/xbits/triage/triage.py --stdin"`，该路径在两个镜像中都不存在（`xbits-zeek.Dockerfile:17-18,21-29` 装了 python3 但没有 triage/、也没有 threat-intel/allowlist）。
- **为什么是绕过而非根治**：配置文件"看起来接上了"，实际是单向的：Suricata 写盘 + 发事件，xbits 无人消费、无盘可读、无工具可调。任何据此判断"文件分析已上线"的运维结论都是错的。
- **正面修复方向**：把 triage、python3、情报数据纳入镜像（或明确只在宿主运行并挂载同一 spool 卷），CI 用真实 Suricata file-store 产出驱动一次端到端测试；docker 配置与 CLI 参数由同一份参数清单生成/校验，避免"配置改了、启动命令没改"。

## R14 · "suricata fileinfo → xbits → triage" 的 QA 全程自造 spool 与事件，从未经过 Suricata

- **严重度/分类**：medium / 测试掩盖
- **证据**
  - CI 步骤名声称覆盖真实链路：`.github/workflows/xbits-ci.yml:239`（`File static-triage orchestration QA (suricata fileinfo -> xbits -> triage)`）。
  - 实际测试自建 spool 并直接写文件：`xbits/test/qa_file_triage.py:66-71`（`store_file` 把样本写进临时目录）、`:96-121`（直接 `subprocess.Popen` 起 xbits，`--file-spool-dir` 指向临时目录）。
  - 事件也是手工构造的：`qa_file_triage.py:77-93`（`base_file_event`）与 `:169-179`（手写 EVE `fileinfo`），没有任何 Suricata 进程参与；断言只读 `--analysis-file`（`:128-141`），不校验 ES 推送、不校验情报命中、不校验超时/缓存路径。
  - 与之对照：docker 侧真正启用 file-store 的 `suricata-test.yaml` 反而无人测试（见 R13）。
- **为什么是绕过而非根治**：测试验证的是"xbits 处理我伪造的事件"这一半，伪装成"Suricata 产出的 fileinfo 被正确处理"；`file-store v2` 的目录布局、`stored` 字段、`files` EVE 类型是否真如假设，全部未被验证。这类测试绿了只会掩盖 R10/R13 的真实故障。
- **正面修复方向**：用真实 Suricata（镜像 + docker/suricata-test.yaml）跑一个含文件的 pcap，捕获它写出的 `<dir>/<sha[0:2]>/<sha>` 与 `fileinfo` 事件，再喂给 xbits；为 `failed`/`skipped` 阶段加"必须出现在 ES 或告警"的断言；补 timeout 与 cache 用例。

## R15 · `match_buffers`/`sid_library` 解析失败被 `unwrap_or_default()` 静默变空表 → 全量抑制失效

- **严重度/分类**：medium / 兜底绕过
- **证据**
  - `analysis.rs:327-351`：读文件失败才 `eprintln`，**解析失败直接变空映射**且无任何日志：
    ```rust
    match fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),  // 坏 JSON = {}
        Err(err) => { eprintln!("xbits: cannot load metadata ..."); HashMap::new() }
    }
    ```
    两处（`load_meta` 与 `load_match_buffers`）都是这个形状。
  - 空 `match_buffers` 的直接后果：`suppression_key` 因 `buffers.is_empty()` 返回 `None`（`analysis.rs:276-279`），`process_now` 里 `key.is_none()` 且 `meta` 为 `None` 时**一个日志都不打**（`analysis.rs:720-742` 的诊断全在 `if let Some(meta)` 里）。
  - 抑制失效后的表现与"没有误报"完全一致：`whitelist.contains` 永不命中（`analysis.rs:743-746`），所有本应被抑制的事件继续进 ES。
- **为什么是绕过而非根治**：配置/元数据损坏被当成"没有元数据"处理，抑制能力静默归零；而 README 把 `match_buffers.json` 描述为抑制的必需前提（`xbits/README.md:230-234`），缺了它不仅不该静默，还应当拒绝启动或显式告警。
- **正面修复方向**：解析失败必须 fatal（带路径与行号）或至少 error 级日志 + 健康状态降级；启动时做自检（如对抽样 SID 试建 key，失败即拒绝服务）；删除 `unwrap_or_default()` 在这两处的兜底用法。

---

## 附：被证伪的怀疑点（避免重复排查）

- **docker 与代码路径/文件名不一致（怀疑点 6 的一部分）**：`docker/xbits-suricata.Dockerfile:21` 确实创建了 `/opt/xbits/filestore`，与 `suricata-test.yaml:27` 的 `dir:` 一致；`probe-rules-*.yaml` 的 `default-rule-path` 也与镜像内拷贝路径一致。真正的问题不是路径拼错，而是"配了没人消费"（见 R13）。
- **`let _ =` 遍布各处并非都在掩盖错误**：`hook.rs:164`、`lib.rs:140` 的 `remove_file`（socket 清理）、`intel.rs:274/318` 测试清理属于合理忽略；有实质影响的是 `analysis.rs:944/945`（审计落盘）与 `analysis.rs:1155-1164`（提交失败），已归入 R9。
- **`engine.rs` 的 `context` 关联键本身**（`engine.rs:120-140`）对正反向 5 元组做了排序归一（`std::mem::swap`），Suricata 告警与 Zeek 上下文的正/反方向能对上，未发现"永久匹配不上"的缺陷；问题在超时丢弃（R8）而非键构造。