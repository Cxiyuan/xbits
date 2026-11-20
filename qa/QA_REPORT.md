# xbits 根因 QA 报告（交叉核验版）

- 角色：verifier（team deep-qa-rootcause / task t5，attempt `deb42a55`）
- 输入：`qa/findings/{rust,python,rules,tests}.md` 四份审计（共 55 条）
- 方法：只读静态核验。逐条打开被引用的 `file:line` 用 read/grep 复核，并用独立脚本重算可量化断言（SID 计数、规则语法统计、数据行数、JSON 计数）。**未修改任何源码，未运行 cargo/docker/suricata/pytest，未联网。**
- 判定口径：**Verified** = 证据成立（行号可能有个位数漂移，但被引代码/数据实际存在且语义一致）；**Rejected** = 证据不成立或误读，附反证 `file:line`；**Uncertain** = 静态无法定论，需运行。
- 结论口径：只保留「表面已完成、实际靠兜底/静默降级/测试假绿绕过」的问题，按根因合并去重。

**核验统计**：55 条原始发现 → 合并为 **24 条必须正面根治**（含 2 条 blocker）+ **5 条需运行确认** + **5 条误报剔除** + **5 条系统性根因**，共 39 条，全部可复核。

---

## 0. 两个专项复核结论

### A) xbits `intel.rs` 是否"只标注不决策"？——**属实（Verified，判定为 blocker）**

| 核验点 | 结论 | 证据 |
|---|---|---|
| 情报是否进入评分 | 否 | `engine.rs:231-290` `make_alert` 先算 `score: rule.score.max(1)`（`:276`）与 `confidence`（`:212-228`），`annotate` 在其**之后**调用（`:325`、`:362`），只赋值字段（`engine.rs:95-110`） |
| 情报是否影响抑制 | 否 | 抑制只看 `benign()`（规则内 `benign_uri_contains/benign_host_contains`，`engine.rs:199-210`）与 validator 误报白名单（`analysis.rs:743-785`） |
| 情报是否进 ES/审计文档 | 否 | `analysis.rs:1002-1052` `normalized_document` 的 `json!` 无 `intel`/`allowlist`；**全文件 grep `intel` = 0 命中** |
| 是否只进 stdout 告警 JSON | 是 | `EngineAlert.intel/allowlist`（`engine.rs:39-44`）只在 `hook.rs:269-275` 序列化到 stdout/alert-file |
| 文档是否宣称"参与决策" | 是 | `intel.rs:4-5`「命中加重／命中降级、放行」；`xbits/README.md:313-317`「异常加权提示」；`allowlist/README.md:47-48`「命中则降级/抑制」 |

**判定**：情报链路对 score / confidence / 是否输出 / 是否进 ES **零影响**，且标注连 ES 文档都进不去。属"接口接上了、决策没接"的表面完成。

### B) `threat-intel/` 与 `allowlist/` 是否不在任何 workflow `paths:`？——**属实（Verified）**

- 逐文件核对 7 个 workflow 的 `paths:`：`app-id-scan.yml:5-10`、`suricata-{dns-tunnel,recon-tools,web-exploit,backdoor-c2}.yml:6-30`、`xbits-ci.yml:6-20`、`xbits-images.yml:6-20`，**无 `threat-intel/**`、`allowlist/**`、`triage/**`**。
- 全 workflow 目录 grep `threat-intel|allowlist` = **0 命中**；`triage` 仅出现在 `xbits-ci.yml:222-244` 的**步骤内容**（不在 `paths:`）。
- 即：`xbits-ci.yml:222-244` 新增的 triage 单测/`qa_file_triage.py` 步骤，改 `triage/triage.py` 时**该 workflow 根本不会启动**。

**判定**：新增三个根目录（`triage/`、`threat-intel/`、`allowlist/`）零 CI 触发，属结构性假绿。

---

## 一、必须正面根治（不可再兜底）

> 每条给出：问题 / 证据 / 根因 / 正面修复方案 / 影响面。合并后的条目在其后标注来源审计 ID。

### V-01 · blocker · 测试模块编译不过，`cargo test` 结果不可信
- **问题**：`EngineAlert` 新增两字段后，测试构造器未同步，「测试通过」的前提不成立。
- **证据**：`engine.rs:39-44` 新增 `pub intel` / `pub allowlist`；`analysis.rs:1177-1201` 的 `fn alert()` 构造到 `context: None,`（`:1199`）后直接 `}`（`:1200`），缺 2 个字段 → Rust E0063。全仓 `EngineAlert {` 字面量仅两处：`engine.rs:265`（`make_alert`，已带 `intel: None, allowlist: None`，`:287-288`）与 `analysis.rs:1178`（测试构造器，缺字段）。
- **根因**：告警结构无单一构造入口，测试直接写结构体字面量新增字段就要逐处同步。需注意：CI 的 `rust` job 确实跑 `cargo test`（`xbits-ci.yml:76,101`）且下游 4 个 job 均 `needs: rust`（`:29,130,196,248`），所以该错误一旦推送会立刻变红——**问题是当前工作区改动尚未提交**（`git status` 中 `xbits/src/*.rs` 全为 `M`、新文件为 `??`），即本轮改动从未经过 CI，"测试通过"的表述不成立。
- **正面修复**：`EngineAlert` 收口到一个 `make_alert` 构造入口（或 `Default` + 结构体更新语法），测试只经该入口构造；补 CI 门禁不变式（`cargo test` 失败即阻断依赖 job 已具备，无需新增）。
- **影响面**：所有"CI 绿"结论（match_context、file triage、images）失去可信度。
- 来源：R1。

### V-02 · blocker · 情报只标注不决策，且标注不进 ES 文档
- **问题**：命中已知 C2 IP 与未命中的告警，在 score/confidence/是否输出/是否进 ES 上**完全等价**。
- **证据**：见 §0-A（`engine.rs:95-110`、`:276`、`:231-290`；`analysis.rs:1002-1052` 无 intel；`analysis.rs` 全文 0 命中）。文档反述见 `intel.rs:4-5`、`xbits/README.md:313-317`、`allowlist/README.md:47-48`。
- **根因**：情报查询挂在"告警产出之后"的标注钩子，而不是"决策点之前"的输入；ES 文档 schema 与告警结构体是两套字段清单，新增字段只加了一边。
- **正面修复**：① 威胁命中前移到决策点：明确 `score/confidence` 增量 + 可选的独立 `intel` 告警事件；② 白名单命中产出显式"抑制/降级"决策并写 `reason=intel-allowlist`；③ `normalized_document` 必须携带 `intel`/`allowlist` 与决策依据；④ 补端到端断言：同一事件命中/未命中情报，产出必须不同。
- **影响面**：整个「统一情报查询」能力对检测结果零贡献，且分析师在 ES 里看不到任何标注。
- 来源：R2（+ PY-15 的健康信号问题见 V-04）。

### V-03 · high · md5/sha1 情报永不查询；文件事件绕过引擎，hash 情报链路实际为空
- **问题**：加载了 md5/sha1 数据，但查询端只查 `file_sha256`；而唯一携带 `file_sha256` 的事件在 hook 层就被 `continue` 掉。
- **证据**：`intel.rs:92-97` 三种哈希合并进 `hashes`；`intel.rs:193-198` 只读 `ev.file_sha256`（`threat_hash` 支持 32/40/64 长度，但**调用方**只传 sha256）；`hook.rs:132-133` 解析了 `file_sha1`/`file_md5` 却无消费者；`hook.rs:259-264` `is_file_event(&ev.kind)` → `submit_file` → `continue`，**永不进 `engine.process`**，故 `annotate` 不执行。数据侧 `threat-intel/data/{md5.txt,sha1.txt,sha256.txt}` 分别 2,408/2,044/3,204 行。
- **根因**：哈希情报没有"按算法分派"的查询接口；文件事件在 hook 层被分叉，与"先标注评分、再进 triage"的顺序相反。
- **正面修复**：`threat_hash(algo, value)` 显式分派三套集合，文件事件与告警事件两条路径都调用；`fileinfo` 先进引擎（标注/评分）再进 triage；补"造 md5 命中事件必须产出 intel 标注"用例。
- **影响面**：文件哈希情报（约 7,656 条）实际上一条都不会被查询。
- 来源：R3。

### V-04 · high · 情报加载与健康自检三处静默降级：配置错=永不命中，日志还会说谎
- **问题**：目录/文件读失败全部吞成空集合；帮助文本承诺默认路径但代码无默认；`is_empty()` 只查 7 个集合中的 3 个。
- **证据**：
  - `intel.rs:19-30` `load_set`：`if let Ok(...)`，读失败 → 空集合，无日志/计数/错误。
  - `main.rs:199-200` 帮助文本「默认 data/…」，但 `main.rs:65-66` 默认值是 `None`，`main.rs:254-257` 直接透传 → **代码中不存在默认路径解析**。
  - `intel.rs:125-129` `is_empty()` 只查 `threat.ips`、`threat.hashes`、`allowlist.domains`，漏 `threat.domains`（50,000 条，最大一份）、`allowlist.ips`、`allowlist.public_dns`。
  - `hook.rs:213-217` 唯一的启动状态行：`Some(svc) if !svc.is_empty() => "intel=on" / Some(_) => "intel=empty" / None => "intel=off"`；而 `main.rs:254` 永远传 `Some(intel)`，`intel=off` 从 CLI 不可达。
- **根因**：把"数据集是否真的加载"压成一个布尔近似，且加载端没有返回结构化统计。
- **正面修复**：`load_set` 返回 `(集合, 读取结果)`，`IntelService::load` 汇总每类条目数与失败原因；启动逐项打印并纳入健康检查；`is_empty()` 要么覆盖全部集合、要么删除；区分「未配置 / 配置错 / 数据为空」三态；删掉帮助文本里不存在的默认值。
- **影响面**：只部署 5 万条恶意域名时启动行打印 `intel=empty`（方向相反）；生产少写一个参数则情报静默为"永不命中"，唯一痕迹本身还在误报。
- 来源：R4 + R5 + PY-15（同一根因，合并）。

### V-05 · high · 威胁域名用后缀匹配 + 名单含公共后缀 `co.kr`，且与 CLI 精确语义相反
- **问题**：用"域名后缀"近似"恶意域名列表"，并在数据里放进公共后缀。
- **证据**：`intel.rs:49-60` `suffix_hit` 对每条候选做 `v == w || v.ends_with(".{w}")`，从**排序（升序，`intel.rs:104`）后的第一个**命中返回 → 返回**最短**后缀；`intel.rs:32-37` 注释却称"排序保证最长后缀匹配稳定"，且 `load_suffixes` 全仓无调用者（grep 仅定义）。威胁域名同样走后缀语义：`intel.rs:186`。数据：`threat-intel/data/domain.txt:49400` = `co.kr`。CLI 侧是集合精确匹配（`threat-intel/tools/query.py` 的 `if v in self._load()[algo]`），而 `xbits/README.md:317` 声称"查询语义与子模块 CLI 一致"。
- **根因**：两个组件各写一套匹配语义，没有一致性测试；威胁情报误用了白名单的"后缀"模型。
- **正面修复**：威胁域名改精确匹配（或明确"域名字典 + 排除公共后缀"），只有 allowlist 做后缀匹配；加载期用公共后缀表校验并拒绝 `co.kr` 这类条目；用反向后缀有序结构 + 二分取最长匹配，替代 O(n) 全表扫描与逐条 `format!` 分配。
- **影响面**：`naver.co.kr` 等整片域名被判威胁；一旦按文档接入决策即成规模误报。
- 来源：R6。

### V-06 · high · pending 状态机双失：分析层"空闲才超时"，引擎层"静默蒸发"
- **问题**：超时判定绑在"通道空闲"上；引擎层过期直接丢弃，`flush_pending` 是清空式假接口。
- **证据**：
  - `analysis.rs:1141-1149` 唯一分析线程只在 `Err(RecvTimeoutError::Timeout)` 分支调用 `flush_expired_pending()`；`tick = pending_context_timeout`（默认 500ms，`main.rs:243`）。持续流量下 `recv_timeout` 恒返回 `Ok` → 超时永不判定，`pending` 无容量上限（`analysis.rs:453-454`）。
  - `engine.rs:157-162` `prune()` 按 TTL（写死 60s，`engine.rs:84`）静默 `retain` 丢弃，无日志/计数/降级输出；`engine.rs:329` 注释 "Rejected benign/confidence cases are dropped."；`engine.rs:369-372` `flush_pending` 清空并返回空 `Vec`，全仓无调用者。
  - 状态表无界：`engine.rs:68-69` `scores`/`cid_uid` 只增不减；`engine.rs:306` 写 `cid_uid` 全仓无读取；`engine.rs:292-297` `scores` 只累加不衰减。
  - 文档反述：`xbits/README.md:254-256`「超时按 fail-closed 处理…绝不丢事件」、`analysis.rs:590-593`。
- **根因**：超时语义实现成"流量形态的函数"；两层各有一套 pending 机制且语义不一致。
- **正面修复**：每轮循环先扫过期 pending（或独立计时线程），与消息处理解耦；pending 加容量上限与超时指标；引擎层超时必须产生可见结果（降级输出 + `context_missing` 记录）或与 analysis 层合并成同一状态机；删除 `flush_pending` 或实现真 flush；`scores`/`cid_uid` 加 TTL/容量，删掉只写不读的 `cid_uid`。
- **影响面**：事件密集时挂起告警既不判定也不输出且无界增长；同一告警走哪层 pending 决定它是"可见低置信"还是"彻底消失"。
- 来源：R7 + R8（同一状态机根因，合并）。

### V-07 · high · 审计/ES 唯一通道静默丢文档；分析线程 panic 后全量静默停摆
- **问题**：写失败/未配置都被当正常路径；提交失败无人观察；一条可达 panic 路径会永久降级分析。
- **证据**：`analysis.rs:943-950` `emit`：`if let Ok(mut file) = …open(path)` 打开失败即跳过；`let _ = writeln!` 写失败吞掉；`if !to_es { return; }`（未配 `analysis_file` 且 `to_es=false` → 文档直接消失）；`handle_file` 的 `received/analyzing/failed/skipped` 全部 `to_es=false`（`analysis.rs:918-933`）。`analysis.rs:1154-1165` `let _ = self.tx.send(...)`。`analysis.rs:905-906` `&sha[0..2]` 字节切片，`file_sha256` 来自事件 JSON（`hook.rs:131`），socket 权限 `0o666`（`hook.rs:209`）→ 非 char 边界即 panic，接收端随线程退出被丢弃。
- **根因**：把"写不进去/没配"当正常路径；分析线程无存活探测；外部输入未做格式校验就参与字节切片。
- **正面修复**：写/打开失败上报（错误计数 + stderr + 健康端点 fail）；未配 `analysis_file` 时对 `to_es=false` 文档给出明确去向或强制二选一；`submit_*` 检查 `send` 结果并在失败时标记流水线不可用；`file_sha256` 先做 `[0-9a-f]{32,64}` 校验再用 `get(0..2)`；分析线程加心跳/重建。
- **影响面**：`triage/README.md:97-99`、`xbits/README.md:226-228,345` 承诺的"全程跟踪/唯一落盘入口"在磁盘满、权限错、未配置时静默失效。
- 来源：R9。

### V-08 · high · triage 编排：超时/坏 JSON/缺文件同形，只杀 `sh`，`stored` 不校验，且 30s 同步阻塞唯一分析线程
- **问题**：四种故障压成两个字符串；超时约束不住子进程；文件定位忽略 `file_stored`；triage 跑在决策线程上。
- **证据**：
  - `analysis.rs:353-401` `run_shell`：超时 `kill` 后 `break`，随后 `rx.recv_timeout(1s).unwrap_or_else(|_| (String::new(), String::new()))` → `Ok(out)`，超时返回 `Ok("")`。
  - `analysis.rs:880-885` 空串 → `bad-triage-json: {err}`；validator 超时同理记为 `validator-output-error`（`analysis.rs:562-566`）。
  - `analysis.rs:386-387` `let _ = child.kill(); let _ = child.wait();` 只杀 `sh -c`（`analysis.rs:354-356`），孙进程 `python3 triage/triage.py` 继续跑；kill 失败被 `let _` 吞掉。
  - `analysis.rs:897-916` `resolve_file_path` 不读 `event.file_stored`（`hook.rs:137` 有解析），`file_stored=false` 只要 spool 有同名 sha 仍会 triage；note 文案（`analysis.rs:802`）声称 `stored=false or not found`，与代码不符；文档承诺 `triage/README.md:99`「文件缺失或 `stored=false` → `failed`（fail-closed，不猜测）」直接被违反。
  - `analysis.rs:1145` `Ok(Job::File(event)) => analyzer.handle_file(event)` 在唯一分析线程内同步执行，`analysis.rs:842` 默认 30s（`main.rs:56`）。
- **根因**：外部不可控耗时操作与有超时语义的状态机放在同一执行体；进程管理只杀壳；阶段语义与文案各写一套。
- **正面修复**：`run_shell` 返回显式 `Timeout`/`NonZeroExit`，用进程组（`setsid`/`killpg`）杀整棵树，阶段文档区分 `timeout` 与 `bad-json`；校验 `file_stored=false` 直接 `failed(stored=false)`；triage 走独立 worker/线程池 + 有界队列，分析线程只做决策。
- **影响面**：运维无法区分"triage 太慢"和"输出格式错"；超时保护名存实亡；一次 triage 阻塞全部告警与超时判定（并与 V-06 叠加）。
- 来源：R10 + R12（同一编排根因，合并）。

### V-09 · high · `min_confidence` 不是门槛而是"抬升"：过滤条件恒为假
- **证据**：`engine.rs:228` `confidence.min(100).max(rule.min_confidence.unwrap_or(0))`；`engine.rs:239-243` 再判 `if confidence < minimum { return None }` —— 上一步已保证 `>= minimum`，恒假。文档把它写作过滤器（`xbits/README.md:325`、`model.rs:142`）。测试无 `min_confidence` 用例（`engine.rs:375-473`）。
- **根因**：策略门槛与标签下限共用一个字段，语义被实现成"抬标签"。
- **正面修复**：删 `.max(min_confidence)` 让门槛真正过滤（或改名 `confidence_floor` 并同步文档/字段语义）；补 `min_confidence=90` + 无上下文 → 必须不输出的单测。
- **影响面**：`min_confidence: 90` 的规则不会少报，而是以 90 的置信度输出——比不设门槛更危险。
- 来源：R11。

### V-10 · high · 规则转译 sticky buffer 顺序整体反转（5,544 条），且 2,073 条正确顺序反被整条剔除
- **问题**：把 Snort「content 在前、buffer 修饰」语义搬进 Suricata（buffer 只作用其**后**的 content/pcre），锚点落错字段；同时把正确写法误判为非法删除。
- **证据**：
  - 统计（本次独立重算，严格正则 `content:"…";…;http_uri`）：**5,544 条**，与审计一致。样例 `规则检测/suricata/Web攻击/SQL注入/sql.rules:3`：`content:"select"; http_uri; nocase; pcre:"…"`。
  - `规则检测/convert_probe_rules.py:346` `URICONTENT_RE.sub(lambda m: f'content:"{m.group(1)}"; http_uri;')`；`规则检测/docs/规则归档与转换方案.md:62` 称"等价"。
  - `convert_probe_rules.py:296-299` `if tl == "http_uri" and not prev.lower().startswith("content:"): return "dangling-http-uri"` → `semantic_gaps.json` 记 `dangling-http-uri: 2073`。
  - 同仓两种顺序并存：自研用前置（`规则检测/suricata/后门通信/命令与控制信标规则.rules:35` `http.uri.raw; …`），转译用后置。
  - CI 只做加载：`.github/workflows/xbits-images.yml:155-161` `suricata -T`；17,403 条转译规则无 PCAP 回放。
- **根因**：转换器按"令牌重写"而非"语义树→线性化"；CI 只断言"能加载"，无命中语义回归。
- **正面修复**：转换器先归约到 `(buffer, content…)` 语义树，再按 `buffer; content; 修饰词` 重新生成；删除 `dangling-http-uri` 误判，改为"buffer 无后继 content/pcre 时告警"；为每类 buffer 各挑 2~3 条做"只在该 buffer 命中/不命中"的 PCAP 回归，接进 `xbits-images`；撤回文档"等价"结论。
- **影响面**：锚点变宽（误报上升）+ 精确约束落错字段（漏报）；2,073 条被误删。
- 来源：R-01。

### V-11 · high · `http_stat_code` 之后的 content 被绑定到 3 字节缓冲：17 条规则永不命中
- **证据**：`规则检测/suricata/Web攻击/文件包含/file_include.rules:26`（sid:13060038）：`content:"200"; http_stat_code; content:"|0d 0a 0d 0a|"; content:"|23 21 2f|bin|2f|bash"; …`；`规则检测/suricata/恶意软件/后门/backdoor.rules:9-11`。本次独立统计「buffer 关键词之后还有 content」= **17 条**，与审计一致。元数据把 13060043 写成 `["http.header","http.status"] / primary=http.header`（`规则检测/xbits/规则库元数据/match_buffers.json`）。
- **根因**：同 V-10 的顺序反转；且没有"buffer 容量 vs content 长度"的静态校验。
- **正面修复**：状态码生成 `http_stat_code; content:"N";` 前置，且必须是最后一个 buffer 段，其后继续匹配须显式重置 buffer（`file_data;`/`http_header;`）；加静态断言：buffer 容量上界（状态码=3、method≤16）< content 长度即 fail 生成流程；用两组构造 PCAP 做"应当命中"回归。
- **影响面**：17 条「文件在、SID 在、CI 绿、永远不报警」的死规则。
- 来源：R-02。

### V-12 · high · `http.uri.raw` 被生成器塌缩成 `http.uri`（15 条），与 xbits 硬约束冲突
- **证据**：`规则检测/build_match_buffers.py:141-142` `if n.startswith("http.uri"): return "http.uri"` → `"http.uri.raw".startswith("http.uri")` 为真；仅下划线写法正确映射（`:31` `"http_raw_uri": "http.uri.raw"`）。产物核对：`match_buffers.json` 的 `9103001/9104001/9110002/9110004` 全部 `"primary": "http.uri"`；本次统计 dotted `http.uri.raw` 规则共 **15 条**（Web漏洞利用 9 / 命令与控制信标 4 / WebShell后门通信 2），与审计一致。xbits 侧：`analysis.rs:144-153` 把 `http.uri.raw` 列入 `CONTEXT_ONLY_BUFFERS`，`analysis.rs:248-250` 注释「必须来自 match_context 导出，禁止用归一化值兜底」。
- **根因**：`build_match_buffers.py` 与 `analysis.rs:168-188` 各写一份映射表、无一致性测试（后者注释要求"必须与 ALIASES 一致"）。
- **正面修复**：`canonical_buffer` 精确匹配整串（显式列出 `http.uri` / `http.uri.raw` / `http.uri.query`），未知 dotted 名返回 `None` 而非放行；补 `canonical_buffer("http.uri.raw") == "http.uri.raw"` 单测；跨语言导出映射做集合相等断言；`qa_xbits_match_context.py` 至少用生产元数据跑 3 个真实 SID（含 raw 规则）。
- **影响面**：15 条规则的"精确抑制"退化回被明令禁止的归一化兜底（`%3C`/大小写/`%2e` 还原与否决定是否同一 key）。
- 来源：R-03 + TS-05（同一根因：元数据无人校验）。

### V-13 · high · 1,031 条 `lua:` 规则无 sticky buffer，Lua 增强可能整段不执行
- **证据**：规则库自述约束 `规则检测/suricata/DNS隧道与带外检测/DNS隧道与带外检测规则.rules:243-244`「只有 hook 没有 buffer 的规则会被当作 straight match，脚本不会执行」。本次独立统计（活跃规则行 18,098，`lua:` 7,065 条）：**无 buffer 1,067 条**，与审计的 1,031 条同量级（关键词集合差异导致 ±3%）。样例 `规则检测/suricata/Web攻击/SQL注入/sql.strong.rules:150`（sid:13020170）`content:…; nocase; lua:sqli_context.lua;`；元数据 `13020170 → buffers:["payload"], app_tx_lua:false`（已核对）。注入器不看 buffer：`规则检测/apply_lua_enhancements.py:101-102`（`mode == "all"` 直接注入）、`:35` 正则插在 `sid:` 前。
- **根因**：批量注入只看 flow 方向；无任何测试能证明"Lua 到底跑没跑"（转译规则从不回放 PCAP）。
- **正面修复**：先做事实校准（同样 content 两条最小规则、一条带 `http.uri;` 前置、一条不带，用 `print` 观察 `match` 是否被调用），把结论写回规则库注释；按结论二选一：给这 1,031 条补 buffer，或撤掉 `lua:` 并在元数据如实标"无增强"；`apply_lua_enhancements.py` 加"目标规则必须已有 sticky buffer"前置；CI 断言"`lua:` 且无 buffer 的条数 == 0"。
- **影响面**：这些规则降误报的唯一手段（URL 解码、注释归一化、盲注判定）失效，退化成纯 content 匹配。
- 来源：R-05。

### V-14 · high · 已修复（t39 C6-A + t40 C6-B，abaf277 之后的 commit 7c4c752 等；状态更新于第 9 轮） · 原问题：1,546 条 flowbits/depend 请求→响应状态链被删除并宣称"交 xbits"，xbits 无任何消费代码
- **证据**：`convert_probe_rules.py:676-680`（`flowbits:` → `skip="flowbits-correlation"`）、`:683-687`（`depend`/`scope_id` → `skip="dependency-correlation"`）、`:850-852` 写 `success_rules.json`（**996 条**，已核对）；`semantic_gaps.json`：`flowbits-correlation: 670`、`dependency-correlation: 876`，合计 1,546。文档承诺：`规则检测/README.md:6-7`、`:19`。xbits 侧：grep `success_rules|depends|dependency` 在 `xbits/` **0 命中**；`main.rs:71-184` 无对应 CLI；`analysis.rs` 的 `RuleMeta` 只反序列化 `tier/category/name`。
- **根因**："删除即修复"——把检测链路从 A 删掉、在 B 写注释，然后用 `suricata -T` 绿证明完成。
- **正面修复**：二选一并明写：① xbits 实现 `--success-rules`，按 `community_id + sid` 做请求→响应配对，产出 `correlated=true` 与评分，并有配对成立/不成立两种断言；② 不实现就恢复 Suricata 侧 flowbits 或把 `depend` 规则合并成单条，并删除文档承诺。对 `semantic_gaps.json` 每个 reason 建"能力归属表"（谁接管/有无测试）。
- **影响面**：检测能力净减少 1,546 条，所有可见证据都指向"已迁移"。
- 来源：R-04。

### V-15 · high · 已修复（t37 C5-C + t38 C5-D + t40 C6-B，abaf277 之后的 commit 7c4c752 等；状态更新于第 9 轮） · 原问题：剔除治理空转：`semantic_gaps.json` 只有生产者，`dead_rules.json` 恒为 `[]`
- **证据**：`semantic_gaps.json` counts 合计 **14,120**（本次逐项重算一致：`http-only-uri-unsupported 2947`、`dangling-http-uri 2073`、`dsl-semantic 1634`、`no-dependency 4708`、`dependency-correlation 876`、`flowbits-correlation 670`、`state-noalert 527`、`convert-rule-none 263`、`isdataat 136`、`unsupported 89`、`negated-pcre 80`、`method-unsupported 48`、`mixed-position 39`、`response-direction-conflict 14`、`rawbytes-unsupported 8`、`rate-unsupported 6`、`duplicate-position 1`、`false-positive-quarantine 1`）；消费方只有转换器自身（`convert_probe_rules.py:832-838`），`xbits/` grep `semantic_gaps` **0 命中**，workflow 也不读。`dead_rules.json` 实测内容 `[]`；机制上不可能非空：`convert_probe_rules.py:744-745` `flowbit_set = None` → `:360-363` 注入分支永不执行，带 flowbits 的规则更早在 `:676-680` 被剔除 → `cleanup_dead_flowbits`（`:462-505`）无输入。文档仍以它为卖点：`规则检测/README.md:20`。
- **根因**：把"记录了剔除原因"当成治理完成；没有 diff 契约、没有能力归属、没有阈值。
- **正面修复**：`semantic_gaps.json` 纳入 CI 契约（每次转换与提交版本 diff，每个 reason 的 SID 集合变化需显式白名单，新增剔除直接 fail）；每个 reason 建"能力归属 + 有无测试"字段，无归属视为 bug；剔除率设阈值告警；删除无效的 flowbits 清理链路，或改成有实际输入的形式。
- **影响面**：44.8%（14,120 / 31,523）源规则未进 Suricata，缺口在 CI 完全不可见，且 reason 本身可能是错的（含 V-10 的 2,073 条误删）。
- 来源：R-06 + R-07。

### V-16 · high · 新增三个根目录不进任何 workflow `paths:`，改了被测代码 CI 一次都不跑
- **证据**：见 §0-B。具体：`xbits-ci.yml:6-20` 只监听 `xbits/**` + 4 个 `生成用例脚本` + 自身，却在 `:222-244` 跑 `triage/tests/*`、`triage/triage.py`；`xbits-images.yml:6-20` 监听 `docker/**`、`xbits/**`、`app-id/**`、`规则检测/**`、`测试用例/generate_web_pcaps.py`，而 `:99-100` 的覆盖门禁读 `测试用例/{cases,recon_cases,web_cases,backdoor_cases}.json`（不在 paths）；`xbits-ci.yml:321-357` 的 `suricata-live` 拷 `规则检测/**`、`测试用例/*.config`、`*.yaml.in`（均不在该 workflow 的 paths）。
- **根因**：paths 按"源码区域"手工维护，与被测脚本实际读取的资源清单脱钩；新增模块没人回头改触发条件。
- **正面修复**：`xbits-ci.yml` paths 补 `triage/**`、`threat-intel/**`、`allowlist/**`、`规则检测/**`、`测试用例/*.{config,yaml.in,py}`；`xbits-images.yml` 补 `测试用例/*.json`、`triage/**`；更稳的做法是为 triage/intel/allowlist 各开独立 workflow（paths=自身+共用断言脚本）；加一条纯静态元测试：解析 `qa_*/test_*` 脚本里的仓库相对路径，断言每个都被至少一个 workflow `paths:` 前缀覆盖。
- **影响面**：本次审计的核心新模块恰好是最不会被触发的那几个目录，属结构性 CI 假绿。
- 来源：TS-01。

### V-17 · high · 测试只验证自造夹具，生产元数据与 17k 条规则无人校验
- **证据**：
  - 覆盖门禁自述"Every sid in every `规则检测/**/*.rules`"（`xbits/test/qa_rule_coverage.py:4-6`），实际 `CATEGORIES` 只列 4 个目录（`:17-42`）；本次重算：4 目录 **74** 个唯一 SID，全量 **17,477** 个 → 17,403 条不在门禁内；PASS 文案仍写 all（`:102`）；CI 步骤名 `Rule coverage gate (all SIDs must be exercised)`（`xbits-images.yml:99`）。
  - match_context 只用 6 条手写夹具：`xbits-ci.yml:219-220` 传 `xbits/testdata/match_buffers.json`（实测 **6** 个 SID，`"source":"testdata"`）；生产元数据 3.7MB / **17,477** 条，全 workflow 仅此一处引用 testdata，生产文件 0 引用。
  - hook 矩阵 docstring 承诺 `engine SID set == case.require`（`xbits/test/qa_suricata_hook_matrix.py:10-13`），代码只做 `eve != engine`、`require <= set(engine)`、`forbid & set(engine)`（`:247-253`），`extra` 只拼进 OK 文案（`:262-266`）。
- **根因**："给定正确元数据时逻辑对"被当成"元数据正确"；生成器改错 ALIASES、规则新增忘重算，测试全绿。
- **正面修复**：CI 跑 `build_match_buffers.py --check` 并与提交产物 diff，不一致 fail；门禁改成"目录白名单 + 显式 excluded（带原因/计数）"，PASS 文案打印 `covered 74/17477 (excluded 12 dirs)`；`qa_xbits_match_context.py` 用生产元数据跑 3~5 个真实 SID；hook 矩阵对"精确规则集"场景用 `set(engine) == require`，其余把 `extra` 变成 `::warning::` 或 `known_extra` 白名单。
- **影响面**：17,403 个 SID 只有"能加载"，没有任何命中语义回归。
- 来源：TS-02 + TS-05 + TS-06。

### V-18 · high · 运行时断言过弱：`grep` 子串 + 固定 `sleep` + "没输出即正确" + 双空用例
- **证据**：`xbits-ci.yml:70-73`（`sleep 1` → `grep -q 'xb-zeek-http-request'` → `kill … || true`）、`:158-162`（`xbits --stdin < testdata/alert.jsonl | grep -q '"signature_id":9103001'`，而输入第 1 行本身就含该串）、`:390-393`；`xbits-images.yml:236-243` 同构。`xbits/test/qa_xbits_context.py:74` `time.sleep(0.25)`、`:119-120` 负例只断言 `len(got) == 0`（与"引擎崩溃/规则没加载"同形）。`测试用例/backdoor_cases.json` 的 `c2_periodic` `require: []`、`forbid: []` —— 实测确认是全量 18 个用例中唯一双空；`测试用例/assert_suricata.py:49-56` 在双空下两个集合必为空 → 恒 OK。`triage/tests/test_triage.py:118-135` 「增强路径」只 `assertIn("pefile", r["engines"])`，而 `triage.py:239-245`/`:333-340` 无论 import 成功与否都写键 → 断言恒真。
- **根因**：把"能启动/能出现某子串"当成行为验证；固定墙钟等待替代终态轮询。
- **正面修复**：三处 hook 断言统一改用 `xbits/test/assert_xbits.py`（`--min-events`、`--require-uid`、字段集合校验）；`sleep 1` 换成"轮询到满足条件的 JSON 行，超时即失败"；`kill` 改为确认退出码 0 且 socket 已清理；`assert_suricata.py` 拒绝 require/forbid 双空；负例旁放"必须产出"的对照告警；增强步骤断言值而非键（`assertTrue(engines["pefile"])` + `info["pe"]` 字段）。
- **影响面**：告警缺 `community_id`、`sid` 变 0、字段缺失、丢 10 条只剩 1 条，全部通过；C2 周期性信标这条最易改坏的时序检测恰好在唯一无态度断言的用例里。
- 来源：TS-07 + TS-08 + TS-09 + TS-10 + TS-04 + R14 + PY-14（同一"弱断言/假同步"根因，合并）。

### V-19 · high · YARA 全链路只验"能编译"；运行期失败静默丢弃；严重度按规则名子串猜
- **证据**：`triage/tests/validate_rules.py:24-35` 只 `yara.compile(filepath=…)`，从不 `match()`；`triage/tests/` 里 `yara` 仅出现在该文件（已 grep）。`triage/triage.py:397-411` 逐文件编译失败 → `r = None` 静默跳过、不计数；`:421` `engines["yara"] = True` 在编译**前**置位；`:422-423` 目录不存在直接 `return`。`triage.py:437-441` 严重度 = 规则名是否含 `rat/ransom/webshell/backdoor/trojan/malware/shellcode`，而 `triage/rules/manifest.json` 实测 **224** 条规则名全部是 `xb_webshell_*`(85)/`xb_trojan_*`(81)/`xb_backdoor_*`(58) → 全部 critical → `:724-725` 任何一条命中即 `malicious`，`:711` 权重体系被旁路；手工规则 `triage/rules/webshell/curated_webshell.yar:44` 的 `severity = "critical"`、`:27` 的 `severity = "high"` meta 被忽略，而 `triage/rules/README.md:33` 称 meta severity "会影响命中权重"。规则条件过宽：`curated_webshell.yar:22-37`（`$eval and any of ($b64,$gz,$rot)`）、`:39-54`（`$class` 单独即可命中）；`triage/triage.py:664-669` 装了 yara 就默认加载 `triage/rules`，但 `triage/README.md:28` 把开关写成 `--rules-dir`；`triage/README.md:48` 唯一 semgrep 示例用 `--semgrep-config auto`（会联网拉 registry），与同文件 `:39`「不联网」冲突。
- **根因**：规则集的质量门只有"compile"；运行期失败不计数；严重度用名字猜而非 meta。
- **正面修复**：`validate_rules.py` 未装 yara 返回非零（或 `--require-yara`）；加正/负样本对（已知 webshell 必须出现 `yara.*`，良性文本不得出现）；`engines.yara = {import, rules_dir, rules_loaded, rules_failed, match_errors}`；严重度优先读 `match.meta["severity"]`，单条弱命中封顶 suspicious；宽规则加 `<?php` 锚点；README 写清"装了即默认加载"；semgrep 示例改 `triage/semgrep/webshell.yml` 或标注 `auto` 会联网。
- **影响面**：规则写错条件 → 编译 OK → 命中恒 0 → 线上样本判 clean；224 条生成规则全部 critical，弱命中直接 malicious（正常 PHP/JS/Java 源码误判）。
- 来源：TS-03 + PY-05 + PY-07 + PY-08 + PY-12。

### V-20 · high · Python 引擎"执行失败"与"未检出"同形，且"证书表存在"被当成"可信"
- **证据**：`triage/triage.py:512-515` `_run` 返回 `returncode` 但调用方丢弃；`:554-571` `engines["clamav"] = True` 在真正执行前置位，`rc` 不检查，无 "FOUND" 即 `{"signature": None}`（= 干净），异常只写 `info["clamav_error"]`；capa/semgrep/binwalk 同构。`:445-466` oletools 已安装但 `VBA_Parser` 解析异常被 `except: pass`（`:460-461`），与"无宏"不可区分；只有"库没装"才留痕。签名降级：`:307-312` `signed = bool(sec_dir.VirtualAddress and sec_dir.Size)`（不校验证书链/是否被篡改），`:713-722` `if signed and not has_strong: verdict = "clean"; score = min(score, 20)`，而 `has_strong` 只认 `yara./clamav./capa./semgrep./intel.` 前缀，`pe.inject_write`/`pe.inject_thread`/`pe.packed_section` 等 high 证据不算 → 恶意 PE 尾部追加任意 Authenticode blob 即可把 verdict 从 malicious 改写为 clean。
- **根因**：`engines` 只表达"库能 import"，不表达"引擎是否成功执行"；把"探测到的东西"直接当结论。
- **正面修复**：`engines` 拆 present/ok/error，`rc>1`/`TimeoutExpired`/空输出非零退出记为引擎失败，输出顶层加 `degraded: true / engine_errors: [...]`；xbits 侧对 `degraded` 的 completed 不当作"干净"（至少 `verdict_confidence: low`）；区分 `signed_present` 与 `signature_verified`，只有后者允许降级，且降级不覆盖 high/critical 证据（只降权不反转 verdict）；`oletools` 解析失败写 `info["oletools_error"]` + 低危 finding。
- **影响面**：病毒库缺失/过期/超时都显示"已用 ClamAV 检查且干净"；签名降级是一条可主动利用的绕过路径。
- 来源：PY-03 + PY-06 + PY-13。

### V-21 · high · 情报采集失败仍写"成功"快照并覆盖旧数据，退出码永远 0
- **证据**：`threat-intel/tools/collect.py:88-90`（CIRCL manifest 失败 WARN + `return`）、`:148-150`（iplist 失败 WARN + `return`）；失败源不写 `stat`（`stat[src["name"]]` 只在成功路径 `:142`/`:158`）；`:197` 以 `"w"` 截断写；`:265` `write_outputs(...)` 无条件覆盖 `data/` 与 `exports/`；`:272` `return 0`。现存证据：`threat-intel/data/meta.json` 的 `"feodo-tracker": {"ips": 1}`——C2 推荐阻断列表只落 1 条也记为成功，无最小产出量校验。`abusech-api` 是打印 SKIP 的空壳（`:161-162`）却登记进 `COLLECT_SOURCES`（`:165-169`）；`sources.json` 声明 `options.to_ids` 但代码写死 `:127 if a.get("deleted") or not a.get("to_ids")`。
- **根因**：把"抓取失败"降级成一行 stderr，用退出码 0 伪装成功；没有临时目录 + 原子替换、没有最小产出阈值、没有上一份快照。
- **正面修复**：每源返回 `SourceResult{ok, fetched, http_code, error, last_success_utc}`；写临时目录，只有"至少一个源成功且每源产出 ≥ 阈值"才原子替换；任一源失败非零退出并写 `status=failed` 进 `meta.sources`；保留 `meta.last_success_utc` 与上一份快照；`enabled 且 type 未实现` fail-fast 或写 `{"status":"unimplemented"}`；`to_ids` 从 opts 读取并校验未知选项。
- **影响面**：断网/被 410/被限流时等于把最后一份可用情报清空，而 triage / Suricata / xbits 三个消费方都只看这些文件，运维看到的是绿色。
- 来源：PY-01 + PY-02。

### V-22 · medium-high · allowlist 语义合并：`public_dns` 反向并入通用 `ip.txt`，DNS 基线可被"加一条普通白名单"关掉；配置 JSON 是装饰品
- **证据**：`allowlist/tools/refresh.py:84` `ips.extend(v for v in vals if v not in domains)  # 占位防重`——IP 字符串永不等于域名，该判断是跨类型死判断；`:92` 又把同一批单独写 `public_dns.txt`。实测：`allowlist/data/ip.txt` 与 `allowlist/data/public_dns.txt` **逐行完全相同**（各 15 行），`allowlist/custom/ip.txt` **不存在**，`meta.json` 记 `ip: 15, public_dns: 15`。消费侧：`intel.rs:146-152` 查两份本应正交的集合，`intel.rs:199-209` 基线判定 `!is_public_dns(dst) && !allowlisted_ip(dst)` → 任何 IP 进了通用 `ip.txt` 就不再触发 `public_dns_off_baseline`。配置装饰：`allowlist/sources.json` 无任何代码读取（grep 仅 `refresh.py:11` docstring 与 README），`type`/`enabled`/`path` 全部不生效；`refresh.py:100-102` `--check` 只打印计数后 `return 0`，不比对 `data/` 与 `custom/`；`threat-intel` 侧 `query.py`/`refresh.py` 校验规则亦不一致。
- **根因**：两套语义被合并进同一份文件却保留两套接口；"源清单"做成 JSON 给人配置驱动的印象，真正清单是 Python 字典。
- **正面修复**：`ip.txt` 只来自 `custom/ip.txt`，`public_dns.txt` 只由 `public_dns_servers.txt` 单向派生，禁止反向并入；基线判定只用 `is_public_dns`；`meta` 给"来源文件→输出文件"映射并断言不相交；让 `sources.json` 成为唯一真源（未知 type 报错）；`--check` 增加"custom 归一化结果 == data 快照"比对，不一致非零退出。
- **影响面**：DNS 基线信号可被一次普通白名单添加静默关闭；"加条目"实际是空操作。
- 来源：PY-09 + PY-10。

### V-23 · medium · 同一 IP 数据三套归一化，IPv6 永不命中（潜伏）
- **证据**：`allowlist/tools/add.py:57-62` 压缩式 `str(ipaddress.ip_address(...))`；`allowlist/tools/refresh.py:46-51` 展开式 `ip_address(v).exploded.lower() if ":" in v else v`；查询端 `allowlist/tools/query.py:60-73` 与 `xbits/src/intel.rs:19-30,146-152` 都只 `strip().lower()` 原文精确比较。
- **根因**：归一化逻辑分散在四层，无共享 `canonical_ip()`，也无"写盘前一致性"断言。
- **正面修复**：抽 `canonical_ip()` 在 add/refresh/query 共用，`intel.rs` 加载时同样归一（或加载成 `IpAddr` 比较）；`refresh --check` 增加"data 与 custom 归一化后一致"断言；补 IPv6 用例。
- **影响面**：`add.py add public_dns 2001:db8::1` 后 query 与 xbits 永远匹配不到；当前数据全是 IPv4，故为潜伏缺陷、零测试覆盖。
- 来源：PY-11。

### V-24 · medium · 文档与实现系统性不符：把"生成器输出"当"规则事实"
- **证据**：
  - `xbits/README.md:246-249`「当前规则库不存在此类规则（全部 17477 条都有可精确获取的具体 buffer）」——本次核对 `match_buffers.json` 的 `app_tx_lua` 恒为 false（**0 true / 17,477**），这是生成器 `build_match_buffers.py:185-190` 把 `lua` 从 buffers 剔除的必然结果，而同一份表在 `http.uri.raw` 上写错 buffer（V-12）。
  - `xbits/README.md:254-256`「超时按 fail-closed 处理…绝不丢事件」↔ `engine.rs:157-162` 静默剪枝（V-06）。
  - `规则检测/README.md:16` 仍称 `zeek/威胁情报/` 存在（实际 `规则检测/zeek/` 只剩 3 个行为脚本 + README，已核对）；`:19`/`:20` 仍宣传 `success_rules.json` 供 xbits 关联、`dead_rules.json` 已清理失效规则（V-14/V-15）；`:30`/`:42` 仍把 `convert_probe_zeek.py` 描述成"情报转换器"并给出重跑命令。
  - `规则检测/convert_probe_zeek.py:8-12` 声称"不再向 规则检测/zeek/ 输出任何数据脚本"，但文件仍保留 `OUT = ROOT/"zeek"`（`:26`）与三个 `mkdir`+`write_text` 生成器（`:50/55/138`、`:141/144/169`、`:172/175/186`），只是 `main()`（`:189-204`）不再调用；且主流程仍因一个它不读的输入目录失败（`:193-196` return 2）。
  - `规则检测/docs/规则质量QA数据.json` 仍收录已删除的 `zeek/威胁情报/{botnet_apps,public_dns_servers,white_domains}.zeek` 三段统计（文件内为乱码形式，本次按内容定位确认），而 `qa_rule_quality.py` 在 workflow 里 **0 引用**。
  - `threat-intel/README.md:26` 仍写 xbits"（规划中）…作关联置信度加权"。
- **根因**：文档断言直接引用生成器输出（循环论证）；删除动作只在部分文档收尾；删除产物仍留在"由 workflow 本应产出但从未产出"的 QA 数据里。
- **正面修复**：所有「全部 N 条都…」式断言必须指向一条 CI 断言或可复现命令；文档改为"由 X 生成、正确性由测试 Y 保证"并真的补上 Y；物理删除 `convert_probe_zeek.py` 的三个写盘函数与 `OUT`，保留的解析函数挪到独立模块；CI 加守卫断言 `规则检测/zeek/**/*.zeek` 文件集合 == 3 个行为脚本；把 `qa_rule_quality.py` 接进 `xbits-images` 并 `git diff --exit-code` 校验产物，或断言该 JSON 的 key 集合 == 实际 `.rules`/`.zeek` 文件集合。
- **影响面**：同一仓库三份文档三个说法，"删除是否彻底"失去可信来源；后来者按 README:42 重跑转换器会把目录重建。
- 来源：R-08 + R-09 + R-12 + TS-12。

---

## 二、需运行确认的疑点（Uncertain）

> 静态证据已足，但结论强度依赖运行时行为；建议在修复派单时一并安排验证。

| ID | 疑点 | 静态证据 | 需要什么才能定论 |
|---|---|---|---|
| U-01 | `cargo test` 是否确实编译失败（E0063） | `engine.rs:39-44` 新增字段 vs `analysis.rs:1177-1201` 缺 2 字段 | `cargo test --locked` 一次即可确认；若通过，说明存在本报告未见的构造路径/条件编译 |
| U-02 | 无 buffer 的 `lua:` 规则，Suricata 8.0.8 是否执行 Lua | 规则库自述 `DNS隧道与带外检测规则.rules:243-244`「不执行」 | 两条最小规则（带/不带 `http.uri;`）+ 同一 PCAP，脚本 `print` 到 stderr 观察 `match` 是否被调用 |
| U-03 | sticky buffer 顺序反转对命中率的实际影响（V-10） | 5,544 条统计成立；Suricata 语义为依据文档 | 每类 buffer 的构造 PCAP 回放（只在该 buffer 命中 / 只在其后位置命中） |
| U-04 | YARA 命中与误报的真实比例（V-19） | 224 条规则全 critical、条件过宽 | 装 yara-python 跑正/负样本对，统计 `yara.*` 命中与 verdict |
| U-05 | 生产/镜像部署下 triage 能否找到情报与规则目录（相关静态证据已并入 V-04/V-20） | `triage.py:677-686` 依赖 `threat-intel/data/` 与 `triage/rules/` 的仓库相对布局；`docker/xbits-suricata.Dockerfile:23-26` 无 python3、`:28-50` 无 triage/情报 COPY | 在 xbits-suricata 镜像内跑一次 `triage/triage.py --stdin`，观察 `engines.hash_intel`/`rules_loaded` |

---

## 三、误报剔除清单（Rejected + 反证）

| ID | 原表述（来源） | 判定 | 反证 file:line |
|---|---|---|---|
| X-01 | 「`测试用例/zeek_cases.json`（README 承诺）实际不存在，也无任何用例消费」（tests.md 第 6 点） | **部分 Rejected**：文件**存在**（691 字节，含 6 个 case）。"无消费者"属实 | `测试用例/zeek_cases.json`（`Test-Path` = True）；`测试用例/README.md:190` 只是"在该场景的测试目录中增加"的建议；全仓 grep `zeek_cases` 仅 README 与 findings 自身 |
| X-02 | 「`validate_rules` 未装 yara 时 `return 0` 导致 CI 假绿」（PY-12 原始怀疑） | **Rejected**：CI 在该步之前安装 yara-python，skip 分支不生效（残留风险仅限其他环境，已并入 V-19） | `.github/workflows/xbits-ci.yml:236` 先 `pip install yara-python`，`:237` 才跑 `validate_rules.py`；`triage/tests/validate_rules.py:11-15` 的 skip 在 CI 走不到 |
| X-03 | 「Suricata 规则转译存在 sid 冲突/重复」（rules.md 怀疑点 3） | **Rejected**：17,477 个唯一 SID，重复 0 | 本次独立统计（严格 `^\s*(?!#).*?\bsid\s*:\s*(\d+)\s*;`，51 个 `.rules`）：unique=17,477，dup_sids=0 |
| X-04 | 「Lua 用 `pcall`/`xpcall` 吞异常导致规则静默失效」（rules.md 怀疑点 4） | **Rejected**：49 个 `.lua` 中 `pcall`/`xpcall` **0 处**（真正的等价问题是 V-13 的无 buffer，已单列） | `规则检测/suricata/**/*.lua` 全文正则统计：`pcall_occurrences=0`，`lua_files=49` |
| X-05 | 「docker 与代码中的路径/文件名不一致（`/opt/xbits/filestore` 拼错）」（rust.md 怀疑点 6 的一部分） | **Rejected**：路径一致；真问题是"配了没人消费"（已归入 V-08/V-17） | `docker/xbits-suricata.Dockerfile:28` 创建 `/opt/xbits/filestore`；`docker/suricata-test.yaml:32` `dir: /opt/xbits/filestore`——同一路径 |

> 另有两处**证据需更正、结论仍成立**，不计入剔除：① rust.md 多处引用 `hook.rs:218-222` 的状态行，实际在 `hook.rs:213-217`；② rust.md R13 称 Dockerfile `:21` 创建 filestore，实际 `:28`。行号漂移不影响结论。

---

## 四、跨领域系统性问题

### S-01 · 新增根目录不进 CI 路径过滤（结构性问题，V-16 的元问题）
`paths:` 按"源码区域"手工维护，与被测脚本实际读取的资源清单完全脱钩：清单里的 `test_*` 读 `triage/`、`threat-intel/`、`allowlist/`，`xbits-ci.yml` 却只监听 `xbits/**`。**这不是某个 workflow 的疏漏，而是"触发条件"与"依赖清单"两处手工维护、没有一致性检查。** 建议加一条纯静态元测试（扫描 `qa_*/test_*` 里的仓库相对路径 → 断言被至少一个 `paths:` 前缀覆盖），把这种漂移挡在合并前。

### S-02 · 用生成器的输出给自己背书（循环论证）
`xbits/README.md:249`「全部 17477 条都有精确 buffer」的证据来自 `match_buffers.json`，而该表恰恰是 V-12 证伪的对象（`http.uri.raw`→`http.uri`）且 `app_tx_lua` 恒 false 是生成器剔除 lua 的必然结果（`build_match_buffers.py:185-190`）。同构问题见于 `规则检测/README.md:20`（`dead_rules.json` 恒 `[]` 却当卖点）、`规则检测/QA数据.json`（陈旧且无人重生成）、`triage/rules/REPORT.md`（"全部经 compile 校验"是唯一质量门）。**共性：把"生成/校验脚本跑过"当作"能力已验证"。**

### S-03 · "删除即完成"：能力从 A 处删除，在 B 处只写注释
三类同源样本：① flowbits 状态链 1,546 条从 Suricata 删除，文档写"交 xbits"，xbits 零实现（V-14）；② `zeek/威胁情报/` 目录删除，但生成器仍在、README 与 QA 数据仍引用（V-24）；③ 转换器把 `dangling-http-uri` 当"非法"整条剔除 2,073 条（V-10）。**共性：删除动作没有"接管方已具备能力 + 有测试"的验收门槛。**

### S-04 · 静默降级没有健康出口：`let _ =` / `except: pass` / `unwrap_or_default()` 集中在数据加载与审计通道
- Rust：`intel.rs:19-30`（情报读失败→空集）、`analysis.rs:331-350`（`match_buffers`/`sid_library` 解析失败→空表，抑制能力静默归零）、`analysis.rs:943-950`（审计写失败吞掉）、`analysis.rs:1154-1165`（提交失败忽略）、`engine.rs:157-162`（pending 静默剪枝）。
- Python：`triage.py:397-411`（YARA 编译失败丢弃）、`:460-461`（oletools 解析失败 `pass`）、`:496-508`（hash 情报读失败→空集）、`:554-571`（ClamAV rc 丢弃）、`collect.py:88-90/148-150`（源失败 WARN）、`refresh.py:54-57`（缺文件→空列表）。
- **共性**：这些点位的失败与"正常但为空"完全同形，且都落在**安全判定链路**上。建议统一引入"降级即计数 + 降级即暴露（stderr + 健康端点 + 输出字段）"的约定，并对这几处逐个做"故障注入"测试（删目录/坏 JSON/超时），而不是只测 happy path。

### S-05 · CI 与单测都只验证"能加载/能 import/能启动"
`suricata -T`（`xbits-images.yml:155-161,163-169`）、`zeek -b -Cr`（`:146-154`）、`yara.compile`（`validate_rules.py:24-35`）、`assertIn("pefile", engines)`（`test_triage.py:125/135/152`）、`grep -q` 子串（`xbits-ci.yml:70-73` 等）——全部是"进程退出码/子串/键存在"级别的断言。**这是本次 55 条发现里最高频的共同根因**：没有一条断言回答"命中语义是否改变"。正面方向：为每个引擎/规则集定义 1~2 个"正例必中 + 负例必不中"的判定，并把它接进 CI。

---

## 附：建议派单的修复任务拆分（按根因聚类）

> 仅作建议，供 captain 在用户确认后派单使用。每条可独立验收，标注依赖与预估。

| 簇 | 任务 | 覆盖条目 | 依赖 | 验收判据（可执行） |
|---|---|---|---|---|
| C1 情报闭环 | 让情报参与决策并进 ES 文档 | V-02, V-03, V-04, V-05 | 无 | 同一事件命中/未命中情报产出不同；ES 文档含 `intel`/`allowlist`；启动逐项打印条目数；`cargo test` 绿 |
| C2 状态机 | 统一 pending 超时语义 | V-06, V-08(阻塞部分) | C1 | "持续注入事件 + 时间推进"下过期告警仍被处理；pending 有上限与指标 |
| C3 可观测 | 审计/ES 单通道失败可见 + 线程存活 | V-07 | 无 | 删权限/磁盘满时 stderr + 健康状态 fail；坏 `file_sha256` 不 panic；分析线程可重建 |
| C4 文件 triage | 阶段语义与进程管理 | V-08 | C3 | `timeout`/`bad-json`/`stored=false` 三态可区分；孙进程被杀；端到端断言 status 链 |
| C5 规则语义 | 转译器 buffer 语义树 + 语义回归 | V-10, V-11, V-12, V-13 | 无 | 5,544→0 条后置 buffer；17 条 stat_code 规则修正；15 条 raw 元数据修正；`lua:` 无 buffer == 0；PCAP 正/负例回归进 CI |
| C6 关联能力 | flowbits/depend 二选一落地 | V-14, V-15 | C5 | `success_rules.json` 有消费者并有配对断言，或规则回流 Suricata；`semantic_gaps` 有 diff 契约 |
| C7 CI 触发 | paths 一致性 + 元测试 | V-16, S-01 | 无 | 改 `triage/**`、`threat-intel/**`、`allowlist/**` 均触发对应 job；元测试能抓"新增目录未进 paths" |
| C8 测试真实性 | 替换弱断言与自造夹具 | V-17, V-18, V-19 | C5/C7 | 覆盖门禁打印 `74/17477 + excluded`；hook 矩阵 `set==require`；无 `sleep`+`grep` 断言；YARA 正/负样本必中/必不中；双空用例被拒绝 |
| C9 Python 判定 | 引擎失败≠未检出 + 签名降级 | V-20, V-22, V-23 | 无 | `engines` 拆 present/ok；`degraded` 透出；`signed_present`≠`signature_verified`；IPv6 归一化用例 |
| C10 数据/文档 | 采集原子化 + 文档断言可验证 | V-21, V-24 | C6 | 源失败非零退出且保留旧快照；README 的"全部 N 条"均指向 CI 断言；`zeek/` 文件集合守卫 |

**优先级建议**：C1（blocker，且是本次最核心"表面完成"）→ C3/C4（安全链路静默，影响可观测性）→ C5/C6（检测能力净损失）→ C7/C8（假绿，决定后续所有结论可信度）→ 其余。

---

## 修复后状态（截至第十三轮 C5/C6 收口，由 t50 补录）

> 本节**只记录状态**，不修改上方任何原始发现正文。Verifed 结论按 `qa/FIX_REVIEW.md` 各轮次与
> 已完成修复任务的 output 采信；commit 为本地 `git log --oneline` 可见的修复提交
> （工作区改动尚未全部提交，标注"工作区"者以当前文件为准）。CI 实跑按依赖结果（commit `1374b4d` 双绿）采信。

### V-10 ~ V-24 状态表

| 编号 | 状态 | 修复任务 / commit / 复核轮次 | 说明 |
|---|---|---|---|
| V-10 | **Verified** | t35 C5-A（`7c4c752` 语义树转换）+ t38 C5-D 对称棘轮 + t46/t48 端口方向（`1374b4d`）；第十二/十三轮复核 | 5,544 条后置 buffer 反转已修、活动场景目录 0 违规、`dangling-http-uri` 消失。残留 R12-2（676 处 `content;buffer`，已锁为棘轮基线，不影响活动检测）见待修清单。 |
| V-11 | **Verified** | t35（`7c4c752`）stat_code 段前置 + 容量断言；第十二轮 | 17 条"永不命中"规则已修，抽样 5 条均为 `http.stat_code; content:"200"; pkt_data; …`。 |
| V-12 | **Verified** | t36 C5-B（`6442408`）共享 `buffer_aliases.json` 单一真源；第十二/十三轮 | 15 条 `http.uri.raw` 保真，Python 17 例含 SharedAliases 契约全过。 |
| V-13 | **Verified** | t37 C5-C（`7c4c752` 起 lua 前置 + t50 前 979 条处置）+ t48 PCAP 18 文件；第十二/十三轮 | `lua:` 且无 buffer == 0；946 条无法定位者剔除 lua（保留纯 content），33 条补 buffer。 |
| V-14 | **Verified** | t39 C6-A + t40 C6-B（`3ce9521` cid-scoped 配对）；第十二/十三轮 | `success_rules.json` 已真实消费、cid 入 key、发告警才登记、同 key 多 sid。R13-2 已于本轮补 `benign`/`min_confidence` 预检（见下）。 |
| V-15 | **Verified** | t37 C5-C + t38 C5-D + t40；第十二轮 | 18 reason 全有 owner/tested_by（后扩至 17 reason，见当前工作区）、未知 reason fail-fast、dead_rules 空转链路已删。R12-5 文档残留见待修清单。 |
| V-16 | **Verified** | C7（`52fd837`）paths 覆盖 + 元测试；第四轮 | 7 个 workflow push==PR，triage/threat-intel/allowlist 与测试资源进 paths；元测试对抗 3/4 通过（`os.path.join` 动态路径盲区已记录）。 |
| V-17 | **Verified** | t25 C8（`dcaae21`）覆盖门禁重写；第八轮 | `covered 74/17477 + excluded 11 dirs` 与磁盘一一对应，未分类目录/列表腐烂即 FAIL。 |
| V-18 | **Verified** | t25 C8（`dcaae21`/`bb5e1c7`）弱断言替换；第八轮 | 5 处 sleep+grep 改 `assert_hook_output.py` 轮询+字段+exit/stderr；双空用例直接 FAIL。 |
| V-19 | **Verified** | t25 C8-5 + t28/t29/t31/t33（YARA 三态·编译失败·stat 失败·缓存）；第八～十一轮 | PE/ELF 值断言、YARA 正负样本对、缺 yara 非零退出；`failed_files`/`unreadable_errors` 入 `engine_status`，stat 失败不崩、失败态不滞留缓存；triage 单测 32 例 OK。 |
| V-20 | **Verified** | t26 C9（`dcaae21`）engines 三态 + 签名拆分；第八轮 | `engine_status{tool}={present,ok,error}` + `degraded/engine_errors`；`signed_present` 存在性探测 ≠ `signature_verified`（恒 False），伪证书不洗白。 |
| V-21 | **尚未修复** | — | 采集失败仍 WARN+`return 0`，`write_outputs` 无条件以 `"w"` 覆盖 `data/` 与 `exports/`，无最小产出阈值/原子替换/旧快照保留。影响：断网即清空最后一份情报而运维看到绿。见 `qa/findings/python.md` PY-01。 |
| V-22 | **尚未修复** | — | `refresh.py:85` `ips.extend(v for v in vals if v not in domains)` 跨类型死判断仍把 public_dns 并入通用 `ip.txt`；`sources.json` 仍无代码读取；`--check` 仍不比对 `data/`。DNS 基线可被一次普通白名单静默关闭。见 PY-09/PY-10。 |
| V-23 | **Verified（Python 侧）** | t26 C9（`dcaae21`）`allowlist/tools/ipnorm.py` 单一 `canonical_ip()` + 8 例单测；第八轮 | add/refresh/query 三端共用、zone 拒绝、端到端 IPv6 命中。**残留**：`xbits/src/intel.rs` 加载时 IP 归一（Rust 侧）未在本批改动内，IPv6 事件在 xbits 侧命中仍需确认。 |
| V-24 | **Partially（文档收口未完）** | V-14/V-15 相关表述已在 t39/t40 更新；R12-5/R12-6/R12-7 仍未修 | `规则检测/README.md:22` 仍称 `zeek/威胁情报/` 存在；`xbits/README.md` §8.2（`:389-420`）与 §10（`:456-490`）success_rules 两处重复；PCAP 每类 buffer 仅 1 对。 |

### 尚未修复项索引（按 ID，来源：第五～十三轮 verifier 复核）

| ID | 状态 | 一句话 | 归属 |
|---|---|---|---|
| R5-4 | **尚未修复** | `threshold > score` 无加载期校验（only 文档+单测约束） | 引擎规则加载 |
| R5-5 | **尚未修复** | 引擎计数仅故障消息导出，无 metrics/周期快照 | 可观测 |
| R5-6 | **尚未修复** | degraded+intel 同现时 `reason` 取 intel，需并读 degraded | 可观测 |
| R6-2 | **尚未修复** | hook listener/read_timeout/维护节拍无 Unix socket 集成测试 | 测试覆盖 |
| R6-3 | **尚未修复** | accept 持续连接可饿死无连接侧维护 tick | 状态机 |
| R6-4 | **尚未修复** | pending 单行长度无上限（无换行超长数据占内存） | 健壮性 |
| R8-4 | **尚未修复** | semgrep JSON `errors[]` 仅写 info，rc≠0 带 errors 仍 ok=True | Python 判定 |
| R8-5 | **尚未修复** | `engines[tool]` 语义从"已安装"变"present and ok"的迁移提示不足 | 文档 |
| R8-6 | **尚未修复** | `assert_hook_output.py` 坏 JSON 行静默跳过（报 "0 matched" 而非"行损坏"） | 测试可观测 |
| R9-2 | **尚未修复** | `known_extra` 可抵扣场景内未声明命中，仅要自由文本 reason | 测试断言 |
| R9-3 | **尚未修复** | 8 处新增 require 无逐条"为何应命中"语义说明 | 测试文档 |
| R9-4 | **尚未修复** | 对照门禁静态、单看 forbid 负例无法区分"规则没加载" | 测试断言 |
| R9-5 | **尚未修复** | strict 模式 PASS 文案仍提示"未启用 strict-warnings"，易误读 | 测试文案 |
| R11-1 | **尚未修复** | YARA 缓存键不覆盖跨目录 include（当前 triage/rules 未用，风险低） | 缓存 |
| R12-2 | **尚未修复（已接受基线）** | 676 处 `content;buffer` 后置写法仍在转换规则库；已锁为棘轮基线 | 规则语义 |
| R12-4 | **尚未修复** | 关联计数未进 hook 故障消息；响应无等待路径无输出 | 可观测 |
| R12-5 | **尚未修复** | `规则检测/README.md:22` 仍称 `zeek/威胁情报/` 存在（实际不存在） | 文档 |
| R12-6 | **尚未修复** | `xbits/README.md` success_rules 两处重复章节（§8.2/§10） | 文档 |
| R12-7 | **尚未修复** | PCAP 每类 buffer 仅 1 对正负例（建议 2~3） | 测试覆盖 |
| R13-1 | **已修复（t51 / tests-auditor）** | `check_rule_pcap_bytes()` 按 SID 读规则原文与 PCAP 载荷做运行时断言（buffer/flow/content hex/pcre/URI），pos 必含 neg 必缺；接在 `--generate`/`--eve-root` 前；负例（改坏 PCAP、改坏规则）均 FAIL 点名 SID | 测试真实性 |
| R13-2 | **已修复（本轮）** | `engine.rs:829-844` `emits_alert` 预检已纳入 `benign`/`min_confidence`，与 `make_alert_full` 同口径；补测 `correlation_wait_not_registered_for_benign_or_below_min_confidence` | 关联状态机 |
| R13-3 | **已修复（本轮）** | 本节 + `xbits/README.md` §11 全量清单即为该项修复 | 文档 |

> 说明：R8-1/R8-2/R8-3/R9-1/R10-1/R12-1/R12-3 等已在对应轮次 Verified（见 `qa/FIX_REVIEW.md`
> 第八～十一、十三轮），故不在本"尚未修复"索引内；上表只列第十三轮复核确认仍在的项。

---

## 核验边界声明

1. 本报告所有行号以当前工作区文件为准；`root` 下 `qa/findings/*.md` 由各审计员写入，本报告未修改任何源码或 findings。
2. 行号存在个位数漂移的两处已在 §三 末尾标注（不影响结论）。
3. 所有"重算"均基于只读脚本（正则/字节统计），未执行构建与测试；因此涉及运行时行为的条目归入 §二 Uncertain。
4. 本次未核验的输入：四份 findings 之外的任何声明。若 captain 有额外怀疑点，需另行派单。
