# xbits · Suricata → Zeek 事件级联动

`xbits` 是本仓库自研的跨引擎联动组件，目标不是把 Suricata 告警写进文件再让 Zeek 读日志，而是把 **Suricata 规则/Lua 已经确认的告警事件** 直接推进 Zeek 事件循环，由场景 Zeek 脚本在同一进程内做状态关联。

## 1. 数据路径

```text
Suricata 8.0.8
  eve-log: filetype=unix_stream (client connect)
        │
        ▼
  xbits (Rust, UnixListener，本组件)
        │  过滤 event_type=alert，规范化为 JSONL
        ▼
  stdout
        │
        ▼
Zeek 9.0.1 Input::READER_RAW / STREAM
        │  from_json → Xbits::suricata_alert(rec)
        ▼
  场景 Zeek 脚本（xbits_correlate.zeek 或各场景脚本）
```

关键点：

- **Suricata 是 Unix socket 的客户端**，不是监听端。Suricata 8.0.8
  `src/util-logopenfile.c` 中 `SCLogOpenUnixSocketFp()` 对
  `filetype: unix_stream` 执行 `connect()`；因此 `xbits` 必须调用
  `UnixListener::bind()` 并提供监听端。若把 `xbits` 写成客户端，两边都会
  `connect()`，链路无法建立。
- xbits 只输出 Suricata `alert` 事件，不落盘、不读取 `eve.json`。
- Zeek 通过 `Input::add_event` 的 raw execute/stream 模式启动 xbits；
  xbits 的每一行 stdout 立即触发一个 Zeek 事件，不依赖 Community ID 日志
  join，也不依赖文件轮转延迟。
- Community ID 仍会随事件携带，供 Zeek 与自身的 `new_connection` /
  `http_request` / DNS 事件做内存关联。日志中保留 `community_id` 是
  **关联键**，不是事后日志拼接。

## 2. 组件

```text
xbits/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml             # 1.85.0，CI 精确锁定
├── src/lib.rs                      # EVE 解析 / 过滤 / socket listener
├── src/main.rs                     # CLI：--socket / --stdin / --once
├── testdata/alert.jsonl            # 合成 EVE 正例 + 非 alert 反例
├── testdata/suricata-unix-stream.yaml.in
├── test/assert_xbits.py            # CI 断言（不是检测逻辑）
└── zeek/
    ├── xbits_suricata.zeek         # Input raw → Xbits::suricata_alert
    ├── xbits_correlate.zeek        # 内存关联 + xbits_correlation.log
    ├── xbits_test.zeek             # CI：stdin 注入测试
    └── xbits_live.zeek             # CI：真实 Suricata socket 端到端
```

## 3. Suricata 配置

生产/联调时把 EVE 输出切到 Unix stream：

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /var/run/suricata/eve.sock
      community-id: true
      community-id-seed: 0
      types:
        - alert:
            payload: yes
```

启动顺序：

1. 先启动 `xbits`，让它 bind `/var/run/suricata/eve.sock`；
2. 再启动 Suricata。Suricata 首次连不上时会继续尝试；xbits 停止或重启期间
   Suricata 也会重连。

```bash
install -d -m 0750 /var/run/suricata
/usr/local/bin/xbits --socket /var/run/suricata/eve.sock
```

`--stdin` 只用于 CI/离线验证：从 stdin 读 EVE JSONL，不 bind socket。

## 4. Zeek 接入

在 Zeek 9.0.1 中加载：

```bash
zeek -b -Cr trace.pcap \
  /path/to/xbits/zeek/xbits_correlate.zeek \
  LogAscii::use_json=T
```

`Xbits::command` 默认是：

```zeek
global command: string = "xbits --socket /var/run/suricata/eve.sock" &redef;
```

现场用 `redef Xbits::command = "/usr/local/bin/xbits --socket ...";` 覆盖。
Zeek 的 raw Input reader 会在 source 末尾追加 ` |`，通过 `/bin/sh -c`
启动该命令并持续读取 stdout。

`xbits_correlate.zeek` 当前演示：

- 每收到一个 Suricata alert，按源 IP 累加 `host_score`；
- 记录 `last_signature`；
- 在 `new_connection` 中建立 `community_id → uid` 映射；
- 后续 `http_request` 命中同一主机时输出 `alert_then_http`；
- 写 `xbits_correlation.log`，字段包含 `signature_id`、`community_id`、
  `uid`（可用时）、`score`、`reason`、`scenario`、`related_sids`。

各业务场景应把 `Xbits::suricata_alert` 接到自己的状态机上，而不是复制一份
日志关联脚本。

## 5. 构建与运行

```bash
cd xbits
cargo fmt --check
cargo test --locked
cargo build --release --locked
./target/release/xbits --help
```

版本固定为 Rust 1.85.0（`rust-toolchain.toml`），依赖由 `Cargo.lock` 锁定。

## 6. CI 验证点

`.github/workflows/xbits-ci.yml`：

1. **Rust**：`cargo fmt --check`、`cargo test --locked`（含 mock UnixListener
   端到端）、`cargo build --release --locked`。
2. **Zeek stdin 事件链**：Zeek 9.0.1 容器加载 `xbits_test.zeek`，
   `xbits --stdin` 注入合成 EVE，断言 `xbits_correlation.log` 中出现
   `signature_id=9103001`、`reason=suricata_alert`、`scenario=xbits-cross-engine`。
3. **真实 Suricata → xbits → Zeek（四个场景）**：
   - 编译 Suricata 8.0.8；
   - Suricata 使用 `unix_stream` 输出，分别处理 DNS `txt_burst_positive`、
     侦察 `recon_404_burst`、Web `web_sqli_uri_union`、
     后门 `ws_cmd_query` 四个 PCAP；
   - Zeek 容器内运行 `xbits_live.zeek`，由 xbits 监听 socket；
   - 分别断言 Zeek `xbits_correlation.log` 中的
     `9109103` / `9101109` / `9103001` / `9104002`。
4. 上传 `xbits_correlation.log`、Suricata `eve.json`/日志与测试输出作为
   Actions artifacts。

当前状态：**已验证（GitHub Actions）**。代码提交 `c4f81d5` 的
workflow run `42455328044` 三项 job 全部通过：

- Rust bridge tests and release build：success；
- Zeek 9.0.1 event bridge (stdin)：success；
- Suricata 8.0.8 → xbits → Zeek 9.0.1 live linkage：success。

真实链路四个场景的 `xbits_correlation.log` 断言全部通过：

| 场景 | PCAP | 断言 SID |
|---|---|---|
| DNS | `txt_burst_positive.pcap` | 9109103 |
| 侦察 | `recon_404_burst.pcap` | 9101109 |
| Web | `web_sqli_uri_union.pcap` | 9103001 |
| 后门/WebShell | `ws_cmd_query.pcap` | 9104002 |

例如 DNS 场景的 Zeek 日志：

```json
{"ts":1700000049.01,"uid":"CBsQ8LiAFiKCOYfx2","community_id":"1:QGQnO1vyClpNi8cBuyLHmbBC6So=","signature_id":9109103,"signature":"[DNS隧道-配套] TXT 查询突发(线索级)","src":"10.0.0.5","dst":"10.0.0.53","score":10,"reason":"suricata_alert","scenario":"xbits-cross-engine","related_sids":[9109103]}
```

这证明告警来自 Suricata 8.0.8 的 `unix_stream` 输出，经 xbits 进入 Zeek
事件循环并落为日志；不是离线日志 join。这里的“已验证”仅指链路运行和
测试断言，不代表生产“零误报”。

## 7. 边界与运维

- 只传输 `event_type=alert`；flow/http/dns 原始事件仍由 Zeek 自己解析，
  避免重复和放大。
- xbits 中央引擎负责规则匹配、上下文关联、误报判断和置信度输出；检测语义仍由 Suricata 规则/Lua、Zeek 场景脚本和 xbits analysis rules 共同定义。
- 同一 uid 的事件不保证跨进程顺序完整；Zeek 关联应使用内存表并允许
  事件晚到/缺失。
- stdout 是背压边界：Zeek 读取慢会阻塞 xbits，进而影响 Suricata socket
  写入；生产需监控 xbits 进程和 Zeek `Input` 队列。
- Unix socket 只允许本机访问；目录权限应由部署方限制，不能暴露到网络。
- `xbits` bind 后会把 socket 权限设为 `0666`，以便 Suricata 以不同用户
  连接；环境必须用父目录权限（如 `0750` 且属主为采集用户组）限制访问。
- 生产使用 `xbits --socket ...` 长驻监听；`--once` 只用于 CI/单次回放：
  接受一个 Suricata 连接，读到 EOF 后退出并删除 socket。
- 本组件不兼容其他 Suricata/Zeek 版本，只针对 8.0.8 / 9.0.1。

## 7.1 深度分析流水线（可选）

Hook 事件可以在 `--hook-socket` 模式下进入异步分析流水线：

```bash
xbits --hook-socket /var/run/xbits/hook.sock \
      --rules xbits/rules/analysis.json \
      --sid-library /opt/xbits/analysis-rules/sid_library.json \
      --rules-meta /opt/xbits/analysis-rules/rules_meta.json \
      --validator-cmd 'python /opt/xbits/tools/validate.py' \
      --es-url http://127.0.0.1:9200/xbits-events/_doc \
      --analysis-file /var/log/xbits/analysis.jsonl \
      --match-buffers /opt/xbits/analysis-rules/规则库元数据/match_buffers.json \
      --suppression-ttl-sec 300
```

- `--validator-cmd`：接收一行 JSON（event/alert/metadata/payload），输出
  `{"verdict":"true_positive|false_positive|uncertain","confidence":90,"reason":"...","evidence":["..."]}`；
  validator 的 `reason` 记入分析文档 `xbits.validator_reason`，**不覆盖** `reason` 里的情报决策依据（`intel-*`）；
- `--es-url`：直接 HTTP POST 到 Elasticsearch（当前实现支持 `http://`）；
  `--es-auth` 可传 `ApiKey ...` 或 `Basic ...`；
  `--es-command` 可接 `curl` 等命令，支持 HTTPS/认证；
- `--analysis-file`：同时落一份归一化 JSONL，便于回放；
- `--match-buffers`：按 SID 加载规则实际匹配的 buffer，
  由 `规则检测/build_match_buffers.py` 生成；
- `--suppression-ttl-sec`：xbits 内存抑制 TTL，默认 300 秒。

**文档 sink 是硬性要求**：只要启用了任一分析选项，就必须至少配置一个文档去向
（`--analysis-file` 和/或 `--es-url`/`--es-command`），否则启动直接失败并返回非零退出码——
不会"照常运行但把文档丢掉"。

**失败必须可见（可计数 / 可探测 / 可失败）**：

- 审计文件打开/写入失败、文档序列化失败、ES 推送失败都会写 stderr 且计入 `document_errors`；
- 没有 sink 可写的文档（未配 `--analysis-file` 时的被抑制告警与 `file_triage` 各阶段）
  会写入 stderr 并计入 `documents_without_sink`（启动时另有告警）；
- `--match-buffers` / `--sid-library` / `--rules-meta` 读取或 JSON 解析失败会写 stderr
  并计入 `config_errors`（不再静默成空表、让抑制能力归零而无任何信号）；
- 分析线程 panic 会把流水线标记为不可用（记录 panic 原因），入队连续失败 3 次同样标记；
  hook listener 探测到不可用后立即以非零退出，而不是静默停摆。
- 文件静态 triage 运行在独立的 `xbits-triage` worker 线程（有界队列 64）：外部命令
  （默认 30s）不再阻塞告警判定与 pending 超时；队列满时丢弃并计入 `triage_dropped`
  且落一条 `failed(triage-queue-full)` 文档；超时计入 `triage_timeouts`，并杀掉
  整个进程组（含孙进程）。失败形态（timeout / 非零退出 / 坏 JSON / stored=false /
  找不到文件）在 `file_triage` 文档的 `xbits.note` 里逐项区分，详见 `triage/README.md`。
- 文件情报链路（单一数据源）：triage 的 stdin 请求会带上引擎在进 triage 前算好的情报标注
  `{"intel": {"threat": [{type, value}...], "allowlist": [...]}}`（来自 `engine.intel_annotations`，
  triage 在 `--stdin` 下不读本地名单）。**文件 hash 命中威胁情报时一定会推 ES**：
  `completed` 即使 triage 判 `clean` 也推，并在文档标记 `xbits.intel_conflict=true`，
  `xbits.verdict` 以情报为准（`malicious`）、原始 triage 结论保留在 `xbits.triage_verdict`；
  `failed`/`skipped` 阶段命中同样推 ES，避免已知恶意文件被超时/类别跳过静默丢弃。

**白名单只在 xbits 内部生效**：

```text
source + SID + 五元组 + 该 SID 声明的匹配 buffer 值
```

误报判定后写入 xbits `SuppressionStore`，后续相同 key 的事件在写 ES 前被丢弃；
不会向 Suricata/Zeek 发送任何 dataset、pass 规则或规则重载命令。
被抑制事件只写审计文件，不写主 ES 索引。

White-list key 由 `xbits/src/analysis.rs` 的 `suppression_key()` 生成；
`match_buffers.json` 告诉 xbits 该 SID 应取 `payload`、`http.uri`、
`http.request_body`、`dns.query` 还是其他 buffer。优先使用 Suricata 核心补丁导出的
`match_context` 事件（完整 sticky buffer Base64）；EVE/Zeek 字段只作为回退。
buffer 取不到时**不建立抑制 key**，避免拿错字段做白名单。

Context-only buffer（`lua`、`http.header`、`file.data`、`http.uri.raw`、
`dns.rrtype`、`tls.alpn`、`http.cookie` 等）在 EVE/Zeek 中没有精确等价字段，
**只接受 match_context 导出值**，任何近似值都不会兜底。

`match_buffers.json` 由 `规则检测/build_match_buffers.py` 生成。`lua:` 是脚本挂载点，
**不是数据 buffer**，绝不参与 key：生成器先剥离 `lua`（`build_match_buffers.py:217-228`
显式跳过 `lua`，不让它先占位 buffers），再按规则实际匹配的数据面归类——
有具体 sticky buffer（`http.uri`/`file.data`/`http.header`…）用该 buffer；只有
`content`/`pcre` 而无声明的落到 `payload`（报文精确字节）。因此带 `lua:` 的规则
同样是**可精确抑制**的 `payload`/sticky buffer 规则，而不是"无 buffer 可导出"。

只有当规则既无具体 buffer、也无 `content`/`pcre`、仅挂 `lua` 时，才标记
`app_tx_lua: true`：这类真·纯 Lua 规则在 C 层没有单一精确 buffer 可导出，
**不参与抑制**（每次告警仍走 validator；xbits 记录一次说明日志）。

当前产物实数（**以生成物为准，非写死**；由 `规则检测/build_match_buffers.py` 生成）：
活跃规则 **19,447** 条（`规则检测/xbits/规则库元数据/match_buffers.json` 条目数），
其中 `app_tx_lua: true` **0** 条、挂 `lua:` 脚本的规则 **6,094** 条（均有具体 sticky buffer
或 `payload`，因此都可精确抑制）。这两个计数由生成器判定逻辑决定（`build_match_buffers.py`
的 `lua` 跳过分支与 `app_tx_lua` 分支）；CI 断言的是语义与一致性：
`qa_converter_semantics.py`（产物 SID 总数 == `match_buffers.json` 条目数、`lua:` 规则必带
sticky buffer == 0、buffer 顺序棘轮基线）与 `qa_xbits_match_context.py --production-meta`
（生产元数据与 Rust 侧 context-only 契约一致）。
规则重生后数字会变，请读产物而非沿用本段示例值。

> 早期版本曾把 `lua` 当成 buffer 抢先占位、丢掉 `content` 匹配的 `payload`，
> 导致 919 条规则被误标为 `app_tx_lua` 而无法抑制。现已按上述逻辑根治。

跨 socket 顺序：`match_context` 与 `alert` 来自不同连接、到达顺序无保证。xbits 对
声明了 context-only buffer 的告警在缺 context 时短暂挂起（默认 500ms，`--pending-context-ms`
可调），context 到达即判定。

**挂起/过期语义（与实现一致，不承诺"绝不丢事件"）**：

- 分析层（等 `match_context` 告警）：过期判定与消息处理解耦——每轮循环（含持续有流量、
  `recv` 不超时的情况）都会扫描一次，过期即**立即 fail-closed 判定**（不建 key、不抑制），
  计数 `pending_expired` 并打日志；pending 有容量上限（`PENDING_LIMIT`，默认 1024），
  达到上限后的新告警**立即 fail-closed 判定**并计数 `pending_overflow`（限流日志）；
- 引擎层（`require_context` 规则等 Zeek 上下文）：挂起超过 TTL **不再丢弃、也不再只是计数**，
  而是按 fail-closed 产出一条**降级告警**——`degraded=context-missing`、`reason=context-missing`、
  evidence 写明"上下文始终没到"，随正常告警一起写 stdout 并进入分析流水线（`xbits.degraded`）。
  引擎侧计数为 `pending_expired`；**待处理队列满时**同样产出可见降级告警（`degraded=pending-overflow`）
  并计数 `pending_overflow`，不再只计数/打日志。
  降级告警是"无法判定"的可见事实，**不套用规则的 `min_confidence`**（它始终带 `degraded` 标记）。
- **边界（已知限制，见 §11）**：维护节拍与半行缓冲已有真实 UnixStream 单测（R6-2 部分覆盖：
  `long_connection_still_runs_maintenance_tick`、`serve_stream_survives_overlong_line_and_processes_next_event`），
  剩余缺口为 listener 外层 accept 轮询/空闲维护的端到端断言。半行缓冲本身有**单行上限**
  （`MAX_LINE_BYTES = 1MiB`，R6-4）：超限整行丢弃并计数 + 限流 stderr（首次必打、之后每 1000 行
  汇总），连接继续服务后续行，不会因无换行超长输入无限占内存。
  因此这里只承诺"挂起有界、超时/溢出可见降级、计数可观察"，**不承诺"绝不丢事件"**。
- **维护与事件到达解耦（R5-1 / R6-3）**：hook listener 用 `read_timeout(200ms)` 读取已连接 socket，
  并对 accept 做非阻塞轮询（空闲 20ms、按 200ms 节流维护）；服务单连接期间，读取循环**每次迭代都检查
  一个维护截止时间**——即使客户端持续有数据（`read` 永不超时），也按 200ms 执行 `engine.maintenance()`
  （过期降级告警照常写回输出并投递流水线）。因此无论流量停止、还是长连接持续写入，挂起告警都会按 TTL
  触发降级输出与计数。读取使用**半行缓冲**（带单行上限），超时/分段读取都不会丢半行 JSON；
- 引擎其它 TTL/容量治理同样可见：过期 context / 累计分分别计数 `contexts_expired`、`scores_expired`；
  累计分表超容量上限（`MAX_SCORES`）**只淘汰最旧条目**（不再整表清空），计数 `scores_evicted`；
- 两层计数都会出现在 hook listener 的故障消息里，为避免同名混指，引擎层一律加 `engine_` 前缀导出：
  `engine_pending_expired` / `engine_pending_overflow` / `engine_contexts_expired` /
  `engine_scores_expired` / `engine_scores_evicted`（分析层则是 `pending_expired` / `pending_overflow`）；
  关联计数是例外（R12-4）：故障消息里按 `correlated_pairs` / `correlation_timeouts` /
  `correlation_overflow` / `correlation_unmatched_responses` 导出，取引擎侧权威值（分析层
  `PipelineHealth` 只是同源镜像，避免同步滞后导致读数不同）。

**累计分窗口（R4-2 / R5-3）**：累计分按 `group_by` 分组、窗口内累计，窗口从最近一次命中开始滑动；
默认窗口与事件 TTL 相同（60s）。同一 `group_by` 被多条规则共享时，**窗口取单调最大值**——
短窗口规则不会把长窗口规则已累积的分提前清掉（长窗口优先；条目仍按最近命中时间滑动）。
`threshold > score` 的慢速累积规则必须在规则里显式声明
`score_window_sec`（例如 `"score_window_sec": 3600`），否则事件间隔超过默认窗口时累计分会被清掉、
**永远不会达标**；`threshold == score` 的规则单事件即可达标，无需窗口。该约束现在**在加载期强制**
（R5-4/R15-4）：`xbits --rules` 加载时若发现 `threshold > score` 且未声明 `score_window_sec`，或
`score_window_sec` 为 **0**（0 秒窗口会让累计分立即过期，不是合法值），直接非零退出并在错误里点名
rule id 与相关数值（`model.rs::validate_rules`；0 修法：删字段用默认 TTL 或给正整数秒），不再等
运行时靠 `scores_expired` 间接察觉。窗口过期计数 `scores_expired`（导出为 `engine_scores_expired`），
超容量淘汰计数 `scores_evicted`（导出为 `engine_scores_evicted`），见 `engine.rs` 的
`score_for`/`prune_at`。

`--fp-confidence N` 是误报入白名单的置信度门槛：仅当 validator 明确判定
`false_positive` 且置信度 ≥ N 时才写入抑制 key，避免低置信误报误杀后续真实威胁。

EVE 需要开启 payload：

```yaml
eve-log:
  types:
    - alert:
        payload: yes
        payload-buffer-size: 16kb
```

否则分析器只能拿到告警元数据，不能做 payload 特征验证。

## 8. 中央分析引擎（薄 hook 平面）

在原有 EVE 桥之外，`xbits` 新增 `--hook-socket` 模式：接收 **Suricata/Zeek 进程内薄插件**
推送的 JSONL 事件，在中央引擎做统一上下文/规则/评分，再把命中告警输出为 JSONL
（继续由 Zeek `Input::READER_RAW` 消费；告警最终仍由 `XbitsAlert` 输出）。

```bash
# 1) 启动中央引擎（hook 平面；default.json 仅兼容旧测试，生产用 analysis.json）
xbits --hook-socket /var/run/xbits/hook.sock --rules xbits/rules/analysis.json

# 2) Suricata 薄插件：plugins: xbits-suricata-hook.so
#    环境变量 XBITS_HOOK_SOCKET 指向同一 socket

# 3) Zeek 薄插件：
#    ZEEK_PLUGIN_PATH=$PWD/xbits/zeek-plugin
#    ZEEK_PLUGIN_ACTIVATE=Xbits::Hook
```

事件 schema（节选）：
```json
{"source":"suricata","kind":"alert","sid":9103001,"signature":"SQL 注入","src":"1.1.1.1","dst":"2.2.2.2","sport":40001,"dport":80,"proto":"TCP"}
{"source":"zeek","kind":"event","event":"http_request","desc":"..."}
```

规则文件为 JSON 数组（`xbits/rules/analysis.json` 为生产示例，`default.json` 仅兼容旧测试），支持
`source/kind/proto/signature_contains/sid_in/event/desc_contains/method/group_by/score/threshold/reason`。

**运行期统计（R5-5）**：`--stats-interval N` 每 N 秒输出**一行 JSON**，`--stats-file PATH`
指定文件时写文件（启动创建/截断），否则写 stderr。默认 `N=0` 即**关闭**——选择关闭是因为
既有消费者把 stderr 当日志读，默认打开会改变输出契约；需要观测时显式开启即可。
无连接（accept tick）与长连接（读取循环的 `read_timeout` tick）都会按同一间隔输出，
不会因某条连接长期占用而停止。schema 固定（字段缺失/改名须同步本段）：

```json
{"event":"xbits.stats","ts_unix_ms":1700000000123,"analysis":{"available":true,"send_failures":0,"document_errors":0,"documents_without_sink":0,"config_errors":0,"triage_dropped":0,"triage_timeouts":0,"pending_expired":0,"pending_overflow":0,"correlated_pairs":0,"correlation_timeouts":0},"engine":{"rules":3,"pending":0,"contexts":0,"scores":2,"correlations":0,"pending_expired":0,"pending_overflow":0,"contexts_expired":0,"scores_expired":0,"scores_evicted":0,"correlation_pairs":0,"correlation_timeouts":0,"correlation_overflow":0,"correlation_unmatched_responses":0},"hook_lines_dropped":0,"hook_lines_dropped_bytes":0}
```

未启用分析流水线时 `analysis` 为 `null`（字段仍在）；`engine.*` 与 hook 故障消息中的
`engine_` 前缀计数同源，但这里用独立的 `engine.` 命名空间，便于按 JSON 路径稳定读取。
`hook_lines_dropped` / `hook_lines_dropped_bytes`（R15-5）是 hook 侧超长行丢弃计数
（R6-4 的 `MAX_LINE_BYTES` 整行丢弃）：stderr 只有首次/每 1000 行的限流日志，stats 是
跨连接累计、稳定可解析的出口。

## 8.1 统一情报查询（threat-intel + allowlist）

xbits 中央引擎在**决策点**查询威胁情报与白名单（Zeek 只做纯行为分析，不持有名单；
行为事件 hook 到 xbits 后由 xbits 统一查询并直接影响评分/降级/文档）：

```bash
xbits --hook-socket /var/run/xbits/hook.sock --rules xbits/rules/analysis.json \
      --threat-intel-dir threat-intel/data \   # ip/domain/md5/sha1/sha256.txt（黑）
      --allowlist-dir allowlist/data           # domain/ip/public_dns.txt（白）
```

- 两个目录必须显式指定；**未指定即不启用情报**（启动打印 `intel=unconfigured`），
  不会去猜默认路径。
- 启动时一次性加载为内存集合（数据由 `threat-intel/tools/collect.py`、
  `allowlist/tools/{add,refresh}.py` 刷新，xbits 重启后生效），并逐项打印每个数据集的
  条目数与读取失败原因，状态区分 `unconfigured / misconfigured / empty / loaded`。
- 命中如何进入决策（常量见 `xbits/src/engine.rs` 的 `INTEL_*`）：
  - 威胁命中（IP / 域名 / 文件 md5、sha1、sha256）→ `score += 20`（参与 `threshold` 累计分）、
    `confidence += 15`（在 `min_confidence` 门槛判定前计入，可帮助达到门槛，但不会让证据不足的告警绕过门槛），告警写 `intel_decision=threat-hit`；
  - 白名单命中（IP / 域名）→ `confidence -= 25`，告警写 `intel_decision=allowlist-downgraded`，
    分析文档 `reason` 记 `intel-allowlist`（只降级；不在引擎里丢弃，也不阻断威胁命中）；
  - 两者同时命中 → 以威胁为准，写 `intel_decision=threat-overrides-allowlist`；
  - `allowlist.public_dns_off_baseline` 是 DNS 基线提示字段，**不参与加权**。
  - 情报决策依据在分析文档里写作 `reason=intel-*`（`intel-threat` / `intel-allowlist` /
    `intel-threat-allowlist-conflict`），**优先级最高**：validator 返回的 reason 不会覆盖它，
    而是单独记在 `xbits.validator_reason`（并在 evidence 追加 `validator-reason=...`）。
  - **降级 + 情报同时命中（R5-6）**：`xbits.reason` 只用一个字段给出完整语义——
    `intel-*+degraded-<label>`（如 `intel-threat+degraded-context-missing`），情报部分在前，
    保持 `intel-` 前缀兼容（validator 仍不能覆盖、既有按前缀匹配的消费者仍可用）；
    只有一种命中时仍分别是 `intel-*` / `degraded-*`。`xbits.degraded` 与 evidence 仍保留明细。
- 匹配语义：威胁域名**精确匹配**（与 `threat-intel/tools/query.py` 的集合语义一致）；
  只有 allowlist 域名做后缀匹配（**最长**后缀）。加载期拒绝公共后缀/单标签条目
  （如 `co.kr`、`com`），并打印被拒绝条目。
- **非法 IP 文本（R14-2）**：Python `canonical_ip()` 返回 `None` 即丢弃；Rust `IpSet`
  加载时同样**拒绝**（不进集合、不参与匹配），两者都计入报告（`SetLoad.invalid_ip_warnings`
  + 样本，启动日志打印"非法 IP 文本 N 条，已拒绝且不参与匹配"）。合法 IPv4/IPv6 仍按
  `IpAddr` 值互认，zone id（`fe80::1%eth0`）按非法处理。
- **人工查询 CLI 的差异（R15-6，已知限制）**：`threat-intel/tools/query.py` 与
  `allowlist/tools/query.py` 对非法输入（无法解析的 IP、非 hex 的 hash、空值）直接返回未命中
  且**不计数**（与引擎加载期的"拒绝 + 计数"不同）；详见两个子模块 README 的
  「非法输入的处置」说明。
- 标注进入两条输出：stdout 告警 JSON（`intel` / `allowlist` / `intel_decision`）与
  归一化文档（`--analysis-file`、ES 的 `intel`、`allowlist`、`xbits.intel_decision`）；
  文件 triage 文档同样携带（文件事件先经引擎标注，再进 triage）。

## 8.2 请求→响应关联（success_rules，V-14 方案①）

本章节是 success_rules 的**唯一主文**：CLI、字段、配对算法、TTL/容量、计数与限制以本节为准
（R12-6 把原 §10 的重复描述合并进来，§10 只留指针；§7.1 仅从 hook 故障消息角度交叉引用关联计数，不重复定义）。

PVS 探针规则里 1,546 条"请求探测 → 响应确认"链（flowbits/depend 语义；
`规则检测/xbits/规则库元数据/semantic_gaps.json` 的 `flowbits-correlation` 670 +
`dependency-correlation` 876）在 Suricata 侧被剥离、声明"交 xbits 处理"——xbits 现在
真实消费这份关联表（不再是无消费者的空话）：

```bash
xbits --hook-socket /var/run/xbits/hook.sock --rules xbits/rules/analysis.json \
      --success-rules 规则检测/xbits/规则库元数据/success_rules.json
```

- `success_rules.json`（由 `规则检测/convert_probe_rules.py` 生成）结构：
  `[{"sid": <响应侧>, "depends": [<请求侧>...], "scopes": [...], "msg": ..., "source": ...}]`；
  当前产物 **996 条**响应→请求映射（其中 527 条带 `depends`）——**以产物条目数为准**，
  规则重生后数字会变。加载期展开为 `response_to_requests: HashMap`，查询 O(1)。
- `--success-rules` **未指定即关闭关联**（不猜默认路径）；指定了但文件缺失 / JSON 解析失败
  → 启动直接非零退出，绝不静默降级成"无关联继续跑"（`qa_xbits_success_rules.py` case4
  对 missing-file / bad-json 两种坏配置都断言非零退出）。
- **配对算法**（`xbits/src/engine.rs`，状态机在引擎内）：
  1. 请求侧命中（事件 SID ∈ 任一响应规则的 `depends`）→ 在该 5 元组/community_id 的 key 上
     登记等待条目（记请求侧 SID + 时间戳；同 key 重复命中刷新时间戳）；
  2. 响应侧命中（事件 SID 是某响应规则，且同 key 等待条目的请求侧 ∈ 它的 `depends`）
     → 消费等待条目，响应侧告警带 `correlated=<请求侧 SID>` 字段，evidence 追加
     `correlated=<sid>: response-side success_rule matched on the same community_id (V-14)`；
  3. 关联成立对 `confidence` 的加成 = **+15**（常量 `CORRELATION_CONFIDENCE_BONUS`，
     与情报加分同一通道：在 `min_confidence` 门槛判定**之前**加入，可帮助达到门槛，
     不会让证据不足的告警绕过门槛）。
- **TTL / 上界**：等待条目 TTL = 120s（`CORRELATION_TTL`，引擎事件 TTL 60s 的 2 倍——
  覆盖请求-响应往返与跨请求周期的 PVS 探测）；等待表容量 4096（`MAX_CORRELATIONS`，
  与 pending 同量级），超限挤掉最旧条目并计数。
- **可观测**（`PipelineHealth`，hook 维护循环增量并入）：
  - `correlated_pairs`：配对成立数；`correlation_timeouts`：请求侧等待响应超 TTL 未配对数
    （关联是**增强信号**不是判定本体——超时只计数+日志，不产出降级告警，请求侧告警
    此前已正常判定）；等待表溢出计数 `correlation_overflow`（引擎侧访问器）。
  - `correlation_unmatched_responses`：响应侧命中但同 key 无匹配请求等待的次数（R12-4：
    "只发响应无请求"路径以前完全静默，现在计数 + 限流 stderr，告警照常输出但无
    `correlated` 标记）；前四项都会进 hook listener 故障消息（`ensure_pipeline_healthy`）。
- 归一化文档带 `xbits.correlated`（= 请求侧 SID 文本）与 `xbits.degraded` 并列。
- 无 `success_rules` 时功能整体关闭：等待表不登记、告警无 `correlated` 字段、
  计数恒 0——README 如实标注为"未启用"而不是"已配对但无结果"。
- **CI 断言**（`xbits/test/qa_xbits_success_rules.py`，接 `xbits-ci.yml`）：配对成立带
  `correlated` + evidence；对照组（无 `--success-rules`）不 `correlated` 且 confidence 差
  恰为 `CORRELATION_CONFIDENCE_BONUS`；只发响应不关联；无分析 sink 时 hook 照常配对并产出
  `correlated`；坏配置（missing-file / bad-json）非零退出。TTL 真等待（121s）用
  `--with-ttl-wait` 显式开启以免拖慢日常 CI，TTL 数值与超时计数本体由 `engine.rs` 单测覆盖。

## 9. 上下文关联、误报判断与统一告警落盘

生产分析规则使用 `xbits/rules/analysis.json`，额外支持：

- `require_context`: Suricata 告警必须等到对应 Zeek `http_request/http_header/http_reply` 上下文才输出；
- `benign_uri_contains` / `benign_host_contains`: 正常 URI/Host 上下文可抑制误报；
- `min_confidence`: **真正的过滤门槛**——`confidence` 只由上下文证据（无上下文 50、有上下文 70，再加
  host/uri/status/ua 证据分）与威胁情报加分算出，低于阈值的告警直接丢弃；门槛不会反向抬高 `confidence`
  （历史上曾用 `.max(min_confidence)` 抬升，导致过滤条件恒假，已修正）；
- `sid_in`: 按精确 SID 集合选择规则，避免 `signature_contains` 宽匹配；
- `score` / `threshold`: 累计分数达到阈值后才输出；
- `score_window_sec`: 累计分窗口（秒，可选）。未设置时用引擎默认窗口（与事件 TTL 相同，默认 60s）；
  `threshold > score` 的慢速累积规则必须显式声明足够长的窗口，否则窗口过期会清掉累计分、永不达标
  （窗口语义与计数见上文「累计分窗口」）。**加载期强制**（R5-4/R15-4）：`--rules` 载入时校验
  `threshold > score && score_window_sec.is_none()`，以及 `score_window_sec == 0`（0 秒窗口非法，
  任何规则上都拒绝），命中即非零退出并点名 rule id 与相关数值；
- `alert_kind`: xbits 接管 Zeek `XbitsAlert::emit` 的告警类别管理（例如只接收 `scanner`）。

xbits 通过 5-tuple 缓冲关联 Suricata alert 与 Zeek context；上下文缺失时不输出高置信度告警。

告警统一由 xbits 落盘：

```bash
xbits --hook-socket /var/run/xbits/hook.sock \
      --rules xbits/rules/analysis.json \
      --alert-file /var/log/xbits/alerts.jsonl
```

此时：

- Zeek `xbits_alert.zeek` 不再写 `xbits_alert.log`，只触发 `XbitsAlert::alert` 事件给薄 hook；
- Zeek 仅保留 `conn/http/dns/ssl/app_identity/scan_report` 等元数据日志；
- Suricata EVE 使用 `filetype: xbits-hook`，不落盘 `eve.json`/`fast.log`；
- xbits 输出的统一告警 JSONL 是唯一告警落盘入口，包含 `confidence`、`evidence`、`rule_id`、`alert_kind` 等字段。

## 10. success_rules 关联（唯一主文见 §8.2）

本节原是 §8.2 的重复描述（R12-6）。现已合并：`--success-rules` 的 CLI、JSON 字段、
配对算法、TTL/容量、计数、限制与 CI 断言只在 §8.2 维护；本节保留指针以免章节编号漂移，
不再重复正文。

## 11. 已知限制与修复状态（历史遗留项）

以下为历轮 QA（第五～十五轮）确认的遗留项，逐条如实记录（不隐藏，也不冒充已修）。
每条给出一句准确描述与影响面；详细证据见 `qa/FIX_REVIEW.md` 对应轮次、`qa/QA_REPORT.md`。
本清单随修复进度更新：**尚未修复项**仍如实保留、不隐瞒；本轮（low-cleanup 收口）修复的项标注
"已修复（本轮 A1/A2/A3/D1）"，仍列出以留存历史审计轨迹，但不计入待修数。

### 引擎状态机与计数（第五～六轮）

- **R5-4 `threshold > score` 无加载期校验 —— 已修复（本轮 A1）**：`model.rs::validate_rules` 在规则
  文件入口（`main.rs::load_rules`、`run_hook_listener_full`）做加载期校验：`threshold > score` 且
  未声明 `score_window_sec` 时直接非零退出，错误点名 rule id / 两个数值 / 文件路径；单测覆盖合法、
  非法、显式窗口三态。
  *影响面（已消除）*：误配在部署前即被拦截，不再只能靠 `scores_expired` 间接察觉。
- **R5-5 引擎计数仅故障消息导出 —— 已修复（本轮 A2）**：`--stats-interval N` 默认 0（关闭，保持
  stderr 契约），显式开启后每 N 秒输出单行 `xbits.stats` JSON；`--stats-file PATH` 写文件、否则
  stderr。`hook.rs::stats_snapshot` / `stats_json` 固定 schema（`analysis.*` 11 字段、`engine.*`
  14 字段，未挂分析流水线时 `analysis=null` 但字段稳定），`StatsEmitter` 在 accept tick 与长连接
  `read_timeout` tick 均输出；统计文件创建失败即启动失败。单测锁定格式/字段与 interval 行为。
  *影响面（已消除）*：正常态也能按固定路径读容量水位与淘汰速率。
- **R5-6 degraded 与 intel 同时命中时 reason 取 intel —— 已修复（本轮 A2）**：方案①单字段组合，
  `analysis.rs::decision_reason` 让 `xbits.reason` 在两种命中同时出现时写
  `intel-*+degraded-<label>`（如 `intel-threat+degraded-context-missing`），情报前缀保持兼容
  （validator 仍不覆盖）；单命中仍是 `intel-*` / `degraded-*`，`xbits.degraded` 与 evidence 保留
  明细字段。单测覆盖组合、两种单命中与归一化文档断言。
  *影响面（已消除）*：下游只读 `xbits.reason` 即可得到完整语义。
- **R6-2 hook 接线的 Unix socket 运行时覆盖（部分覆盖，本轮 A1/A3 已补真实单测；剩余缺口为
  listener 外层 accept 轮询/空闲维护节拍的端到端）**：`serve_stream` 层已有运行时真实 socket 覆盖——
  `long_connection_still_runs_maintenance_tick`（真实 `UnixStream::pair`：5ms tick + 20ms TTL + 持续
  写入断言降级告警与 `pending_expired>=1`、半行缓冲不丢数据）与
  `serve_stream_survives_overlong_line_and_processes_next_event`（真实 Unix stream：>1 MiB 无换行
  输入后正常事件仍产出告警）覆盖了维护节拍、半行缓冲与超长行恢复；e2e（`qa_*.py`）走整链，仍不断言
  listener 外层的 accept 轮询间隔与空闲侧维护节拍。
  *剩余影响面*：accept 轮询/空闲维护节拍的端到端断言仍只能静态核对；半行缓冲/EOF 尾行/饿死
  tick 三类缺陷已有运行时单测兜底。
- **R6-3 accept 持续连接可饿死 tick —— 已修复（本轮 A3）**：`hook.rs::serve_stream` 在读取循环
  每次迭代检查维护截止时间，即使客户端持续有数据（`read` 永不超时）也按 `MAINTENANCE_TICK`
  （默认 200ms）执行 `engine.maintenance()`，降级告警照常写回输出；超时分支保留一次维护作为空闲
  兜底。未采用每连接独立线程（保持单线程 `&mut Engine` 单一状态源与判定顺序）。单测
  `long_connection_still_runs_maintenance_tick` 用 5ms tick + 20ms TTL + 持续空行写入断言
  `pending_expired>=1` 且输出降级告警，同时验证半行缓冲不丢数据。
  *影响面（已消除）*：长连接持续写入不再推迟维护/降级输出。
- **R6-4 pending 单行长度无上限 —— 已修复（本轮 A1）**：`hook.rs::LineBuffer` 设单行上限
  `MAX_LINE_BYTES = 1 MiB`，超限整行丢弃并进入丢弃模式直到下一个换行（连接继续、后续正常行不受
  影响），计数 `dropped_lines` / `dropped_bytes` 并限流 stderr（首次 + 每 1000 行）；单测覆盖跨
  chunk 半行、EOF 尾行、无换行超长、单 chunk 超长与汇总节流，并有真实 `UnixStream` 端到端自测
  （写入 `MAX_LINE_BYTES + 64 KiB` ≈ 1.06 MiB 的无换行输入后，后续正常事件仍产出告警）。
  *影响面（已消除）*：无换行超长输入不再无界占用内存。

### 第十五轮新发现（verifier 复核）

- **R15-4 `score_window_sec: 0` 未被加载期拒绝 —— 已修复（本轮 t7）**：`model.rs::Rule::validate`
  现把 `score_window_sec: 0` 一律拒绝（与 `threshold`/`score` 无关，`threshold == score` 的 0 同样
  非法——0 秒窗口会让累计分立即过期）：报错点名 rule id 与
  `score_window_sec=0 is not allowed`，并给出修法（删字段用默认 TTL 或给正整数秒）。单测
  `validate_rejects_zero_score_window` 覆盖三种形态；§7「累计分窗口」与 §9 `score_window_sec`
  字段说明已同步"0 非法"。
  *影响面（已消除）*：误配在部署前被拦截，不再让"窗口立即过期"静默击穿慢速累积语义。
- **R15-5 hook 丢行计数无稳定 stats 出口 —— 已修复（本轮 t7）**：`StatsSnapshot` 新增顶层字段
  `hook_lines_dropped` / `hook_lines_dropped_bytes`（跨连接累计）：`serve_stream` 检测到超长行
  丢弃即 `record_line_drops` 写入 emitter，stderr 限流日志之外提供稳定可解析出口；单测
  `stats_counts_dropped_lines_from_line_buffer`（1 行→1、再丢→2、序列化含字段）与 schema 测试
  （字段恒存在）锁定。§8 的 stats 示例 JSON 已含两字段。
  *影响面（已消除）*：丢行不再只有限流日志，可按固定 JSON 路径持续观测。

### 测试与 CI 断言强度（第八～九轮）

- **R8-4 semgrep JSON errors 未当失败**：`triage.py` 把 `errors[]` 只写进 `info.semgrep.errors`，
  `engines["semgrep"].ok` 仍 True；rc≠0 但带 errors 的 JSON 会被当成"真实执行成功"。
  *影响面*：脚本 AST 规则配置错误时 verdict 仍按"无情报"输出。
- **R8-5 `engines[tool]` 语义变更的迁移提示**：该字段由"已安装"变为"present and ok"摘要，
  Rust 侧不读（`xbits.triage` 原样透传）；外部脚本若按旧语义读会误判"组件缺失"。
  *影响面*：仅影响仓库外消费方；README 已说明三态为主，建议再加迁移提示。
- **R8-6 assert_hook_output 坏 JSON 行静默跳过**：坏行被跳过，只有匹配数不足时才失败；若告警行
  被截断，报错是"0 matched"而非"行损坏"。
  *影响面*：排障时无法从测试输出区分"没告警"与"告警格式坏"。
- **R9-2 `known_extra` 可抵扣场景内未声明命中**：只要求一个自由文本 reason，机制上给"漏断言"
  留了免检通道（当前仅 1 处跨场景用法）。
  *影响面*：场景内多命中可能被 known_extra 掩盖而不触发 warning。
- **R9-3 新增 require 缺逐条语义说明**：`cases/recon_cases/backdoor_cases.json` 8 处新增 require
  是把 CI 基线命中固化为断言，仓库内无逐条"为何该 SID 应命中"的说明。
  *影响面*：若其中某条本是规则误报，测试会把误报锁死。
- **R9-4 对照门禁是静态的**：只证明"该 SID 在别处被 require"，运行时是否真的加载/命中仍靠正例与
  `suricata -T`；单看负例本身无法区分"规则没加载"。
  *影响面*：规则集整批未加载时，纯 forbid 负例仍可通过。
- **R9-5 strict 模式 PASS 文案易误读**：strict 下仍打印"0 warnings not asserted as failures — run
  with --strict-warnings to gate"，易被误读为"未启用 strict"。
  *影响面*：仅是输出文案误导，不影响门禁行为。

### 缓存与转换器语义（第十～十二轮）

- **R11-1 YARA 缓存键不覆盖跨目录 include**：缓存键只覆盖规则目录内枚举到的 `.yar`；若某规则
  `include` 了目录外文件，被 include 文件变化而自身 mtime/size 不变时缓存不失效（既有设计）。
  *影响面*：当前 `triage/rules` 未使用跨目录 include，风险低。
- **R12-2 676 处 `content;buffer` 后置写法仍在转换规则库**：V-10 的"`content;buffer` == 0"
  未全局达成；仅影响加载校验用规则，活动场景目录 0 违规（该 0 违规是静态核对结论，
  CI 只锁转换库侧的棘轮基线，不直接断言场景目录的后置写法）。
  *影响面*：与任务口径有差距；已作为棘轮基线锁死（第十三轮 A=676 与 baseline 相等），需单独立项清零。
- **R12-4 关联计数未进 hook 故障消息 —— 已修复（本轮 A1）**：`hook.rs::engine_failure_stats` 现导出
  `correlated_pairs` / `correlation_timeouts` / `correlation_overflow`，并新增
  `correlation_unmatched_responses`（响应侧命中但无可配对请求等待，以前完全静默）——计数 + 限流
  stderr 日志；单测 `failure_stats_export_correlation_counters` 锁定。
  *影响面（已消除）*：关联能力的可见性与其它计数器对齐。
- **R12-5 `规则检测/README.md` 仍称 `zeek/威胁情报/` 存在 —— 已修复（t55）**：zeek 段现列 3 个行为
  脚本并指向 `allowlist/`、`threat-intel/`；`qa_zeek_file_set.py` 三层守卫接入 CI 锁住该集合。
  *影响面（已消除）*：不再误导读者以为 Zeek 侧仍持名单。
- **R12-6 success_rules 出现两处重复章节 —— 已修复（本轮 D1）**：§8.2 为唯一主文（CLI、字段、
  配对算法、TTL/容量、计数、限制、CI 断言），§10 改为一句指针；两处数字口径同时统一为
  "1,546 条被剥离链（`flowbits-correlation` 670 + `dependency-correlation` 876）"与
  "产物 996 条响应→请求映射（以产物条目数为准）"。
  *影响面（已消除）*：不再维护两份会漂移的正文。
- **R12-7 PCAP 每类 buffer 仅 1 对正负例**：`qa_converter_pcap_regression.py` 的 `CASES` 每类 buffer
  仅 1 对（任务书建议 2~3 条），其余同 buffer 家族 SID 只靠 `-T` 加载校验。
  *影响面*：同家族变体的命中语义未被逐一验证。

### 终轮新发现（第十三轮）

- **R13-1 PCAP 依赖"已核对"是纯打印（已修复，本轮 t51）**：`qa_converter_pcap_regression.py`
  的 `check_rule_pcap_bytes()` 现在按 SID 读规则原文，运行时比对 buffer/flow/content hex/pcre/URI
  归一化与 PCAP 载荷（pos 必全含、neg 必缺一），并在 `--generate` 与 `--eve-root` 前执行，失败直接 FAIL。
  *残留*：仅"规则头 any 443 -> any any"这类描述性打印尚未改为独立断言，但 EVE pos 断言与字节断言
  已覆盖其语义（提示可能过时，不影响判定）。
- **R13-3 已知限制清单不完整（本项）**：第十三轮前本清单停在第六轮 6 项，遗漏 R8/R9/R11/R12 十余项。
  本节即为该项修复，**已修复（本轮）**。
- **R13-2 `emits_alert` 预检未含 `benign`/`min_confidence` —— 已修复（本轮）**：
  `engine.rs::emits_alert` 现与 `make_alert_full` 同口径纳入两个门槛，并补测试
  `correlation_wait_not_registered_for_benign_or_below_min_confidence`；不再给被过滤的请求事件登记等待。
  *影响面（已消除）*：此前可能为非发出的事件登记等待；本轮修复后该路径关闭。

- **R14-2 非法 IP 文本双侧策略不完全一致 —— 已修复（本轮 A2）**：`intel.rs::IpSet` 移除
  `invalid_text`，`contains()` 只按合法 `IpAddr` 比较；`load_ip_dataset` 对非法条目（含 zone id）
  直接拒绝：不进集合、不计入 `entries`、不参与匹配，但仍累计 `invalid_ip_warnings` + 样本并在启动
  report 打印"已拒绝且不参与匹配"，与 Python `allowlist/tools/ipnorm.py::canonical_ip` 返回 `None`
  对齐。单测断言计数、报告可见性与非法原文一律不命中。
  *影响面（已消除）*：脏数据只产生可见告警，不再成为可命中的名单条目；合法地址命中不变。

> 更新约定：新增未修项按 `R<轮>-<序号>` 编号追加到对应主题分组，并在 `qa/QA_REPORT.md` 的
> "修复后状态"段落同步；修复后把条目移到"已修复"说明里，不要直接删除历史审计证据。


