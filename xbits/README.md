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
**不是数据 buffer**，绝不参与 key：生成器先剥离 `lua`，再按规则实际匹配的数据面归类——
有具体 sticky buffer（`http.uri`/`file.data`/`http.header`…）用该 buffer；只有
`content`/`pcre` 而无声明的落到 `payload`（报文精确字节）。因此带 `lua:` 的规则
同样是**可精确抑制**的 `payload`/sticky buffer 规则，而不是"无 buffer 可导出"。

只有当规则既无具体 buffer、也无 `content`/`pcre`、仅挂 `lua` 时，才标记
`app_tx_lua: true`：这类真·纯 Lua 规则在 C 层没有单一精确 buffer 可导出，
**不参与抑制**（每次告警仍走 validator；xbits 记录一次说明日志）。当前规则库
不存在此类规则（全部 17477 条都有可精确获取的具体 buffer）。

> 早期版本曾把 `lua` 当成 buffer 抢先占位、丢掉 `content` 匹配的 `payload`，
> 导致 919 条规则被误标为 `app_tx_lua` 而无法抑制。现已按上述逻辑根治。

跨 socket 顺序：`match_context` 与 `alert` 来自不同连接、到达顺序无保证。xbits 对
声明了 context-only buffer 的告警在缺 context 时短暂挂起（默认 500ms，`--pending-context-ms`
可调），context 到达即判定；超时按 fail-closed 处理（不建 key、不抑制），绝不丢事件。

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
- 匹配语义：威胁域名**精确匹配**（与 `threat-intel/tools/query.py` 的集合语义一致）；
  只有 allowlist 域名做后缀匹配（**最长**后缀）。加载期拒绝公共后缀/单标签条目
  （如 `co.kr`、`com`），并打印被拒绝条目。
- 标注进入两条输出：stdout 告警 JSON（`intel` / `allowlist` / `intel_decision`）与
  归一化文档（`--analysis-file`、ES 的 `intel`、`allowlist`、`xbits.intel_decision`）；
  文件 triage 文档同样携带（文件事件先经引擎标注，再进 triage）。

## 9. 上下文关联、误报判断与统一告警落盘

生产分析规则使用 `xbits/rules/analysis.json`，额外支持：

- `require_context`: Suricata 告警必须等到对应 Zeek `http_request/http_header/http_reply` 上下文才输出；
- `benign_uri_contains` / `benign_host_contains`: 正常 URI/Host 上下文可抑制误报；
- `min_confidence`: **真正的过滤门槛**——`confidence` 只由上下文证据（无上下文 50、有上下文 70，再加
  host/uri/status/ua 证据分）与威胁情报加分算出，低于阈值的告警直接丢弃；门槛不会反向抬高 `confidence`
  （历史上曾用 `.max(min_confidence)` 抬升，导致过滤条件恒假，已修正）；
- `sid_in`: 按精确 SID 集合选择规则，避免 `signature_contains` 宽匹配；
- `score` / `threshold`: 累计分数达到阈值后才输出；
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


