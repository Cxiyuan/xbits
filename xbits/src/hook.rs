use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::Serialize;

use crate::analysis::AnalysisPipeline;
use crate::engine::Engine;
use crate::model::{HookEvent, Rule};

/// 空闲维护节拍（R5-1）：连接上无数据超过该间隔就触发一次引擎维护，
/// 让挂起告警的 TTL 过期 / 计数 / 降级输出与"是否有新事件"解耦。
const MAINTENANCE_TICK: Duration = Duration::from_millis(200);
/// accept 空闲时的轮询间隔（无连接时也要按 tick 推进维护，但不忙等）。
const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(20);
/// listener 同时服务的活动连接上限（R6-2）：有界，避免连接洪泛耗尽内存；
/// 超限只丢弃新连接并打印，不影响已接入连接。
const MAX_ACTIVE_CONNECTIONS: usize = 256;
/// hook 行缓冲的单行上限（R6-4）。
///
/// 正常 hook 事件远小于该值：Suricata EVE 的 payload / HTTP body 在分析层受
/// `--max-payload`（默认 16KiB）约束，1MiB 留出 64 倍余量；同时把"无换行的异常输入"
/// 限制在常量内存内——超限整行丢弃（不中断连接、不影响后续正常行），并计数 + 限流告警。
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// 按换行切分的 hook 行缓冲，带单行长度上限（R6-4）。
///
/// 与旧实现（`pending: Vec<u8>` 无限追加）的区别：单行超过 [`MAX_LINE_BYTES`] 时
/// **整行丢弃**并进入 `discarding` 状态，直到下一个换行才恢复；因此无换行超长输入
/// 只会占用不超过 `MAX_LINE_BYTES` 的缓冲，不会无限增长。
#[derive(Debug, Default)]
struct LineBuffer {
    buf: Vec<u8>,
    /// 当前行已因超限被丢弃：持续丢到下一个换行，避免无换行输入无限占内存。
    discarding: bool,
    dropped_lines: u64,
    dropped_bytes: u64,
}

impl LineBuffer {
    fn new() -> Self {
        Self::default()
    }

    /// 追加一段读取数据，返回其中完整（以 `\n` 结尾）且未超限的行。
    fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        let mut rest = chunk;
        while let Some(pos) = rest.iter().position(|b| *b == b'\n') {
            self.push_fragment(&rest[..pos], true, &mut lines);
            rest = &rest[pos + 1..];
        }
        if !rest.is_empty() {
            self.push_fragment(rest, false, &mut lines);
        }
        lines
    }

    fn push_fragment(&mut self, fragment: &[u8], terminated: bool, lines: &mut Vec<Vec<u8>>) {
        if self.discarding {
            self.dropped_bytes = self.dropped_bytes.saturating_add(fragment.len() as u64);
            if terminated {
                self.discarding = false;
            }
            return;
        }
        if self.buf.len().saturating_add(fragment.len()) > MAX_LINE_BYTES {
            // 整行丢弃（含已缓冲部分与本段），并进入丢弃模式直到换行。
            self.dropped_lines = self.dropped_lines.saturating_add(1);
            self.dropped_bytes = self
                .dropped_bytes
                .saturating_add(self.buf.len() as u64)
                .saturating_add(fragment.len() as u64);
            self.buf.clear();
            self.buf.shrink_to(4096);
            self.discarding = !terminated;
            return;
        }
        self.buf.extend_from_slice(fragment);
        if terminated {
            lines.push(std::mem::take(&mut self.buf));
        }
    }

    /// 连接结束：返回最后一行（可能没有换行符）。被丢弃的超长行不返回。
    fn finish(&mut self) -> Option<Vec<u8>> {
        let line = if !self.discarding && !self.buf.is_empty() {
            Some(std::mem::take(&mut self.buf))
        } else {
            None
        };
        self.buf.clear();
        self.discarding = false;
        line
    }
}

/// 超长行丢弃的可见化（R6-4）：首次必打，之后每 1000 行汇总一次（不刷屏、不静默）。
fn report_line_drops(lines: &LineBuffer, reported: &mut u64) {
    let dropped = lines.dropped_lines;
    if dropped == *reported {
        return;
    }
    let first = *reported == 0;
    let milestone = dropped / 1000 > *reported / 1000;
    if first || milestone || dropped % 1000 == 0 {
        eprintln!(
            "xbits: hook dropped {} overlong line(s) >{} bytes (total_dropped={}, total_bytes={}); connection continues",
            dropped - *reported,
            MAX_LINE_BYTES,
            dropped,
            lines.dropped_bytes
        );
        *reported = dropped;
    }
}

// ---- R5-5：运行期统计快照（稳定 JSON schema） ----

/// 分析层计数快照（`PipelineHealth` 的公开读取面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisStatsSnapshot {
    pub available: bool,
    pub send_failures: u64,
    pub document_errors: u64,
    pub documents_without_sink: u64,
    pub config_errors: u64,
    pub triage_dropped: u64,
    pub triage_timeouts: u64,
    pub pending_expired: u64,
    pub pending_overflow: u64,
    pub correlated_pairs: u64,
    pub correlation_timeouts: u64,
}

/// 引擎计数快照（不用 `engine_` 前缀：这是独立的 stats 命名空间 `engine.*`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineStatsSnapshot {
    pub rules: usize,
    pub pending: usize,
    pub contexts: usize,
    pub scores: usize,
    pub correlations: usize,
    pub pending_expired: u64,
    pub pending_overflow: u64,
    pub contexts_expired: u64,
    pub scores_expired: u64,
    pub scores_evicted: u64,
    pub correlation_pairs: u64,
    pub correlation_timeouts: u64,
    pub correlation_overflow: u64,
    pub correlation_unmatched_responses: u64,
}

/// 单行 JSON 统计快照：字段固定，消费者可按路径稳定读取。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatsSnapshot {
    /// 固定事件名，便于从混合 stderr/日志流里过滤。
    pub event: &'static str,
    /// UTC 毫秒时间戳。
    pub ts_unix_ms: u64,
    /// 未启用分析流水线时为 `null`（schema 仍存在，字段稳定）。
    pub analysis: Option<AnalysisStatsSnapshot>,
    pub engine: EngineStatsSnapshot,
    /// R6-4/R15-5：hook 侧因超过 `MAX_LINE_BYTES` 被整行丢弃的行数（跨连接累计，
    /// 随快照生成时的观察者值）。超限丢弃只进 stderr 限流日志，stats 是稳定可解析出口。
    pub hook_lines_dropped: u64,
    /// R6-4/R15-5：被丢弃的超长行累计字节数（近似，含缓冲与分段）。
    pub hook_lines_dropped_bytes: u64,
}

/// 生成统计快照（纯函数，便于单测锁定 schema）。
pub fn stats_snapshot(
    pipeline: Option<&AnalysisPipeline>,
    engine: &Engine,
    ts_unix_ms: u64,
) -> StatsSnapshot {
    self::stats_snapshot_with_drops(pipeline, engine, ts_unix_ms, 0, 0)
}

/// 带 hook 侧丢弃计数的快照（`serve_stream` 用 `LineBuffer` 的观察值调用）。
pub fn stats_snapshot_with_drops(
    pipeline: Option<&AnalysisPipeline>,
    engine: &Engine,
    ts_unix_ms: u64,
    lines_dropped: u64,
    lines_dropped_bytes: u64,
) -> StatsSnapshot {
    StatsSnapshot {
        event: "xbits.stats",
        ts_unix_ms,
        analysis: pipeline.map(|p| {
            let health = p.health();
            AnalysisStatsSnapshot {
                available: health.is_available(),
                send_failures: health.send_failures(),
                document_errors: health.document_errors(),
                documents_without_sink: health.documents_without_sink(),
                config_errors: health.config_errors(),
                triage_dropped: health.triage_dropped(),
                triage_timeouts: health.triage_timeouts(),
                pending_expired: health.pending_expired(),
                pending_overflow: health.pending_overflow(),
                correlated_pairs: health.correlated_pairs(),
                correlation_timeouts: health.correlation_timeouts(),
            }
        }),
        engine: EngineStatsSnapshot {
            rules: engine.rules_len(),
            pending: engine.pending_len(),
            contexts: engine.contexts_len(),
            scores: engine.scores_len(),
            correlations: engine.correlations_len(),
            pending_expired: engine.pending_expired(),
            pending_overflow: engine.pending_overflow(),
            contexts_expired: engine.contexts_expired(),
            scores_expired: engine.scores_expired(),
            scores_evicted: engine.scores_evicted(),
            correlation_pairs: engine.correlation_pairs(),
            correlation_timeouts: engine.correlation_timeouts(),
            correlation_overflow: engine.correlation_overflow(),
            correlation_unmatched_responses: engine.correlation_unmatched_responses(),
        },
        hook_lines_dropped: lines_dropped,
        hook_lines_dropped_bytes: lines_dropped_bytes,
    }
}

/// 序列化为单行 JSON（字段均为基本类型，序列化失败属于程序错误）。
pub fn stats_json(
    pipeline: Option<&AnalysisPipeline>,
    engine: &Engine,
    ts_unix_ms: u64,
) -> String {
    serde_json::to_string(&stats_snapshot(pipeline, engine, ts_unix_ms))
        .expect("stats snapshot is serializable")
}

fn now_unix_ms() -> u64 {
    UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// `--stats-interval` / `--stats-file` 的运行期配置。
#[derive(Debug, Clone)]
pub struct HookStatsConfig {
    /// 输出间隔；`Duration::ZERO` = 关闭（CLI 默认值，保持现有 stderr 契约）。
    pub interval: Duration,
    /// 指定时写文件（启动时创建/截断），否则写 stderr；均是一行一条 JSON。
    pub file: Option<PathBuf>,
}

impl Default for HookStatsConfig {
    fn default() -> Self {
        Self {
            interval: Duration::ZERO,
            file: None,
        }
    }
}

/// 周期统计发射器。由 listener 与 `serve_stream` 共享：即使某条连接长期占用，
/// 读取循环的 `read_timeout` 也按同一节拍输出，不被 accept 侧饿死。
pub struct StatsEmitter {
    interval: Duration,
    last: Instant,
    /// `None` = 关闭；`Some(None)` = 写 stderr；`Some(Some(writer))` = 写文件。
    state: Option<Option<BufWriter<File>>>,
    /// R15-5：hook 侧超长行丢弃计数（跨连接累计，由 serve_stream 累加）。
    lines_dropped: u64,
    lines_dropped_bytes: u64,
}

impl StatsEmitter {
    fn new(config: HookStatsConfig) -> io::Result<Self> {
        let state = if config.interval.is_zero() {
            None
        } else {
            Some(match config.file {
                Some(path) => Some(BufWriter::new(File::create(path)?)),
                None => None,
            })
        };
        Ok(Self {
            interval: config.interval,
            last: Instant::now(),
            state,
            lines_dropped: 0,
            lines_dropped_bytes: 0,
        })
    }

    fn disabled() -> Self {
        Self {
            interval: Duration::ZERO,
            last: Instant::now(),
            state: None,
            lines_dropped: 0,
            lines_dropped_bytes: 0,
        }
    }

    /// R15-5：多连接事件循环按连接累计新的丢弃量（增量累加）。
    fn record_line_drops(&mut self, lines: u64, bytes: u64) {
        self.lines_dropped = self.lines_dropped.saturating_add(lines);
        self.lines_dropped_bytes = self.lines_dropped_bytes.saturating_add(bytes);
    }

    /// R15-5：用「当前所有连接的总丢弃数」覆盖式写入（单调不减），
    /// 供 listener 事件循环在活动连接集合变化时避免重复累加/漏计。
    fn set_line_drops_total(&mut self, lines: u64, bytes: u64) {
        self.lines_dropped = self.lines_dropped.max(lines);
        self.lines_dropped_bytes = self.lines_dropped_bytes.max(bytes);
    }

    fn maybe_emit(
        &mut self,
        pipeline: Option<&AnalysisPipeline>,
        engine: &Engine,
    ) -> io::Result<()> {
        let Some(output) = self.state.as_mut() else {
            return Ok(());
        };
        if self.last.elapsed() < self.interval {
            return Ok(());
        }
        let snapshot = self::stats_snapshot_with_drops(
            pipeline,
            engine,
            now_unix_ms(),
            self.lines_dropped,
            self.lines_dropped_bytes,
        );
        let line = serde_json::to_string(&snapshot).expect("stats snapshot is serializable");
        match output {
            Some(writer) => {
                writeln!(writer, "{line}")?;
                writer.flush()?;
            }
            None => eprintln!("{line}"),
        }
        self.last = Instant::now();
        Ok(())
    }
}

fn parse_event(line: &str) -> Option<HookEvent> {
    // 1) xbits 薄插件格式
    if let Ok(ev) = serde_json::from_str::<HookEvent>(line) {
        if !ev.source.is_empty() {
            return Some(ev);
        }
    }

    // 2) Suricata EVE filetype 插件原样转发的 EVE JSON
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let event_type = v.get("event_type")?.as_str()?;
    let mut ev = HookEvent::default();
    ev.source = "suricata".into();
    ev.kind = event_type.into();
    ev.ts = v
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.timestamp = ev.ts.clone();
    ev.community_id = v
        .get("community_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.src = v
        .get("src_ip")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.dst = v
        .get("dest_ip")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.sport = v.get("src_port").and_then(serde_json::Value::as_u64);
    ev.dport = v.get("dest_port").and_then(serde_json::Value::as_u64);
    ev.proto = v
        .get("proto")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.app_proto = v
        .get("app_proto")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.tx_id = v
        .get("tx_id")
        .and_then(serde_json::Value::as_u64);
    ev.payload = v
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.payload_printable = v
        .get("payload_printable")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.request_body = v
        .pointer("/http/request_body")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.response_body = v
        .pointer("/http/response_body")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.dns_query = v
        .pointer("/dns/queries/0/rrname")
        .or_else(|| v.pointer("/dns/query"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.sni = v
        .pointer("/tls/sni")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.direction = v
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.method = v
        .pointer("/http/http_method")
        .or_else(|| v.pointer("/http/method"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.uri = v
        .pointer("/http/url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.user_agent = v
        .pointer("/http/http_user_agent")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.host = v
        .pointer("/http/hostname")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    ev.status = v
        .pointer("/http/status")
        .and_then(serde_json::Value::as_u64);
    ev.flow_id = v.get("flow_id").map(|x| match x {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    if event_type == "alert" {
        if let Some(alert) = v.get("alert") {
            ev.sid = alert
                .get("signature_id")
                .and_then(serde_json::Value::as_u64);
            ev.signature = alert
                .get("signature")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            ev.action = alert
                .get("action")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            ev.category = alert
                .get("category")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            ev.severity = alert
                .get("severity")
                .map(|sev| sev.to_string());
        }
    }
    // Suricata 转存文件后的 fileinfo 事件：归一为 file_stored，交给 xbits 静态 triage。
    if event_type == "fileinfo" {
        ev.kind = "file_stored".into();
        if let Some(fi) = v.get("fileinfo") {
            ev.file_sha256 = fi.get("sha256").and_then(serde_json::Value::as_str).map(str::to_string);
            ev.file_sha1 = fi.get("sha1").and_then(serde_json::Value::as_str).map(str::to_string);
            ev.file_md5 = fi.get("md5").and_then(serde_json::Value::as_str).map(str::to_string);
            ev.file_name = fi.get("filename").and_then(serde_json::Value::as_str).map(str::to_string);
            ev.file_magic = fi.get("magic").and_then(serde_json::Value::as_str).map(str::to_string);
            ev.file_size = fi.get("size").and_then(serde_json::Value::as_u64);
            ev.file_stored = fi.get("stored").and_then(serde_json::Value::as_bool);
            if ev.tx_id.is_none() {
                ev.tx_id = fi.get("tx_id").and_then(serde_json::Value::as_u64);
            }
        }
    }
    ev.extra = v.as_object().cloned().unwrap_or_default();
    Some(ev)
}

/// 是否为"文件已转存"类事件（触发 xbits 静态 triage 编排）。
fn is_file_event(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "file_stored" | "fileinfo" | "file"
    )
}

/// 把引擎告警写成一行 JSONL（stdout / --alert-file 的唯一出口）。
fn write_alert<W: Write + ?Sized>(writer: &mut W, alert: &crate::engine::EngineAlert) -> io::Result<()> {
    match serde_json::to_string(alert) {
        Ok(json) => {
            writeln!(writer, "{json}")?;
            writer.flush()?;
        }
        Err(err) => eprintln!("xbits: serialize alert error: {err}"),
    }
    Ok(())
}

/// 引擎侧计数导出（R4-1 / R12-4）：全部写进 hook 故障消息。
///
/// 关联计数（`correlated_pairs` / `correlation_timeouts`）取引擎侧权威值，分析层
/// `PipelineHealth` 只是同源镜像（避免同步滞后导致读数不同）；`correlation_overflow` /
/// `correlation_unmatched_responses` 只在引擎侧存在。
fn engine_failure_stats(engine: Option<&Engine>) -> String {
    let Some(engine) = engine else {
        return String::new();
    };
    format!(
        ", engine_pending_expired={}, engine_pending_overflow={}, engine_contexts_expired={}, engine_scores_expired={}, engine_scores_evicted={}, correlated_pairs={}, correlation_timeouts={}, correlation_overflow={}, correlation_unmatched_responses={}",
        engine.pending_expired(),
        engine.pending_overflow(),
        engine.contexts_expired(),
        engine.scores_expired(),
        engine.scores_evicted(),
        engine.correlation_pairs(),
        engine.correlation_timeouts(),
        engine.correlation_overflow(),
        engine.correlation_unmatched_responses()
    )
}

/// 分析流水线 / 引擎不可用时返回错误：让进程以非零退出，而不是静默降级继续跑。
///
/// 触发来源：分析线程 panic 退出，或入队连续失败达到阈值（见 `PipelineHealth`）。
/// 消息里同时带两层指标，且**字段名不混用**：
/// - 分析层：`pending_expired` / `pending_overflow`（等 match_context 的告警）；
/// - 引擎层：`engine_pending_expired` / `engine_pending_overflow` / `engine_contexts_expired` /
///   `engine_scores_expired` / `engine_scores_evicted`（R4-1：引擎计数真正导出并被消费）；
/// - 关联（R12-4）：`correlated_pairs` / `correlation_timeouts` / `correlation_overflow` /
///   `correlation_unmatched_responses`（"只发响应无请求"路径以前静默，现在至少有计数 +
///   限流 stderr 日志）。
fn ensure_pipeline_healthy(
    pipeline: Option<&AnalysisPipeline>,
    engine: Option<&Engine>,
) -> io::Result<()> {
    let Some(pipeline) = pipeline else {
        return Ok(());
    };
    if pipeline.is_available() {
        return Ok(());
    }
    let reason = pipeline
        .failure_reason()
        .unwrap_or_else(|| "unknown (analysis thread not running)".to_string());
    let health = pipeline.health();
    let engine_stats = engine_failure_stats(engine);
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "analysis pipeline unavailable: {reason} (send_failures={}, document_errors={}, documents_without_sink={}, config_errors={}, triage_dropped={}, triage_timeouts={}, pending_expired={}, pending_overflow={}{engine_stats})",
            health.send_failures(),
            health.document_errors(),
            health.documents_without_sink(),
            health.config_errors(),
            health.triage_dropped(),
            health.triage_timeouts(),
            health.pending_expired(),
            health.pending_overflow()
        ),
    ))
}


/// 引擎定时维护（R5-1）：把过期 pending 的降级告警、溢出降级告警写出去并投递分析流水线。
///
/// 与"事件到达"解耦：连接空闲（read_timeout）与无连接（accept tick）都会调用。
/// 每次维护同时把引擎侧的关联观测计数增量并入流水线健康（V-14：correlated_pairs /
/// correlation_timeouts 的唯一出口），保证计数可见。
fn maintenance<W: Write + ?Sized>(
    engine: &mut Engine,
    pipeline: Option<&AnalysisPipeline>,
    writer: &mut W,
) -> io::Result<()> {
    if let Some(pipeline) = pipeline {
        pipeline.sync_correlation_counts(engine);
    }
    for (event, alert) in engine.maintenance() {
        if let Some(pipeline) = pipeline {
            pipeline.submit_alert(event, alert.clone());
        }
        write_alert(writer, &alert)?;
    }
    ensure_pipeline_healthy(pipeline, Some(engine))
}

/// 处理一行 hook JSON（原 listener 内的单行逻辑，抽出来供定时读取复用）。
fn handle_line<W: Write + ?Sized>(
    line: &str,
    engine: &mut Engine,
    pipeline: Option<&AnalysisPipeline>,
    writer: &mut W,
) -> io::Result<()> {
    let ev: HookEvent = match parse_event(line) {
        Some(v) => v,
        None => {
            eprintln!("xbits: bad hook event: {line}");
            return Ok(());
        }
    };
    // 分析线程已 panic 退出或入队连续失败 → 明确失败（进程非零退出），不静默降级。
    ensure_pipeline_healthy(pipeline, Some(engine))?;
    if ev.kind.eq_ignore_ascii_case("match_context") {
        if let Some(pipeline) = pipeline {
            pipeline.submit_event(ev);
        }
        return Ok(());
    }
    // 文件已转存事件：先经引擎（规则评分 + 情报标注走同一决策链），再带着引擎给出的
    // 情报标注进静态 triage。triage 由 xbits 以 --stdin 调起时，以本次传入的情报为准，
    // 不再自行读本地 file_hash.txt（本地名单仅 triage 独立 CLI 使用）；即情报只有一个
    // 数据源（本引擎）、一个判定点，triage 侧不另起一套查询语义。
    if is_file_event(&ev.kind) {
        // 每条告警配它自己的原始事件（R6-1）：降级告警带的是被降级的挂起告警事件，
        // 不再用"当前事件"重配，避免分析层拿到别的事件的 payload/sid。
        for (event, alert) in engine.process(&ev) {
            if let Some(pipeline) = pipeline {
                pipeline.submit_alert(event, alert.clone());
            }
            write_alert(writer, &alert)?;
        }
        if let Some(pipeline) = pipeline {
            pipeline.sync_correlation_counts(engine);
        }
        let annotations = engine.intel_annotations(&ev);
        match pipeline {
            Some(pipeline) => pipeline.submit_file(ev, annotations),
            None => eprintln!(
                "xbits: file_triage skipped: 未启用分析流水线（需要 --file-spool-dir/--triage-cmd/--analysis-file 之一）；file_sha256={}",
                ev.file_sha256.as_deref().unwrap_or("")
            ),
        }
        return Ok(());
    }
    for (event, alert) in engine.process(&ev) {
        if let Some(pipeline) = pipeline {
            pipeline.submit_alert(event, alert.clone());
        }
        write_alert(writer, &alert)?;
    }
    if let Some(pipeline) = pipeline {
        pipeline.sync_correlation_counts(engine);
    }
    Ok(())
}

/// 处理一条连接：带 read_timeout 的读取循环 + 跨读/跨超时的**残留半行缓冲**。
///
/// R5-1：超时不是错误——超时即触发一次引擎维护（所以挂起告警的 TTL 不再依赖下一条事件）；
/// 同时半行 JSON 必须留在 `pending` 缓冲里，绝不因超时丢失。
///
/// R6-3：维护 tick 与"是否有数据到达"解耦。旧实现只在 `read` 超时时维护；客户端长期占住
/// 连接且持续有数据时 `read` 永不超时，维护（过期降级告警/计数）会被无限推迟。现在每次
/// 循环顶部按 `maintenance_tick` 截止时间检查，即使读取一直有数据也按时调用
/// [`maintenance`]（降级告警照常写回 `writer` 并投递流水线）。超时分支仍保留一次维护，
/// 保证空闲连接也按 tick 推进。
/// 生产 listener 已改用 [`run_listener_event_loop`]（多连接轮询）；本函数保留为
/// 单连接参考实现，被下面的 UnixStream 单测直接调用（R6-3/R6-4 回归）。
#[allow(dead_code)]
fn serve_stream<W: Write + ?Sized>(
    stream: UnixStream,
    engine: &mut Engine,
    pipeline: Option<&AnalysisPipeline>,
    writer: &mut W,
    stats: &mut StatsEmitter,
    maintenance_tick: Duration,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    // read_timeout 用同一 tick：空闲连接最迟一个 tick 也会被唤醒做维护。
    stream.set_read_timeout(Some(maintenance_tick))?;
    let mut reader = BufReader::new(stream);
    // R6-4：残留半行缓冲带单行上限；超长行整行丢弃并计数，连接继续服务后续行。
    let mut lines = LineBuffer::new();
    let mut reported_drops: u64 = 0;
    let mut stats_dropped_lines: u64 = 0;
    let mut stats_dropped_bytes: u64 = 0;
    let mut last_maintenance = Instant::now();
    let mut chunk = [0u8; 8192];
    loop {
        // R5-5：统计节拍与事件解耦——长连接持续有数据时也在循环顶部按 interval 输出，
        // 不依赖 accept 侧 tick（后者在长连接期间被 serve_stream 占用）。
        stats.maybe_emit(pipeline, engine)?;
        // R6-3：维护 tick 与数据到达解耦。持续有数据（read 不超时）时也必须按时维护。
        if last_maintenance.elapsed() >= maintenance_tick {
            maintenance(engine, pipeline, writer)?;
            last_maintenance = Instant::now();
        }
        match reader.read(&mut chunk) {
            Ok(0) => {
                // 对端关闭：把最后一行（可能没有换行符）也处理掉，然后结束连接。
                if let Some(line_bytes) = lines.finish() {
                    let line = String::from_utf8_lossy(&line_bytes);
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        handle_line(trimmed, engine, pipeline, writer)?;
                    }
                }
                break;
            }
            Ok(n) => {
                for line_bytes in lines.push(&chunk[..n]) {
                    let line = String::from_utf8_lossy(&line_bytes);
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    handle_line(trimmed, engine, pipeline, writer)?;
                }
                report_line_drops(&lines, &mut reported_drops);
                // R15-5：丢弃计数进 stats（限流 stderr 之外的稳定可解析出口）。
                let new_lines = lines.dropped_lines.saturating_sub(stats_dropped_lines);
                let new_bytes = lines.dropped_bytes.saturating_sub(stats_dropped_bytes);
                if new_lines > 0 || new_bytes > 0 {
                    stats.record_line_drops(new_lines, new_bytes);
                    stats_dropped_lines = lines.dropped_lines;
                    stats_dropped_bytes = lines.dropped_bytes;
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                // 空闲 tick：推进引擎维护（过期降级告警要能按时输出，R5-1）。
                maintenance(engine, pipeline, writer)?;
                last_maintenance = Instant::now();
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                // 与旧行为一致：读错误只结束当前连接，不拖垮整个 listener。
                eprintln!("xbits: hook read error: {err}");
                break;
            }
        }
    }
    Ok(())
}

/// 事件循环里一个已接入连接的状态（R6-2）：非阻塞读取 + 跨轮询保留的半行缓冲。
struct ActiveConnection {
    stream: UnixStream,
    lines: LineBuffer,
    /// 已写进 StatsEmitter 的累计丢弃数（避免每轮重复累加）。
    stats_dropped_lines: u64,
    stats_dropped_bytes: u64,
    reported_drops: u64,
}

enum PollOutcome {
    Data,
    Idle,
    Eof,
}

impl ActiveConnection {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            lines: LineBuffer::new(),
            stats_dropped_lines: 0,
            stats_dropped_bytes: 0,
            reported_drops: 0,
        })
    }

    /// 非阻塞读**一次**（最多一个 chunk），保证多连接轮询公平、accept 不被单个连接饿死。
    fn poll_once<W: Write + ?Sized>(
        &mut self,
        chunk: &mut [u8],
        engine: &mut Engine,
        pipeline: Option<&AnalysisPipeline>,
        writer: &mut W,
        stats: &mut StatsEmitter,
    ) -> io::Result<PollOutcome> {
        match self.stream.read(chunk) {
            Ok(0) => Ok(PollOutcome::Eof),
            Ok(n) => {
                for line_bytes in self.lines.push(&chunk[..n]) {
                    let line = String::from_utf8_lossy(&line_bytes);
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    handle_line(trimmed, engine, pipeline, writer)?;
                }
                report_line_drops(&self.lines, &mut self.reported_drops);
                // R15-5：按连接累计写入 stats（多连接时由下方 totals 汇总）。
                let new_lines = self
                    .lines
                    .dropped_lines
                    .saturating_sub(self.stats_dropped_lines);
                let new_bytes = self
                    .lines
                    .dropped_bytes
                    .saturating_sub(self.stats_dropped_bytes);
                if new_lines > 0 || new_bytes > 0 {
                    stats.record_line_drops(new_lines, new_bytes);
                    self.stats_dropped_lines = self.lines.dropped_lines;
                    self.stats_dropped_bytes = self.lines.dropped_bytes;
                }
                Ok(PollOutcome::Data)
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PollOutcome::Idle)
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => Ok(PollOutcome::Idle),
            Err(err) => {
                eprintln!("xbits: hook read error: {err}");
                Ok(PollOutcome::Eof)
            }
        }
    }

    fn finish<W: Write + ?Sized>(
        &mut self,
        engine: &mut Engine,
        pipeline: Option<&AnalysisPipeline>,
        writer: &mut W,
    ) -> io::Result<()> {
        if let Some(line_bytes) = self.lines.finish() {
            let line = String::from_utf8_lossy(&line_bytes);
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                handle_line(trimmed, engine, pipeline, writer)?;
            }
        }
        Ok(())
    }
}

/// accept + 多连接轮询事件循环（R6-2）。
///
/// 旧实现一次只 `serve_stream` 一条连接：第一条连接不发数据也不断开时，accept 永远
/// 不会执行，第二条连接即使已在 backlog 里也拿不到服务。这里改成非阻塞 accept +
/// 轮询所有连接（每连接每轮最多读一个 chunk），维护 tick 在外层独立推进：
/// - 空闲连接不会饿死 accept，也不会饿死维护（每 `maintenance_tick` 执行 `maintenance`）；
/// - 引擎仍是单线程 `&mut Engine`，不引入跨线程锁，保持判定顺序与单一状态源；
/// - `stop` 仅测试注入（生产传 None），用于让端到端测试优雅收尾。
fn run_listener_event_loop<W: Write + ?Sized>(
    socket_path: &str,
    mut engine: Engine,
    writer: &mut W,
    pipeline: Option<&AnalysisPipeline>,
    mut stats: StatsEmitter,
    maintenance_tick: Duration,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    let path = Path::new(socket_path);
    if path.exists() {
        let ft = std::fs::metadata(path)?.file_type();
        if !ft.is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{socket_path} exists and is not a Unix socket"),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let _guard = SocketFile {
        path: path.to_path_buf(),
    };
    listener.set_nonblocking(true)?;

    let mut connections: Vec<ActiveConnection> = Vec::new();
    let mut last_maintenance = Instant::now();
    // R15-5：已关闭连接的累计丢弃数（事件循环全程单调累加，避免关闭后从 stats 回落）。
    let mut closed_dropped_lines: u64 = 0;
    let mut closed_dropped_bytes: u64 = 0;
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(stop) = stop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }
        stats.maybe_emit(pipeline, &engine)?;
        if last_maintenance.elapsed() >= maintenance_tick {
            maintenance(&mut engine, pipeline, writer)?;
            last_maintenance = Instant::now();
        }

        let mut did_work = false;
        // 非阻塞 drain accept：第二条连接不会被第一条空闲连接挡住。
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    ensure_pipeline_healthy(pipeline, Some(&engine))?;
                    if connections.len() >= MAX_ACTIVE_CONNECTIONS {
                        eprintln!(
                            "xbits: hook active connection limit reached ({MAX_ACTIVE_CONNECTIONS}); dropping new connection"
                        );
                        drop(stream);
                    } else {
                        connections.push(ActiveConnection::new(stream)?);
                    }
                    did_work = true;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => break,
                Err(err) => return Err(err),
            }
        }

        // 轮询所有连接：每轮每连接最多读一个 chunk，避免某条连接独占循环。
        let mut i = 0;
        while i < connections.len() {
            match connections[i].poll_once(&mut chunk, &mut engine, pipeline, writer, &mut stats)? {
                PollOutcome::Data => {
                    did_work = true;
                    i += 1;
                }
                PollOutcome::Idle => i += 1,
                PollOutcome::Eof => {
                    connections[i].finish(&mut engine, pipeline, writer)?;
                    closed_dropped_lines = closed_dropped_lines
                        .saturating_add(connections[i].lines.dropped_lines);
                    closed_dropped_bytes = closed_dropped_bytes
                        .saturating_add(connections[i].lines.dropped_bytes);
                    connections.swap_remove(i);
                    did_work = true;
                }
            }
        }
        // R15-5：stats 里的 hook 行丢弃是跨连接累计；活动连接逐连接累加，关闭时并入 closed_*。
        // 用「当前总丢弃数」覆盖式写入（单调不减），避免多连接下重复累加。
        let mut total_lines = 0u64;
        let mut total_bytes = 0u64;
        for conn in &connections {
            total_lines = total_lines.saturating_add(conn.lines.dropped_lines);
            total_bytes = total_bytes.saturating_add(conn.lines.dropped_bytes);
        }
        stats.set_line_drops_total(
            total_lines.saturating_add(closed_dropped_lines),
            total_bytes.saturating_add(closed_dropped_bytes),
        );

        if !did_work {
            std::thread::sleep(ACCEPT_IDLE_SLEEP);
        }
    }

    // 停止时收尾所有连接（处理无换行的尾行），测试可据此安全 join。
    for mut conn in connections {
        conn.finish(&mut engine, pipeline, writer)?;
    }
    Ok(())
}

/// 测试专用 listener 入口（R6-2）：可注入短 TTL / tick 与 stop 标志。
/// 生产入口仍用 60s TTL + 200ms tick（`run_hook_listener_full` 不暴露这些参数）。
#[cfg(test)]
fn run_hook_listener_for_test<W: Write + ?Sized>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
    ttl: Duration,
    maintenance_tick: Duration,
    stop: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    let engine = Engine::new(rules).with_ttl(ttl);
    run_listener_event_loop(
        socket_path,
        engine,
        writer,
        None,
        StatsEmitter::disabled(),
        maintenance_tick,
        Some(stop),
    )
}

struct SocketFile {
    path: PathBuf,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 监听 Suricata/Zeek 薄 hook 插件推来的 JSONL 事件，交给中央引擎处理，
/// 把命中的引擎告警写到 `writer`（通常是 stdout，由 Zeek Input raw 消费）。
pub fn run_hook_listener<W: Write + ?Sized>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
) -> io::Result<()> {
    run_hook_listener_with_analysis(socket_path, rules, writer, None)
}

pub fn run_hook_listener_with_analysis<W: Write + ?Sized>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
    pipeline: Option<&AnalysisPipeline>,
) -> io::Result<()> {
    run_hook_listener_full(
        socket_path,
        rules,
        writer,
        pipeline,
        None,
        None,
        HookStatsConfig::default(),
    )
}

/// 完整版 listener：可挂载统一情报服务（threat-intel + allowlist）与 success_rules
/// 关联表（V-14 方案①），引擎告警将携带 intel / allowlist / correlated 标注。
#[allow(clippy::too_many_arguments)]
pub fn run_hook_listener_full<W: Write + ?Sized>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
    pipeline: Option<&AnalysisPipeline>,
    intel: Option<std::sync::Arc<crate::intel::IntelService>>,
    success_rules: Option<crate::engine::SuccessRules>,
    stats_config: HookStatsConfig,
) -> io::Result<()> {
    // R5-4：库 API 同样做加载期校验（`main.rs::load_rules` 已在带路径的上下文里校验过一次；
    // 这里防止其他调用方绕过 CLI 直接把非法规则塞进 listener）。
    crate::model::validate_rules(&rules)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("bad rules: {err}")))?;
    // R5-5：统计文件创建失败即启动失败，不静默退化成"间隔开着但没输出"。
    if !stats_config.interval.is_zero() {
        let sink = match &stats_config.file {
            Some(path) => path.to_string_lossy().into_owned(),
            None => "stderr".to_string(),
        };
        eprintln!(
            "xbits: runtime stats every {:?} -> {sink} (one JSON line per tick)",
            stats_config.interval
        );
    }
    let stats = StatsEmitter::new(stats_config)?;

    let mut engine = Engine::new(rules);
    if let Some(ref intel) = intel {
        engine = engine.with_intel(intel.clone());
    }
    if let Some(success) = success_rules {
        eprintln!(
            "xbits: success_rules correlation enabled (V-14): response_rules={}, request_sids covered",
            success.len()
        );
        engine = engine.with_success_rules(success);
    }
    // 情报状态逐项打印：未配置 / 读取失败 / 为空 / 已加载 四态可区分，
    // 不再用一个会撒谎的布尔（例如只加载了 5 万条域名却打印 intel=empty）。
    if let Some(ref svc) = intel {
        for line in svc.report() {
            eprintln!("xbits: {line}");
        }
    } else {
        eprintln!("xbits: intel=off (未挂载情报服务)");
    }
    let intel_state = intel
        .as_ref()
        .map(|svc| svc.state().as_str())
        .unwrap_or("off");
    eprintln!(
        "xbits: hook listener on {} (rules={}, intel={})",
        socket_path,
        engine.rules_len(),
        intel_state
    );

    // R5-1/R6-2：非阻塞 accept + 多连接轮询；维护 tick 在事件循环外层独立推进，
    // 空闲连接既不会饿死 accept，也不会饿死维护。
    run_listener_event_loop(
        socket_path,
        engine,
        writer,
        pipeline,
        stats,
        MAINTENANCE_TICK,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// 测试用共享输出缓冲：listener 线程写、测试主线程随时读（R6-2 端到端）。
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        fn text(&self) -> String {
            let guard = self.0.lock().expect("shared buf");
            String::from_utf8_lossy(guard.as_slice()).into_owned()
        }
    }

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("shared buf").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn temp_socket_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "xbits-hook-{tag}-{}-{nanos}.sock",
            std::process::id()
        ))
    }

    fn wait_for_socket(path: &Path) {
        for _ in 0..300 {
            if path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("listener socket not created: {}", path.display());
    }

    fn wait_until<F: Fn() -> bool>(timeout: Duration, predicate: F) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn line_buffer_splits_complete_lines_across_chunks() {
        let mut lines = LineBuffer::new();
        assert!(lines.push(b"{\"a\":1").is_empty(), "半行不返回");
        let got = lines.push(b"}\n{\"b\":2}\n");
        assert_eq!(
            got,
            vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()],
            "跨 chunk 的半行必须拼成完整行"
        );
        assert_eq!(lines.dropped_lines, 0);
        assert_eq!(lines.finish(), None);
    }

    #[test]
    fn line_buffer_returns_unterminated_tail_on_finish() {
        let mut lines = LineBuffer::new();
        assert!(lines.push(b"tail-without-newline").is_empty());
        assert_eq!(
            lines.finish(),
            Some(b"tail-without-newline".to_vec()),
            "EOF 尾行（无换行）仍须处理"
        );
        assert_eq!(lines.finish(), None, "finish 后不得重复返回");
    }

    #[test]
    fn overlong_line_without_newline_is_bounded_and_dropped() {
        // R6-4：持续发送无换行超长数据不得无界占内存；超限后整行丢弃并计数。
        let mut lines = LineBuffer::new();
        let chunk = vec![b'a'; 64 * 1024];
        for _ in 0..64 {
            assert!(lines.push(&chunk).is_empty());
            assert!(
                lines.buf.len() <= MAX_LINE_BYTES,
                "行缓冲必须有界: {}",
                lines.buf.len()
            );
        }
        assert_eq!(lines.dropped_lines, 1, "超长行只计一次");
        assert!(
            lines.dropped_bytes > MAX_LINE_BYTES as u64,
            "丢弃字节数必须累计: {}",
            lines.dropped_bytes
        );
        assert!(lines.discarding, "无换行超长输入必须进入丢弃模式");

        // 后续正常行仍被处理：换行结束丢弃行，下一行完整返回。
        let got = lines.push(b"\n{\"ok\":true}\n");
        assert_eq!(got, vec![b"{\"ok\":true}".to_vec()]);
        assert_eq!(lines.dropped_lines, 1, "恢复后不得重复计数");
        assert!(!lines.discarding);
    }

    #[test]
    fn overlong_line_in_single_chunk_does_not_emit_partial_line() {
        let mut lines = LineBuffer::new();
        let mut data = vec![b'x'; MAX_LINE_BYTES + 1];
        data.push(b'\n');
        data.extend_from_slice(b"{\"after\":1}\n");
        let got = lines.push(&data);
        assert_eq!(
            got,
            vec![b"{\"after\":1}".to_vec()],
            "超长行不得以截断形式交给解析器"
        );
        assert_eq!(lines.dropped_lines, 1);
        assert_eq!(lines.finish(), None);
    }

    #[test]
    fn line_drop_report_is_first_then_per_thousand() {
        let mut lines = LineBuffer::new();
        lines.dropped_lines = 1;
        let mut reported = 0;
        report_line_drops(&lines, &mut reported);
        assert_eq!(reported, 1, "首次丢弃必须可见（不静默）");
        lines.dropped_lines = 2;
        report_line_drops(&lines, &mut reported);
        assert_eq!(reported, 1, "第 2 次不刷屏");
        lines.dropped_lines = 1000;
        report_line_drops(&lines, &mut reported);
        assert_eq!(reported, 1000, "每 1000 行汇总一次");
    }

    #[test]
    fn serve_stream_survives_overlong_line_and_processes_next_event() {
        // R6-4 自测（真实 Unix stream）：无换行超长输入不得拖垮连接，换行后的正常事件照常产出告警。
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r-ok","name":"ok","source":"suricata","kind":"alert","sid_in":[9103001],"score":20,"threshold":20}"#,
        )
        .expect("rule");
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let handle = std::thread::spawn(move || {
            let mut engine = Engine::new(vec![rule]);
            let mut out = Vec::new();
            serve_stream(
                server,
                &mut engine,
                None,
                &mut out,
                &mut StatsEmitter::disabled(),
                MAINTENANCE_TICK,
            )
            .expect("serve");
            out
        });
        let overlong = vec![b'x'; MAX_LINE_BYTES + 64 * 1024];
        client.write_all(&overlong).expect("write overlong line");
        client.write_all(b"\n").expect("terminate dropped line");
        client
            .write_all(
                br#"{"source":"suricata","kind":"alert","sid":9103001,"signature":"SQL","community_id":"1:cid="}"#,
            )
            .expect("write valid event");
        client.write_all(b"\n").expect("terminate valid event");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let out = handle.join().expect("server thread");
        let text = String::from_utf8(out).expect("utf-8 alerts");
        let alerts: Vec<_> = text.lines().collect();
        assert_eq!(
            alerts.len(),
            1,
            "超长行不得产出告警，后续正常行必须产出一条: {text}"
        );
        assert!(
            alerts[0].contains("\"rule_id\":\"r-ok\""),
            "正常事件的告警必须来自后续行: {text}"
        );
    }

    #[test]
    fn long_connection_still_runs_maintenance_tick() {
        // R6-3：客户端持续写入（间隔 1ms < read_timeout 5ms，read 永不超时）时，
        // 解耦的维护 tick 仍须按 5ms 执行：20ms TTL 的挂起告警要输出降级告警。
        // 同时最后一条事件分两次写入（半行 + 尾），验证长连接期间半行缓冲不丢数据。
        let ctx_rule: Rule = serde_json::from_str(
            r#"{"id":"r-ctx","name":"ctx","source":"suricata","kind":"alert","sid_in":[9103001],"score":20,"threshold":20,"reason":"ctx","require_context":true}"#,
        )
        .expect("ctx rule");
        let direct_rule: Rule = serde_json::from_str(
            r#"{"id":"r-direct","name":"direct","source":"suricata","kind":"alert","sid_in":[9103002],"score":20,"threshold":20,"reason":"direct"}"#,
        )
        .expect("direct rule");
        let engine = Engine::new(vec![ctx_rule, direct_rule]).with_ttl(Duration::from_millis(20));
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let handle = std::thread::spawn(move || {
            let mut engine = engine;
            let mut out = Vec::new();
            serve_stream(
                server,
                &mut engine,
                None,
                &mut out,
                &mut StatsEmitter::disabled(),
                Duration::from_millis(5),
            )
            .expect("serve");
            (out, engine)
        });

        // 先验证半行缓冲：一条命中 direct 规则的告警分两次写入（此时还没有 pending）。
        client
            .write_all(br#"{"source":"suricata","kind":"alert","sid":9103002,"signature":"HALF""#)
            .expect("half line");
        client
            .write_all(b",\"community_id\":\"1:cidH=\"}\n")
            .expect("finish half line");

        // 再制造一条挂起告警（require_context 规则等不到上下文）。
        client
            .write_all(
                br#"{"source":"suricata","kind":"alert","sid":9103001,"signature":"SQL","community_id":"1:cid="}"#,
            )
            .expect("write pending alert");
        client.write_all(b"\n").expect("newline");

        // 持续写入空行：read 不超时，但不会进入 handle_line/engine.process，
        // 因此只有解耦的维护 tick 能推进 prune（旧实现此路径永远不维护；
        // 末尾也不再有任何会被 process 的事件，避免 prune 由事件路径兜底）。
        for _ in 0..80 {
            client.write_all(b"\n").expect("write blank line");
            std::thread::sleep(Duration::from_millis(1));
        }
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

        let (out, engine) = handle.join().expect("server thread");
        let text = String::from_utf8(out).expect("utf-8 output");
        assert!(
            text.contains("\"degraded\":\"context-missing\""),
            "长连接持续写入时维护 tick 必须执行并输出降级告警: {text}"
        );
        assert!(engine.pending_expired() >= 1, "过期 pending 必须计数");
        assert!(
            text.contains("\"signature_id\":9103002"),
            "半行缓冲不得丢数据（后半行事件必须产出告警）: {text}"
        );
    }

    // ---- R6-2：listener 外层 accept / 空闲维护的端到端覆盖（真实 Unix socket） ----

    #[test]
    fn listener_idle_connection_still_runs_maintenance_tick() {
        // R6-2 场景①：客户端发一条 alert 后保持空闲（不断开、不再发数据），
        // listener 外层维护 tick 仍须在 TTL 后输出 degraded=context-missing。
        let ctx_rule: Rule = serde_json::from_str(
            r#"{"id":"r-ctx","name":"ctx","source":"suricata","kind":"alert","sid_in":[9103001],"score":20,"threshold":20,"reason":"ctx","require_context":true}"#,
        )
        .expect("ctx rule");
        let path = temp_socket_path("idle-maint");
        let path_string = path.to_string_lossy().into_owned();
        let out = SharedBuf::default();
        let out_thread = out.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut writer = out_thread;
            run_hook_listener_for_test(
                &path_string,
                vec![ctx_rule],
                &mut writer,
                Duration::from_millis(20),
                Duration::from_millis(5),
                &stop_thread,
            )
        });

        wait_for_socket(&path);
        let mut client = UnixStream::connect(&path).expect("connect");
        client
            .write_all(
                br#"{"source":"suricata","kind":"alert","sid":9103001,"signature":"SQL","community_id":"1:cid="}"#,
            )
            .expect("write alert");
        client.write_all(b"\n").expect("newline");
        // 保持连接空闲（不发数据、不 shutdown）。
        let ok = wait_until(Duration::from_secs(3), || {
            out.text().contains("\"degraded\":\"context-missing\"")
        });
        assert!(
            ok,
            "空闲连接期间 listener 维护 tick 必须执行并输出降级告警: {}",
            out.text()
        );

        stop.store(true, Ordering::Relaxed);
        handle.join().expect("listener thread").expect("listener ok");
        drop(client);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_accepts_second_connection_while_first_idle() {
        // R6-2 场景②：第一条连接不发任何数据直接空闲，accept 侧仍能接入并服务第二个连接
        // （旧单连接 serve_stream 实现会一直卡在第一条连接，第二个连接永远不被 accept）。
        let direct_rule: Rule = serde_json::from_str(
            r#"{"id":"r-direct","name":"direct","source":"suricata","kind":"alert","sid_in":[9103002],"score":20,"threshold":20,"reason":"direct"}"#,
        )
        .expect("direct rule");
        let path = temp_socket_path("idle-accept");
        let path_string = path.to_string_lossy().into_owned();
        let out = SharedBuf::default();
        let out_thread = out.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut writer = out_thread;
            run_hook_listener_for_test(
                &path_string,
                vec![direct_rule],
                &mut writer,
                Duration::from_secs(60),
                Duration::from_millis(5),
                &stop_thread,
            )
        });

        wait_for_socket(&path);
        let idle_first = UnixStream::connect(&path).expect("first connect");
        // 让 listener 先 accept 并进入对第一条连接的轮询（保持空闲）。
        std::thread::sleep(Duration::from_millis(80));

        let mut second = UnixStream::connect(&path).expect("second connect");
        second
            .write_all(
                br#"{"source":"suricata","kind":"alert","sid":9103002,"signature":"DIRECT","community_id":"1:cid2="}"#,
            )
            .expect("write second alert");
        second.write_all(b"\n").expect("newline");
        let ok = wait_until(Duration::from_secs(3), || {
            out.text().contains("\"signature_id\":9103002")
        });
        assert!(
            ok,
            "第一条空闲连接不得饿死 accept：第二个连接必须被服务并产出告警: {}",
            out.text()
        );

        stop.store(true, Ordering::Relaxed);
        handle.join().expect("listener thread").expect("listener ok");
        drop(idle_first);
        drop(second);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stats_json_has_stable_schema_and_fields() {
        // R5-5：单行 JSON 的字段固定（无流水线时 analysis=null，schema 仍在）。
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r-ok","name":"ok","source":"suricata","kind":"alert","score":20,"threshold":20}"#,
        )
        .expect("rule");
        let engine = Engine::new(vec![rule]);
        let json = stats_json(None, &engine, 1_700_000_000_123);
        assert_eq!(json.lines().count(), 1, "stats 必须单行: {json}");
        let v: serde_json::Value = serde_json::from_str(&json).expect("stats json");
        assert_eq!(v["event"], "xbits.stats");
        assert_eq!(v["ts_unix_ms"].as_u64(), Some(1_700_000_000_123));
        assert!(v["analysis"].is_null(), "无流水线时 schema 仍保留 analysis 字段");
        let eng = &v["engine"];
        for key in [
            "rules",
            "pending",
            "contexts",
            "scores",
            "correlations",
            "pending_expired",
            "pending_overflow",
            "contexts_expired",
            "scores_expired",
            "scores_evicted",
            "correlation_pairs",
            "correlation_timeouts",
            "correlation_overflow",
            "correlation_unmatched_responses",
        ] {
            assert!(eng.get(key).is_some(), "engine.{key} 缺失: {json}");
        }
        assert_eq!(eng["rules"].as_u64(), Some(1));
        assert_eq!(eng["pending"].as_u64(), Some(0));
        // R15-5：hook 丢弃计数字段必须始终存在（无丢弃时为 0，schema 稳定）。
        assert_eq!(v["hook_lines_dropped"].as_u64(), Some(0), "{json}");
        assert_eq!(v["hook_lines_dropped_bytes"].as_u64(), Some(0), "{json}");
    }

    #[test]
    fn stats_json_exposes_analysis_health_fields() {
        // 有流水线时 analysis.* 全部可读（ PipelineHealth 的正常态也要可观测）。
        let pipeline = crate::analysis::AnalysisPipeline::start(
            crate::analysis::AnalysisConfig::default(),
        )
        .expect("start pipeline");
        let engine = Engine::new(vec![]);
        let json = stats_json(Some(&pipeline), &engine, 7);
        let v: serde_json::Value = serde_json::from_str(&json).expect("stats json");
        let analysis = &v["analysis"];
        assert_eq!(analysis["available"].as_bool(), Some(true), "{json}");
        for key in [
            "send_failures",
            "document_errors",
            "documents_without_sink",
            "config_errors",
            "triage_dropped",
            "triage_timeouts",
            "pending_expired",
            "pending_overflow",
            "correlated_pairs",
            "correlation_timeouts",
        ] {
            assert!(analysis.get(key).is_some(), "analysis.{key} 缺失: {json}");
        }
    }

    #[test]
    fn stats_emitter_respects_interval_and_writes_one_json_line() {
        let dir = std::env::temp_dir().join(format!(
            "xbits-stats-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("stats.jsonl");
        let engine = Engine::new(vec![]);

        // 默认 0 = 关闭：连文件都不创建，保持既有 stderr 契约。
        let mut off = StatsEmitter::new(HookStatsConfig {
            interval: Duration::ZERO,
            file: Some(path.clone()),
        })
        .expect("emitter");
        off.maybe_emit(None, &engine).expect("emit off");
        assert!(!path.exists(), "默认关闭时不得创建统计文件");

        // 间隔未到不输出。
        let mut slow = StatsEmitter::new(HookStatsConfig {
            interval: Duration::from_secs(3600),
            file: Some(path.clone()),
        })
        .expect("emitter");
        slow.maybe_emit(None, &engine).expect("emit slow");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "");

        // 间隔到达后写一行可解析 JSON。
        let mut fast = StatsEmitter::new(HookStatsConfig {
            interval: Duration::from_millis(1),
            file: Some(path.clone()),
        })
        .expect("emitter");
        std::thread::sleep(Duration::from_millis(5));
        fast.maybe_emit(None, &engine).expect("emit fast");
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1, "一次 tick 只写一行: {text}");
        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("stats json");
        assert_eq!(v["event"], "xbits.stats");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_counts_dropped_lines_from_line_buffer() {
        // R15-5：超长行丢弃计数必须进 stats——字段存在、随丢弃递增。
        let engine = Engine::new(vec![]);
        let mut lines = LineBuffer::new();
        let mut emitter = StatsEmitter::disabled(); // 计数照记，只是不输出

        // 4 MiB 无换行 → 1 行被丢弃。
        let chunk = vec![b'a'; 64 * 1024];
        for _ in 0..64 {
            assert!(lines.push(&chunk).is_empty());
        }
        emitter.set_line_drops_total(lines.dropped_lines, lines.dropped_bytes);
        let snapshot = self::stats_snapshot_with_drops(
            None,
            &engine,
            1,
            emitter.lines_dropped,
            emitter.lines_dropped_bytes,
        );
        assert_eq!(snapshot.hook_lines_dropped, 1, "一行超长输入 = 一次丢弃");
        assert!(
            snapshot.hook_lines_dropped_bytes > MAX_LINE_BYTES as u64,
            "丢弃字节数必须累计"
        );

        // 恢复后再丢一行：计数递增。
        let _ = lines.push(b"\n");
        let mut data = vec![b'x'; MAX_LINE_BYTES + 1];
        data.push(b'\n');
        let got = lines.push(&data);
        // 对照（R15-5 修正）：这条超长行同样应被丢弃（不产出行），且丢弃计数
        // 递增到 2；"正常行不受影响"改用下方的小行验证。
        assert!(got.is_empty(), "超过 MAX_LINE_BYTES 的行必须被丢弃");
        emitter.set_line_drops_total(lines.dropped_lines, lines.dropped_bytes);
        let snapshot = self::stats_snapshot_with_drops(
            None,
            &engine,
            2,
            emitter.lines_dropped,
            emitter.lines_dropped_bytes,
        );
        assert_eq!(
            snapshot.hook_lines_dropped, 2,
            "第二次丢弃必须递增计数"
        );

        // 正常行不受影响：小行照常产出，丢弃计数不再变化。
        let mut small = vec![b'k'; 16];
        small.push(b'\n');
        let got_small = lines.push(&small);
        assert_eq!(got_small.len(), 1, "正常行不受影响（对照）");
        emitter.set_line_drops_total(lines.dropped_lines, lines.dropped_bytes);
        assert_eq!(emitter.lines_dropped, 2, "正常行不得计入丢弃");

        // 序列化进单行 JSON 的字段可见。
        let json = serde_json::to_string(&snapshot).expect("serialize");
        assert!(json.contains("\"hook_lines_dropped\":2"), "{json}");
        assert!(json.contains("\"hook_lines_dropped_bytes\":"), "{json}");
    }

    #[test]
    fn failure_stats_export_correlation_counters() {
        // R12-4：hook 故障消息必须带关联计数；"只发响应无请求"路径不再静默。
        let success = crate::engine::SuccessRules::parse(
            r#"[{"sid":14030020,"depends":[14030019]}]"#,
        )
        .expect("success rules");
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r-corr","name":"corr","source":"suricata","kind":"alert","sid_in":[14030020],"score":20,"threshold":20}"#,
        )
        .expect("rule");
        let mut engine = Engine::new(vec![rule]).with_success_rules(success);
        let response_only = HookEvent {
            source: "suricata".into(),
            kind: "alert".into(),
            sid: Some(14030020),
            community_id: Some("1:cidR=".into()),
            ..Default::default()
        };
        let _ = engine.process(&response_only);
        let stats = engine_failure_stats(Some(&engine));
        assert!(stats.contains("correlated_pairs=0"), "{stats}");
        assert!(stats.contains("correlation_timeouts=0"), "{stats}");
        assert!(stats.contains("correlation_overflow=0"), "{stats}");
        assert!(
            stats.contains("correlation_unmatched_responses=1"),
            "只发响应无请求必须计数: {stats}"
        );
        assert!(stats.contains("engine_scores_evicted="), "{stats}");
        assert_eq!(engine_failure_stats(None), "");
    }
}
