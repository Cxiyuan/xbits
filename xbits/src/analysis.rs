use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::EngineAlert;
use crate::intel::EventIntelAnnotations;
use crate::model::HookEvent;

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub validator_command: Option<String>,
    pub validator_timeout: Duration,
    pub sid_library: Option<PathBuf>,
    pub rules_meta: Option<PathBuf>,
    pub es_url: Option<String>,
    pub es_command: Option<String>,
    pub es_auth: Option<String>,
    pub analysis_file: Option<PathBuf>,
    pub match_buffers: Option<PathBuf>,
    pub suppression_ttl: Duration,
    pub fp_confidence: u64,
    pub max_payload: usize,
    /// 等 match_context 到达的最长时间；超时按 fail-closed 判定。
    pub pending_context_timeout: Duration,
    // ---- 静态 triage 编排 ----
    /// 调用静态 triage 的外部命令（stdin 收 {path,...}，stdout 回 triage JSON）。
    pub triage_command: Option<String>,
    pub triage_timeout: Duration,
    /// Suricata file-store 落盘目录；用于按 sha256 定位转存文件。
    pub file_spool_dir: Option<PathBuf>,
    /// 只对这些文件类别（binary/script/document/archive）做 triage；空=全部。
    pub triage_categories: Vec<String>,
    /// triage 结果缓存 TTL，同一文件（sha256）不重复分析。
    pub triage_cache_ttl: Duration,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            validator_command: None,
            validator_timeout: Duration::from_secs(5),
            sid_library: None,
            rules_meta: None,
            es_url: None,
            es_command: None,
            es_auth: None,
            analysis_file: None,
            match_buffers: None,
            suppression_ttl: Duration::from_secs(300),
            fp_confidence: 90,
            max_payload: 16384,
            pending_context_timeout: Duration::from_millis(500),
            triage_command: None,
            triage_timeout: Duration::from_secs(30),
            file_spool_dir: None,
            triage_categories: vec![
                "binary".into(),
                "script".into(),
                "document".into(),
                "archive".into(),
            ],
            triage_cache_ttl: Duration::from_secs(3600),
        }
    }
}

/// 连续多少次 `tx.send` 失败后判定流水线不可用。
const SEND_FAILURE_THRESHOLD: u64 = 3;

/// 无 sink 文档向 stderr 输出的上限（避免刷屏；计数始终累加）。
const NO_SINK_STDERR_LIMIT: u64 = 5;

/// 分析流水线健康状态：可计数、可探测、可失败。
///
/// - `available`：分析线程是否仍在工作（启动置 true，panic/退出置 false）；
/// - `reason`：不可用的原因（只记录第一次，供运维定位）；
/// - `send_failures` / `consecutive_send_failures`：入队失败计数；
/// - `document_errors`：审计文件打开/写入失败、文档序列化失败、ES 推送失败；
/// - `documents_without_sink`：没有任何 sink 可写的文档数（不得静默丢文档）；
/// - `config_errors`：`--match-buffers` / `--sid-library` / `--rules-meta` 读取或解析失败；
/// - `triage_dropped`：triage 队列满或 worker 不可用导致丢弃的文件任务数；
/// - `triage_timeouts`：triage 外部命令超时次数（与 bad-json 严格区分）。
#[derive(Debug, Default)]
pub struct PipelineHealth {
    available: AtomicBool,
    send_failures: AtomicU64,
    consecutive_send_failures: AtomicU64,
    document_errors: AtomicU64,
    documents_without_sink: AtomicU64,
    config_errors: AtomicU64,
    triage_dropped: AtomicU64,
    triage_timeouts: AtomicU64,
    reason: Mutex<Option<String>>,
}

impl PipelineHealth {
    fn new() -> Self {
        Self::default()
    }

    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    pub fn failure_reason(&self) -> Option<String> {
        self.reason.lock().ok().and_then(|guard| guard.clone())
    }

    pub fn send_failures(&self) -> u64 {
        self.send_failures.load(Ordering::Relaxed)
    }

    pub fn document_errors(&self) -> u64 {
        self.document_errors.load(Ordering::Relaxed)
    }

    pub fn documents_without_sink(&self) -> u64 {
        self.documents_without_sink.load(Ordering::Relaxed)
    }

    pub fn config_errors(&self) -> u64 {
        self.config_errors.load(Ordering::Relaxed)
    }

    pub fn triage_dropped(&self) -> u64 {
        self.triage_dropped.load(Ordering::Relaxed)
    }

    pub fn triage_timeouts(&self) -> u64 {
        self.triage_timeouts.load(Ordering::Relaxed)
    }

    fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::Relaxed);
    }

    /// 标记流水线不可用并记录原因（原因只记第一次，同时向 stderr 报一次）。
    fn fail(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.set_available(false);
        if let Ok(mut guard) = self.reason.lock() {
            if guard.is_none() {
                eprintln!("xbits: analysis pipeline unavailable: {reason}");
                *guard = Some(reason);
            }
        }
    }

    fn note_send_success(&self) {
        self.consecutive_send_failures.store(0, Ordering::Relaxed);
    }

    fn record_send_failure(&self) -> u64 {
        self.send_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_send_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    fn record_document_error(&self) {
        self.document_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn record_document_without_sink(&self) -> u64 {
        self.documents_without_sink
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    fn record_config_error(&self) {
        self.config_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn record_triage_dropped(&self) {
        self.triage_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn record_triage_timeout(&self) {
        self.triage_timeouts.fetch_add(1, Ordering::Relaxed);
    }
}

/// 取 panic payload 的可读描述（用于把分析线程的 panic 记录为退出原因）。
fn describe_panic(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "unknown panic payload".to_string()
}

/// 合法文件哈希：`[0-9a-f]{32,64}` 且长度为 32/40/64（md5/sha1/sha256）。
/// 用于拒绝不可信的 `file_sha256`，避免对非 char 边界做字节切片。
fn is_hex_hash(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ValidatorDecision {
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub confidence: Option<u64>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct RuleMeta {
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MatchBufferMeta {
    #[serde(default)]
    buffers: Vec<String>,
    /// 该 SID 的主 buffer（最具体的应用层 buffer），用于诊断与证据标注。
    #[serde(default)]
    primary: Option<String>,
    /// 该 SID 是否以 payload/stream/file.data/lua 作为匹配信号之一。
    /// 用于精确诊断：payload 类 buffer 取不到值时提示 EVE payload 日志可能未开。
    #[serde(default)]
    has_payload: bool,
    #[serde(default)]
    source: Option<String>,
    /// true: 规则以 app-layer Lua（match(args) 形式）挂载在事务上，
    /// 没有单一精确 buffer 可导出，补丁层明确不做近似导出。
    /// 该类规则不参与抑制，判定仍走 validator。
    #[serde(default)]
    app_tx_lua: bool,
}

struct Decision {
    verdict: String,
    confidence: u64,
    /// 决策依据（intel-* 优先；没有情报决策时才可能被 validator 结论替换）。
    reason: String,
    evidence: Vec<String>,
    validator_used: bool,
    /// validator 自己给出的 reason（单独记录，绝不用来覆盖 intel-* 决策依据）。
    validator_reason: Option<String>,
}

/// 是否允许把该误报判定写入抑制白名单。
/// 只有明确 false_positive 且置信度达到 fp_confidence 门槛才允许，
/// 防止低置信 FP 误杀后续真实威胁。
fn may_whitelist(decision: &Decision, fp_confidence: u64) -> bool {
    decision.is_false_positive() && decision.confidence >= fp_confidence
}

impl Decision {
    fn is_false_positive(&self) -> bool {
        self.verdict.eq_ignore_ascii_case("false_positive") || self.verdict.eq_ignore_ascii_case("false-positive")
    }
}

/// 把引擎的情报决策标签映射到分析文档的 `reason`（决策依据要能被 ES 侧看到）。
///
/// 映射关系与 `engine.rs` 的 `INTEL_*` 增量一一对应：
/// - `allowlist-downgraded` → `intel-allowlist`（白名单命中，置信度已扣减）
/// - `threat-hit` → `intel-threat`（威胁命中，score/confidence 已加权）
/// - `threat-overrides-allowlist` → `intel-threat-allowlist-conflict`（两者同时命中，取威胁）
fn intel_reason(alert: &EngineAlert) -> Option<String> {
    let label = alert.intel_decision.as_deref()?;
    let reason = match label {
        "allowlist-downgraded" => "intel-allowlist",
        "threat-hit" => "intel-threat",
        "threat-overrides-allowlist" => "intel-threat-allowlist-conflict",
        other => return Some(format!("intel-{other}")),
    };
    Some(reason.to_string())
}

struct MatchContextEntry {
    value: String,
    at: Instant,
}

/// match_context-only buffer 集合：EVE/Zeek 没有等价字段（或等价字段不可靠），
/// 精确值只能来自核心补丁导出。buffer_value 对这些一律返回 None。
const CONTEXT_ONLY_BUFFERS: &[&str] = &[
    "lua",
    "http.header",
    "http.request_header",
    "http.response_header",
    "http.header.raw",
    "http.cookie",
    "file.data",
    "http.uri.raw",
    "dns.rrtype",
    "tls.alpn",
];

fn is_context_only(buffer: &str) -> bool {
    CONTEXT_ONLY_BUFFERS.contains(&buffer)
}

/// 把 Suricata 内部 buffer 名（ DetectEngineBufferTypeGetNameById 返回，
/// 形如 http_uri / file_data / http_raw_uri / dns_query）归一到 match_buffers.json 使用的
/// 统一名（http.uri / file.data / http.uri.raw / dns.query）。
/// 必须与 规则检测/build_match_buffers.py 的 ALIASES 保持一致。
/// 已验证的内部注册名（Suricata 8.0.8 源码）：
///   http_uri / http_raw_uri / http_header / http_raw_header / file_data
///   dns_query(rust multi-buffer) / dns.rrtype / tls.alpn（点号直注）
fn canonical_buffer_name(name: &str) -> &str {
    match name {
        "http_uri" => "http.uri",
        "http_raw_uri" => "http.uri.raw",
        "http_method" => "http.method",
        "http_cookie" => "http.cookie",
        "http_raw_cookie" => "http.cookie",
        "http_client_body" => "http.request_body",
        "http_server_body" => "http.response_body",
        "http_header" => "http.header",
        "http_raw_header" => "http.header",
        "http_host" => "http.host",
        "http_raw_host" => "http.host",
        "http_user_agent" => "http.user_agent",
        "http_stat_code" => "http.status",
        "http_stat_msg" => "http.status_msg",
        "file_data" => "file.data",
        "dns_query" => "dns.query",
        other => other,
    }
}

fn match_context_key(event: &HookEvent) -> Option<String> {
    let buffer = event.match_context_buffer.as_deref()?;
    let buffer = canonical_buffer_name(buffer);
    Some(format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        event.source,
        event.sid.unwrap_or(0),
        event.src.clone().unwrap_or_default(),
        event.sport.unwrap_or(0),
        event.dst.clone().unwrap_or_default(),
        event.dport.unwrap_or(0),
        event.proto.clone().unwrap_or_default(),
        buffer
    ))
}

struct SuppressionEntry {
    expires_at: Instant,
}

struct SuppressionStore {
    ttl: Duration,
    entries: HashMap<String, SuppressionEntry>,
}

impl SuppressionStore {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    fn contains(&mut self, key: &str) -> bool {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.entries.contains_key(key)
    }

    fn add(&mut self, key: String) {
        self.entries.insert(
            key,
            SuppressionEntry {
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

fn buffer_value(event: &HookEvent, alert: &EngineAlert, buffer: &str) -> Option<String> {
    let ctx = alert
        .context
        .as_ref()
        .and_then(|value| serde_json::from_value::<HookEvent>(value.clone()).ok());
    let pick = |e: &HookEvent, field: &str| -> Option<String> {
        match field {
            // EVE payload 与规则 payload/stream buffer 等价（包级 Base64）。
            "payload" | "stream" => e.payload.clone(),
            // EVE 的 http.url 是归一化 URI，与 http.uri 精确等价；
            // http.uri.raw 必须来自 match_context 导出，禁止用归一化值兜底。
            "http.uri" => e.uri.clone(),
            "http.host" => e.host.clone(),
            "http.method" => e.method.clone(),
            "http.user_agent" => e.user_agent.clone(),
            "http.request_body" => e.request_body.clone(),
            "http.response_body" => e.response_body.clone(),
            "dns.query" | "dns.queries.rrname" => e.dns_query.clone(),
            "tls.sni" => e.sni.clone(),
            "http.status" | "http.stat_code" => e.status.map(|v| v.to_string()),
            // 以下 buffer 的精确值只来自 match_context 导出；
            // EVE 没有等价字段，禁止用近似值兜底。
            b if is_context_only(b) => None,
            _ => None,
        }
    };
    pick(event, buffer).or_else(|| ctx.as_ref().and_then(|e| pick(e, buffer)))
}

fn suppression_key(
    event: &HookEvent,
    alert: &EngineAlert,
    meta: Option<&MatchBufferMeta>,
    contexts: &HashMap<String, MatchContextEntry>,
) -> Option<String> {
    // 没有 match_buffers 元数据的 SID 一律不建立白名单 key：
    // 禁止退化为“有 payload 就当 payload 规则”的猜测行为。
    let buffers: Vec<String> = meta.map(|m| m.buffers.clone()).unwrap_or_default();
    if buffers.is_empty() {
        return None;
    }
    let mut parts = vec![
        event.source.clone(),
        alert.signature_id.to_string(),
        alert.signature.clone(),
        alert.src.clone(),
        alert.sport.to_string(),
        alert.dst.clone(),
        alert.dport.to_string(),
        alert.proto.clone(),
        alert.uid.clone().unwrap_or_default(),
    ];
    for buffer in buffers {
        // 元数据里的名字已是统一名；再次归一保证与 observe() 的缓存 key 完全一致。
        let canonical = canonical_buffer_name(&buffer);
        let context_key = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            event.source,
            alert.signature_id,
            alert.src,
            alert.sport,
            alert.dst,
            alert.dport,
            alert.proto,
            canonical
        );
        // 导出的 match_context 是规则实际命中的 buffer 值，永远优先；
        // EVE/Zeek 等价字段只在导出缺失时作为可靠等价物使用，
        // lua/http.header/file.data 只接受导出值，不接受任何近似。
        let value = contexts.get(&context_key).map(|e| e.value.clone()).or_else(|| {
            buffer_value(event, alert, &buffer).or_else(|| {
                let ctx = alert.context.as_ref()?;
                let ctx_event: HookEvent = serde_json::from_value(ctx.clone()).ok()?;
                match buffer.as_str() {
                    "http.uri" | "http.host" | "http.method"
                    | "http.user_agent" | "http.request_body" | "http.response_body"
                    | "dns.query" | "dns.queries.rrname" | "tls.sni" => {
                        buffer_value(&ctx_event, alert, &buffer)
                    }
                    _ => None,
                }
            })
        })?;
        parts.push(format!("{buffer}={value}"));
    }
    Some(parts.join("|"))
}

/// 加载 SID 元数据。返回 `(映射, 是否成功)`：读取失败或 JSON 解析失败都必须可见
/// （stderr + 调用方计入 `config_errors`），不再用 `unwrap_or_default()` 静默成空表。
fn load_meta(path: &Option<PathBuf>) -> (HashMap<String, RuleMeta>, bool) {
    let Some(path) = path else {
        return (HashMap::new(), true);
    };
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("xbits: cannot read metadata {}: {err}", path.display());
            return (HashMap::new(), false);
        }
    };
    match serde_json::from_str::<HashMap<String, RuleMeta>>(&data) {
        Ok(map) => (map, true),
        Err(err) => {
            eprintln!(
                "xbits: cannot parse metadata {} ({} bytes): {err}",
                path.display(),
                data.len()
            );
            (HashMap::new(), false)
        }
    }
}

/// 加载 match_buffers 元数据。规则同 [`load_meta`]：解析失败必须可见，不得静默空表
/// （否则所有 SID 都建不出抑制 key，抑制能力归零却没有任何信号）。
fn load_match_buffers(path: &Option<PathBuf>) -> (HashMap<String, MatchBufferMeta>, bool) {
    let Some(path) = path else {
        return (HashMap::new(), true);
    };
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("xbits: cannot read match buffers {}: {err}", path.display());
            return (HashMap::new(), false);
        }
    };
    match serde_json::from_str::<HashMap<String, MatchBufferMeta>>(&data) {
        Ok(map) => (map, true),
        Err(err) => {
            eprintln!(
                "xbits: cannot parse match buffers {} ({} bytes): {err}",
                path.display(),
                data.len()
            );
            (HashMap::new(), false)
        }
    }
}

/// 外部命令（validator / triage / es-command）的执行结果。
///
/// 显式区分超时、非零退出、启动失败与输出编码失败——禁止再把"超时"压成空字符串、
/// 让下游把它误记成 `bad-triage-json`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellOutcome {
    /// 退出码 0 且 stdout 是合法 UTF-8。
    Success(String),
    /// 超过 timeout；已尝试杀掉整棵进程树（`sh -c` 及其孙进程），`kill_error` 记录清理失败原因。
    Timeout { after_ms: u64, kill_error: Option<String> },
    /// 进程正常结束但退出码非 0；stderr 截断保存供证据使用。
    NonZeroExit { code: Option<i32>, stderr: String },
    /// 无法启动子进程，或等待子进程失败。
    SpawnError(String),
    /// stdout 不是合法 UTF-8。
    OutputNotUtf8(String),
    /// 写 stdin 失败（子进程提前退出/管道断开）；最终退出码为 0 时才以此判定。
    IoError(String),
}

impl ShellOutcome {
    /// 人类可读摘要（stderr/证据用）。
    pub fn describe(&self) -> String {
        match self {
            ShellOutcome::Success(out) => format!("success ({} bytes stdout)", out.len()),
            ShellOutcome::Timeout {
                after_ms,
                kill_error,
            } => match kill_error {
                Some(err) => format!("timeout after {after_ms}ms (process-group kill failed: {err})"),
                None => format!("timeout after {after_ms}ms (process group killed)"),
            },
            ShellOutcome::NonZeroExit { code, stderr } => {
                format!("non-zero exit code={code:?} stderr={stderr}")
            }
            ShellOutcome::SpawnError(err) => format!("spawn error: {err}"),
            ShellOutcome::OutputNotUtf8(err) => format!("stdout is not UTF-8: {err}"),
            ShellOutcome::IoError(err) => format!("io error: {err}"),
        }
    }
}

/// 杀掉子进程所在的整个进程组（`sh -c` 及其派生的孙进程）。
///
/// 实现方式（不引入新依赖）：
/// 1. spawn 时用 `CommandExt::process_group(0)` 让子进程成为新进程组组长（pgid == 子进程 pid）；
/// 2. 超时后直接以 `kill(2)` 向 `-pgid` 发 SIGKILL（POSIX：负 pid 表示整个进程组）。
///    `kill` 是 libc 符号，Unix 目标默认链接；这里只声明这一个 FFI 符号，
///    因此不必引入 `libc` crate，也不依赖外部 `kill` 二进制或 shell 内建语义
///    （dash 的内建 kill 会把 `-123` 解析成 0，等于杀掉 xbits 自己 —— 不能用）。
///
/// 跨平台：本 crate 只在 Unix 上构建（`hook.rs` 直接使用 `std::os::unix::*`，`process_group` 也是 Unix API）。
/// 非 Unix 平台给出显式"不支持"错误，而不是假装清理成功。
#[cfg(unix)]
fn kill_process_group(pid: u32) -> Result<(), String> {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SIGKILL 在各 POSIX 系统上均为 9（Linux/macOS/BSD）。
    const SIGKILL: i32 = 9;
    let target = -(pid as i32);
    // SAFETY: kill(2) 只读两个整数参数，无内存安全问题；返回 -1 时通过 errno 取错误。
    let rc = unsafe { kill(target, SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "kill({target}, SIGKILL) failed: {}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) -> Result<(), String> {
    Err("process-group kill is unsupported on this platform (Unix-only crate)".to_string())
}

fn run_shell(command: &str, input: &str, timeout: Duration) -> ShellOutcome {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Unix：独立进程组，便于超时时连孙进程一起杀（见 kill_process_group）。
        .process_group(0);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return ShellOutcome::SpawnError(err.to_string()),
    };
    let pid = child.id();

    // 写 stdin 失败（EPIPE 等）不直接判定失败：先拿到真实退出状态，避免把早退子进程误判成 IO 错。
    let stdin_error = match child.stdin.take() {
        Some(mut stdin) => {
            let mut write_error: Option<String> = None;
            if let Err(err) = stdin.write_all(input.as_bytes()) {
                write_error = Some(err.to_string());
            } else if let Err(err) = stdin.write_all(b"\n") {
                write_error = Some(err.to_string());
            }
            write_error
        }
        None => None,
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        if let Some(mut stream) = stdout {
            if let Err(read_err) = stream.read_to_end(&mut out) {
                eprintln!("xbits: read child stdout failed: {read_err}");
            }
        }
        if let Some(mut stream) = stderr {
            if let Err(read_err) = stream.read_to_end(&mut err) {
                eprintln!("xbits: read child stderr failed: {read_err}");
            }
        }
        let _ = tx.send((out, err));
    });

    let start = Instant::now();
    let mut status = None;
    let mut timed_out_after: Option<u64> = None;
    loop {
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                status = Some(exit_status);
                break;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out_after = Some(start.elapsed().as_millis() as u64);
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                // 等待失败：尽力清理进程树后如实上报。
                if let Err(kill_err) = kill_process_group(pid) {
                    eprintln!("xbits: process-group kill after wait error failed for pid {pid}: {kill_err}");
                }
                return ShellOutcome::SpawnError(format!("wait failed: {err}"));
            }
        }
    }

    if let Some(after_ms) = timed_out_after {
        let kill_error = match kill_process_group(pid) {
            Ok(()) => None,
            Err(err) => {
                eprintln!(
                    "xbits: process-group kill failed for pid {pid}: {err}; falling back to child.kill()"
                );
                if let Err(fallback_err) = child.kill() {
                    eprintln!("xbits: child.kill failed for pid {pid}: {fallback_err}");
                }
                Some(err)
            }
        };
        if let Err(err) = child.wait() {
            eprintln!("xbits: child.wait after timeout failed for pid {pid}: {err}");
        }
        return ShellOutcome::Timeout {
            after_ms,
            kill_error,
        };
    }

    // 子进程已退出：最多再等 1 秒收 stdout/stderr（孙进程可能仍持有管道，收不到就按空处理，
    // 但退出码/超时状态已经明确，不会再把"超时"伪装成空输出）。
    let (out_bytes, err_bytes) = rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|_| (Vec::new(), Vec::new()));

    let exit_status = match status {
        Some(exit_status) => exit_status,
        None => return ShellOutcome::SpawnError("missing exit status".to_string()),
    };
    if !exit_status.success() {
        let stderr_text = String::from_utf8_lossy(&err_bytes);
        return ShellOutcome::NonZeroExit {
            code: exit_status.code(),
            stderr: truncate(stderr_text.trim(), 4096),
        };
    }
    if let Some(err) = stdin_error {
        return ShellOutcome::IoError(format!("stdin write failed: {err}"));
    }
    match String::from_utf8(out_bytes) {
        Ok(out) => ShellOutcome::Success(out),
        Err(err) => ShellOutcome::OutputNotUtf8(format!(
            "{} bytes of invalid UTF-8: {err}",
            err.as_bytes().len()
        )),
    }
}

fn post_http_json(url: &str, body: &str, auth: Option<&str>) -> io::Result<()> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "only http:// is supported; use --es-command for TLS"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().unwrap_or(9200)),
        None => (authority, 9200),
    };
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let auth_header = auth
        .map(|v| format!("Authorization: {v}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n{auth_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.as_bytes().len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if !response.starts_with("HTTP/1.1 2") && !response.starts_with("HTTP/1.0 2") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Elasticsearch returned: {}", response.lines().next().unwrap_or("")),
        ));
    }
    Ok(())
}

/// 等待 match_context 到达的挂起告警（顺序问题根治用）。
struct PendingAlert {
    event: HookEvent,
    alert: EngineAlert,
    at: Instant,
}

/// 文档落盘/推 ES 的共享出口（分析线程与 triage worker 共用同一份 sink 配置与计数）。
struct DocumentEmitter {
    analysis_file: Option<PathBuf>,
    es_url: Option<String>,
    es_command: Option<String>,
    es_auth: Option<String>,
    health: Arc<PipelineHealth>,
}

impl DocumentEmitter {
    fn new(config: &AnalysisConfig, health: Arc<PipelineHealth>) -> Self {
        Self {
            analysis_file: config.analysis_file.clone(),
            es_url: config.es_url.clone(),
            es_command: config.es_command.clone(),
            es_auth: config.es_auth.clone(),
            health,
        }
    }

    /// 落盘/推 ES 的唯一出口。任何"写不进去"都必须计数并上报，不允许静默丢文档：
    /// - 序列化失败 / 审计文件打开失败 / 写入失败 / ES 推送失败 → `document_errors` + stderr；
    /// - 没有对应 sink 的文档（本地审计文档未配 `--analysis-file`，或应进 ES 但未配 ES）
    ///   → `documents_without_sink` + stderr（前若干条与每 1000 条打印一次完整文档）。
    fn emit(&self, doc: &Value, to_es: bool) {
        let line = match serde_json::to_string(doc) {
            Ok(v) => v,
            Err(err) => {
                self.health.record_document_error();
                eprintln!("xbits: normalized document serialize error: {err}");
                return;
            }
        };

        let mut written = false;
        if let Some(path) = self.analysis_file.as_ref() {
            match fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => match writeln!(file, "{line}") {
                    Ok(()) => written = true,
                    Err(err) => {
                        self.health.record_document_error();
                        eprintln!("xbits: analysis file write failed {}: {err}", path.display());
                    }
                },
                Err(err) => {
                    self.health.record_document_error();
                    eprintln!("xbits: analysis file open failed {}: {err}", path.display());
                }
            }
        }

        if to_es {
            let mut es_written = false;
            if let Some(url) = self.es_url.as_ref() {
                match post_http_json(url, &line, self.es_auth.as_deref()) {
                    Ok(()) => es_written = true,
                    Err(err) => {
                        self.health.record_document_error();
                        eprintln!("xbits: Elasticsearch write failed: {err}");
                    }
                }
            }
            if let Some(command) = self.es_command.as_ref() {
                match run_shell(command, &line, Duration::from_secs(10)) {
                    ShellOutcome::Success(_) => es_written = true,
                    other => {
                        self.health.record_document_error();
                        eprintln!("xbits: ES command failed: {}", other.describe());
                    }
                }
            }
            if !es_written && !written {
                self.report_document_without_sink(&line);
            }
            return;
        }

        if !written {
            self.report_document_without_sink(&line);
        }
    }

    /// 没有 sink 的文档：计数 + 明确的 stderr 去向（限流但可数）。
    fn report_document_without_sink(&self, line: &str) {
        let count = self.health.record_document_without_sink();
        if count <= NO_SINK_STDERR_LIMIT || count % 1000 == 0 {
            eprintln!(
                "xbits: document has no sink (count={count}; 配置 --analysis-file 或 --es-url/--es-command): {line}"
            );
        }
    }
}

/// 一条待静态 triage 的文件任务：由分析线程投递，独立 worker 线程执行。
struct TriageJob {
    event: HookEvent,
    path: PathBuf,
    sha: String,
    intel: Option<EventIntelAnnotations>,
}

/// triage 有界队列深度：满时丢弃并计数，绝不阻塞决策线程（背压策略见 `Analyzer::submit_triage`）。
const TRIAGE_QUEUE_DEPTH: usize = 64;

/// 独立 triage worker：唯一执行外部 triage 命令的地方。
///
/// 分析线程只做决策与投递；外部命令（默认 30s 超时）不再阻塞告警判定与 pending 超时。
struct TriageWorker {
    command: Option<String>,
    timeout: Duration,
    categories: Vec<String>,
    cache_ttl: Duration,
    cache: HashMap<String, (Value, Instant)>,
    docs: Arc<DocumentEmitter>,
    health: Arc<PipelineHealth>,
}

impl TriageWorker {
    fn new(config: &AnalysisConfig, docs: Arc<DocumentEmitter>, health: Arc<PipelineHealth>) -> Self {
        Self {
            command: config.triage_command.clone(),
            timeout: config.triage_timeout,
            categories: config.triage_categories.clone(),
            cache_ttl: config.triage_cache_ttl,
            cache: HashMap::new(),
            docs,
            health,
        }
    }

    fn run(mut self, rx: mpsc::Receiver<TriageJob>) {
        while let Ok(job) = rx.recv() {
            let outcome = catch_unwind(AssertUnwindSafe(|| self.process(job)));
            if let Err(payload) = outcome {
                self.health
                    .fail(format!("triage worker panicked: {}", describe_panic(payload)));
                break;
            }
        }
    }

    fn process(&mut self, job: TriageJob) {
        let TriageJob {
            event,
            path,
            sha,
            intel,
        } = job;
        let intel = intel.as_ref();

        // 命中缓存（同一 sha256 不重复分析）。
        if !sha.is_empty() {
            if let Some((cached, at)) = self.cache.get(&sha) {
                if at.elapsed() <= self.cache_ttl {
                    self.emit_stage(
                        &event,
                        "completed",
                        Some(cached.clone()),
                        Some("cache-hit".to_string()),
                        intel,
                    );
                    return;
                }
            }
        }

        let Some(command) = self.command.clone() else {
            self.emit_stage(
                &event,
                "failed",
                None,
                Some("triage-command-not-configured".to_string()),
                intel,
            );
            return;
        };

        self.emit_stage(&event, "analyzing", None, None, intel);
        let input = triage_request_input(&event, &path, &sha, intel).to_string();

        match run_shell(&command, &input, self.timeout) {
            ShellOutcome::Success(out) => self.handle_triage_output(&event, &sha, out, intel),
            ShellOutcome::Timeout {
                after_ms,
                kill_error,
            } => {
                self.health.record_triage_timeout();
                let note = match kill_error {
                    Some(err) => format!(
                        "triage-timeout: after {after_ms}ms (process-group kill failed: {err})"
                    ),
                    None => format!("triage-timeout: after {after_ms}ms (process group killed)"),
                };
                eprintln!("xbits: triage sha={sha} {note}");
                self.emit_stage(&event, "failed", None, Some(note), intel);
            }
            other => {
                let note = format!("triage-failed: {}", other.describe());
                eprintln!("xbits: triage sha={sha} {note}");
                self.emit_stage(&event, "failed", None, Some(note), intel);
            }
        }
    }

    fn handle_triage_output(
        &mut self,
        event: &HookEvent,
        sha: &str,
        out: String,
        intel: Option<&EventIntelAnnotations>,
    ) {
        let value: Value = match serde_json::from_str(out.trim()) {
            Ok(v) => v,
            Err(err) => {
                self.emit_stage(
                    event,
                    "failed",
                    None,
                    Some(format!("bad-triage-json: {err}")),
                    intel,
                );
                return;
            }
        };
        if value.get("ok").and_then(Value::as_bool) == Some(false) {
            self.emit_stage(
                event,
                "failed",
                Some(value),
                Some("triage-returned-error".to_string()),
                intel,
            );
            return;
        }
        let category = value
            .pointer("/type/category")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tracked = self.categories.is_empty()
            || self
                .categories
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&category));
        if !tracked {
            self.emit_stage(
                event,
                "skipped",
                Some(value),
                Some(format!("category '{category}' outside triage set")),
                intel,
            );
            return;
        }
        if !sha.is_empty() {
            self.cache
                .insert(sha.to_string(), (value.clone(), Instant::now()));
        }
        self.emit_stage(event, "completed", Some(value), None, intel);
    }

    fn emit_stage(
        &self,
        event: &HookEvent,
        status: &str,
        result: Option<Value>,
        note: Option<String>,
        intel: Option<&EventIntelAnnotations>,
    ) {
        let doc = file_triage_document(event, status, result.as_ref(), note.as_deref(), intel);
        // to_es 判定见 `file_triage_to_es`：已知威胁命中必须进 ES（即使 triage 判 clean/失败/跳类）。
        let to_es = file_triage_to_es(status, result.as_ref(), intel);
        self.docs.emit(&doc, to_es);
    }
}

/// 组装 triage worker 经 stdin 传给 triage 的请求。
///
/// 单一情报源：intel 来自 `engine.intel_annotations`（t12 之后 triage 在 `--stdin` 下不读本地名单），
/// 因此这里必须把文件哈希命中等情报真的传下去，否则「文件 hash 命中威胁情报」在 triage 路径上既不判也不推 ES。
/// 形状：`{"intel": {"threat": [{"type":"sha256","value":"..."}...], "allowlist": [...]}}`，
/// 仅当确有事前情报标注（`Some`）时才带 `intel` 键；没有情报时不带，triage 记为 `xbits-payload(none)`。
fn triage_request_input(
    event: &HookEvent,
    path: &Path,
    sha: &str,
    intel: Option<&EventIntelAnnotations>,
) -> Value {
    let mut input = json!({
        "path": path.to_string_lossy().to_string(),
        "sha256": sha,
        "name": event.file_name,
        "flow_id": event.flow_id,
        "sid": event.sid,
    });
    if let Some(ann) = intel {
        input["intel"] = json!({
            "threat": ann
                .threat
                .clone()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            "allowlist": ann
                .allowlist
                .clone()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        });
    }
    input
}

/// file triage 文档是否推 ES。
///
/// - `completed`：triage 判 malicious/suspicious **或** xbits 已知威胁命中（hash 命中即推，避免只在 triage 判黑时才进 ES）；
/// - `failed`/`skipped`：已知威胁命中也要推（超时/坏 JSON/类别跳过都不能把已知恶意文件静默丢掉）；
/// - `received`/`analyzing`：只落分析文件跟踪，避免重复推送。
fn file_triage_to_es(
    status: &str,
    triage: Option<&Value>,
    intel: Option<&EventIntelAnnotations>,
) -> bool {
    let threat_hit = intel.is_some_and(EventIntelAnnotations::threat_hit);
    match status {
        "completed" => {
            let verdict = triage
                .and_then(|t| t.get("verdict"))
                .and_then(Value::as_str)
                .unwrap_or("");
            threat_hit || matches!(verdict, "malicious" | "suspicious")
        }
        "failed" | "skipped" => threat_hit,
        _ => false,
    }
}

struct Analyzer {
    config: AnalysisConfig,
    sid_library: HashMap<String, RuleMeta>,
    rules_meta: HashMap<String, RuleMeta>,
    match_buffers: HashMap<String, MatchBufferMeta>,
    match_contexts: HashMap<String, MatchContextEntry>,
    whitelist: SuppressionStore,
    /// 已记录过 app_tx_lua 提示的 SID，避免每告警刷日志。
    app_tx_lua_logged: HashSet<u64>,
    /// 等待 match_context 的挂起告警（顺序问题根治）。
    pending: Vec<PendingAlert>,
    /// 与流水线共享的健康状态（文档错误/无 sink/配置错误/线程存活）。
    health: Arc<PipelineHealth>,
    /// 共享的文档出口（分析线程与 triage worker 共用）。
    docs: Arc<DocumentEmitter>,
    /// 投递文件 triage 任务的有界队列（由独立 worker 消费）。
    triage_tx: mpsc::SyncSender<TriageJob>,
}

impl Analyzer {
    /// 测试用构造器：自带私有健康状态，且 triage 队列接收端已丢弃（提交会明确失败并可见）。
    #[cfg(test)]
    fn new(config: AnalysisConfig) -> Self {
        let health = Arc::new(PipelineHealth::new());
        let docs = Arc::new(DocumentEmitter::new(&config, Arc::clone(&health)));
        let (triage_tx, triage_rx) = mpsc::sync_channel::<TriageJob>(1);
        drop(triage_rx);
        Self::new_with_health(config, health, docs, triage_tx)
    }

    fn new_with_health(
        config: AnalysisConfig,
        health: Arc<PipelineHealth>,
        docs: Arc<DocumentEmitter>,
        triage_tx: mpsc::SyncSender<TriageJob>,
    ) -> Self {
        let (sid_library, sid_ok) = load_meta(&config.sid_library);
        let (rules_meta, rules_ok) = load_meta(&config.rules_meta);
        let (match_buffers, buffers_ok) = load_match_buffers(&config.match_buffers);
        for ok in [sid_ok, rules_ok, buffers_ok] {
            if !ok {
                health.record_config_error();
            }
        }
        if docs.analysis_file.is_none() {
            eprintln!(
                "xbits: --analysis-file 未配置：to_es=false 的文档（被抑制告警、file_triage 各阶段）只能写 stderr，并计入 documents_without_sink"
            );
        }
        let whitelist = SuppressionStore::new(config.suppression_ttl);
        Self {
            config,
            sid_library,
            rules_meta,
            match_buffers,
            match_contexts: HashMap::new(),
            whitelist,
            app_tx_lua_logged: HashSet::new(),
            pending: Vec::new(),
            health,
            docs,
            triage_tx,
        }
    }

    fn observe(&mut self, event: HookEvent) {
        if !event.kind.eq_ignore_ascii_case("match_context") {
            return;
        }
        let now = Instant::now();
        let ttl = self.config.suppression_ttl;
        self.match_contexts
            .retain(|_, entry| now.duration_since(entry.at) <= ttl);
        if let (Some(key), Some(value)) = (match_context_key(&event), event.match_context_value) {
            self.match_contexts.insert(
                key,
                MatchContextEntry {
                    value,
                    at: Instant::now(),
                },
            );
        }
        // context 到达后立即判定所有已具备条件的挂起告警（顺序问题根治）。
        self.flush_ready_pending();
    }

    fn decide(&self, event: &HookEvent, alert: &EngineAlert) -> Decision {
        let payload = event
            .payload_printable
            .as_deref()
            .or(event.payload.as_deref())
            .unwrap_or("");
        let meta = self
            .sid_library
            .get(&alert.signature_id.to_string())
            .or_else(|| self.rules_meta.get(&alert.signature_id.to_string()));

        let mut decision = Decision {
            verdict: "uncertain".into(),
            confidence: alert.confidence,
            // 情报决策必须体现在 reason 上（例如白名单降级 → intel-allowlist），
            // 没有情报决策时才回退到 engine-alert。
            reason: intel_reason(alert).unwrap_or_else(|| "engine-alert".into()),
            evidence: if alert.evidence.is_empty() {
                Vec::new()
            } else {
                vec![alert.evidence.clone()]
            },
            validator_used: false,
            validator_reason: None,
        };
        if let Some(label) = alert.intel_decision.as_deref() {
            decision.evidence.push(format!("intel_decision={label}"));
            if let Some(hits) = alert.intel.as_ref() {
                decision.evidence.push(format!("intel={hits}"));
            }
        }
        if let Some(hits) = alert.allowlist.as_ref() {
            decision.evidence.push(format!("allowlist={hits}"));
        }
        if let Some(meta) = meta {
            if let Some(tier) = meta.tier.as_deref() {
                decision
                    .evidence
                    .push(format!("tier={tier}"));
                if tier.eq_ignore_ascii_case("weak") {
                    decision.confidence = decision.confidence.min(60);
                } else if tier.eq_ignore_ascii_case("strong") {
                    decision.confidence = (decision.confidence + 5).min(100);
                }
            }
            if let Some(category) = meta.category.as_deref() {
                decision
                    .evidence
                    .push(format!("category={category}"));
            }
        }

        if let Some(command) = self.config.validator_command.as_ref() {
            let request = json!({
                "event": event,
                "alert": alert,
                "metadata": meta,
                "payload": truncate(payload, self.config.max_payload),
                "payload_b64": event.payload,
            });
            // 序列化失败不得静默成空输入（validator 会拿到空串却看不出原因）：
            // 计数 + stderr，并跳过本次验证（decision 保持 validator_used=false）。
            let request_line = match serde_json::to_string(&request) {
                Ok(line) => line,
                Err(err) => {
                    self.health.record_document_error();
                    eprintln!("xbits: validator request serialize error: {err}");
                    decision
                        .evidence
                        .push(format!("validator-request-error={err}"));
                    String::new()
                }
            };
            match run_shell(command, &request_line, self.config.validator_timeout) {
                ShellOutcome::Success(output) => match serde_json::from_str::<ValidatorDecision>(&output) {
                    Ok(v) => {
                        decision.verdict = normalize_verdict(&v.verdict);
                        decision.confidence = v.confidence.unwrap_or(decision.confidence).min(100);
                        if !v.reason.is_empty() {
                            // 情报决策依据（intel-*）是"情报参与过决策"的证据，优先级最高：
                            // validator 的空泛 reason（如 stub-validator）不得覆盖它，只单独记录。
                            if decision.reason.starts_with("intel-") {
                                decision.evidence.push(format!("validator-reason={}", v.reason));
                                decision.validator_reason = Some(v.reason);
                            } else {
                                // 无情报决策时保持原有语义：validator 结论作为主 reason，
                                // 同时单独记录一份，便于输出侧统一读取。
                                decision.validator_reason = Some(v.reason.clone());
                                decision.reason = v.reason;
                            }
                        }
                        decision.evidence.extend(v.evidence);
                        decision.validator_used = true;
                    }
                    Err(err) => {
                        decision
                            .evidence
                            .push(format!("validator-output-error={err}"));
                    }
                },
                // 超时/非零退出/启动失败/编码失败分别记在证据里，便于区分"验证器崩了"和"验证器超时"。
                other => {
                    decision
                        .evidence
                        .push(format!("validator-{}", other.describe()));
                }
            }
        }

        if !decision.validator_used {
            // 没有验证器或验证器不可用时，保持 uncertain：
            // 宁可不建立白名单，也不凭空判定 true_positive/false_positive。
            decision.verdict = "uncertain".into();
            let validator_state = if self.config.validator_command.is_some() {
                "validator-unavailable"
            } else {
                "validator-missing"
            };
            // 有情报决策时 reason 保留 intel-*（决策依据不能被验证器状态覆盖），
            // 验证器状态改记 evidence；没有情报决策时保持原有 reason 语义。
            if decision.reason == "engine-alert" {
                decision.reason = validator_state.to_string();
            } else {
                decision.evidence.push(validator_state.to_string());
            }
        }
        decision
    }

    fn process(&mut self, event: HookEvent, alert: EngineAlert) {
        // 顺序根治：match_context 与 alert 走不同 socket 连接，到达顺序无保证。
        // 若该 SID 声明的 context-only buffer 只是"还没到"，短暂挂起，
        // 等匹配的 match_context 到达后立刻判定；超时则按 fail-closed 处理
        // （不建 key、不抑制），绝不丢弃事件。
        if self.should_defer_for_context(&event, &alert) {
            self.pending.push(PendingAlert {
                event,
                alert,
                at: Instant::now(),
            });
            return;
        }
        self.process_now(event, alert);
    }

    /// 是否值得等 match_context：只在该 SID 的缺口全是 context-only buffer、
    /// 且其余 buffer 已可立即解析时才等待（否则等待注定无意义）。
    fn should_defer_for_context(&self, event: &HookEvent, alert: &EngineAlert) -> bool {
        let Some(meta) = self.match_buffers.get(&alert.signature_id.to_string()) else {
            return false;
        };
        if meta.app_tx_lua {
            return false;
        }
        if self.missing_context_only(event, alert, meta).is_empty() {
            return false;
        }
        meta.buffers
            .iter()
            .map(|b| canonical_buffer_name(b))
            .filter(|b| !is_context_only(b))
            .all(|b| buffer_value(event, alert, b).is_some())
    }

    /// 返回该 SID 声明但当前缓存缺失的 context-only buffer 列表。
    fn missing_context_only(
        &self,
        event: &HookEvent,
        alert: &EngineAlert,
        meta: &MatchBufferMeta,
    ) -> Vec<String> {
        meta.buffers
            .iter()
            .map(|b| canonical_buffer_name(b))
            .filter(|b| is_context_only(b))
            .filter(|b| {
                let context_key = format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}",
                    event.source,
                    alert.signature_id,
                    alert.src,
                    alert.sport,
                    alert.dst,
                    alert.dport,
                    alert.proto,
                    b
                );
                !self.match_contexts.contains_key(&context_key)
            })
            .map(str::to_string)
            .collect()
    }

    /// context 到达后，立即判定所有已具备条件的挂起告警。
    fn flush_ready_pending(&mut self) {
        // 先整体取走 pending，避免与 &self 的只读查询产生借用冲突。
        let all = std::mem::take(&mut self.pending);
        let mut ready = Vec::new();
        let mut remaining = Vec::new();
        for pending in all {
            let complete = match self
                .match_buffers
                .get(&pending.alert.signature_id.to_string())
            {
                Some(meta) => self
                    .missing_context_only(&pending.event, &pending.alert, meta)
                    .is_empty(),
                None => true,
            };
            if complete {
                ready.push(pending);
            } else {
                remaining.push(pending);
            }
        }
        self.pending = remaining;
        for pending in ready {
            self.process_now(pending.event, pending.alert);
        }
    }

    /// 超过等待窗口仍未拿到 context：按 fail-closed 直接判定（不抑制）。
    fn flush_expired_pending(&mut self) {
        let now = Instant::now();
        let timeout = self.config.pending_context_timeout;
        let mut expired = Vec::new();
        let mut remaining = Vec::new();
        for pending in self.pending.drain(..) {
            if now.duration_since(pending.at) >= timeout {
                expired.push(pending);
            } else {
                remaining.push(pending);
            }
        }
        self.pending = remaining;
        for pending in expired {
            self.process_now(pending.event, pending.alert);
        }
    }

    fn process_now(&mut self, event: HookEvent, alert: EngineAlert) {
        let meta = self.match_buffers.get(&alert.signature_id.to_string());
        if meta.map(|m| m.app_tx_lua).unwrap_or(false) {
            // app-tx 挂载的 Lua 规则没有单一精确 buffer 可导出（补丁层明确不近似），
            // 这类规则按元数据标记不参与抑制：每次告警仍走 validator 出判定。
            // 仅记录一次，避免日志洪泛。
            let first = self.app_tx_lua_logged.insert(alert.signature_id);
            if first {
                eprintln!(
                    "xbits: sid {} is app-layer lua (app_tx_lua=true); no exact buffer exportable, suppression disabled, validator judgment still applies",
                    alert.signature_id
                );
            }
        }
        let key = suppression_key(
            &event,
            &alert,
            meta,
            &self.match_contexts,
        );
        if key.is_none() {
            if let Some(meta) = meta {
                if !meta.app_tx_lua {
                    // 精确报告缺的是哪个声明 buffer（context-only 且无导出值）。
                    let missing = self.missing_context_only(&event, &alert, meta);
                    if !missing.is_empty() {
                        let primary = meta.primary.as_deref().unwrap_or("?");
                        eprintln!(
                            "xbits: sid {} suppression skipped: primary buffer {primary}, missing exact match_context for [{}]",
                            alert.signature_id,
                            missing.join(", ")
                        );
                    } else if meta.has_payload && event.payload.is_none() {
                        // has_payload 规则但告警无 EVE payload：提示 payload 日志未开启，
                        // 否则 payload/stream buffer 取不到值会静默无法建立抑制 key。
                        eprintln!(
                            "xbits: sid {} has_payload=true but EVE payload missing; enable eve-log alert payload to allow suppression",
                            alert.signature_id
                        );
                    }
                }
            }
        }
        let suppressed = key
            .as_deref()
            .map(|key| self.whitelist.contains(key))
            .unwrap_or(false);
        if suppressed {
            let decision = Decision {
                verdict: "suppressed".into(),
                confidence: 100,
                reason: "xbits-whitelist".into(),
                evidence: vec![format!("key={}", key.as_deref().unwrap_or_default())],
                validator_used: false,
                validator_reason: None,
            };
            let payload = event
                .payload_printable
                .as_deref()
                .or(event.payload.as_deref())
                .unwrap_or("");
            let doc = normalized_document(&event, &alert, &decision, payload, self.config.max_payload);
            self.emit(&doc, false);
            return;
        }

        let decision = self.decide(&event, &alert);
        let payload = event
            .payload_printable
            .as_deref()
            .or(event.payload.as_deref())
            .unwrap_or("");
        let is_false_positive = decision.is_false_positive();
        let doc = normalized_document(&event, &alert, &decision, payload, self.config.max_payload);
        if is_false_positive {
            if let Some(key) = key {
                // fp_confidence 是误报入白名单的置信度门槛：只有 validator
                // 明确判定 false_positive 且置信度达标时才写抑制 key，
                // 否则只输出判定、不建立白名单（否则低置信 FP 会误杀后续真威胁）。
                if may_whitelist(&decision, self.config.fp_confidence) {
                    self.whitelist.add(key);
                } else {
                    eprintln!(
                        "xbits: sid {} false_positive confidence {} < fp_confidence {}; not whitelisted",
                        alert.signature_id, decision.confidence, self.config.fp_confidence
                    );
                }
            }
        }
        self.emit(&doc, !is_false_positive);
    }

    /// 处理 Suricata 转存文件事件：编排静态 triage 并逐阶段跟踪。
    /// 阶段：received -> analyzing -> completed/failed/skipped（全部写入分析文件，供全程跟踪）。
    ///
    /// `intel` 是引擎在进 triage 之前给出的情报标注（文件哈希/IP/域名），
    /// 每个阶段文档都会带上它与决策标签，使"文件命中情报"在决策链上可见。
    /// 处理 Suricata 转存文件事件：分析线程只做准入判定与投递，外部 triage 命令由独立 worker 执行。
    ///
    /// 阶段：received → analyzing → completed/failed/skipped（writer 逐阶段落文档）。
    fn handle_file(&mut self, event: HookEvent, intel: Option<EventIntelAnnotations>) {
        let intel_ref = intel.as_ref();
        self.emit_file_stage(&event, "received", None, None, intel_ref);

        let sha = event.file_sha256.clone().unwrap_or_default();
        let path = match self.admit_file(&event, &sha) {
            Ok(path) => path,
            Err(note) => {
                eprintln!("xbits: file event rejected (sha={sha}): {note}");
                self.emit_file_stage(&event, "failed", None, Some(note), intel_ref);
                return;
            }
        };

        // 投递到独立 triage worker（有界队列）；不再在决策线程里同步执行外部命令。
        self.submit_triage(TriageJob {
            event,
            path,
            sha,
            intel,
        });
    }

    /// 文件事件准入判定：`stored=false` / 非法 sha / 文件找不到都在这里给出**明确原因**，
    /// 不再"猜 spool 路径"或把多种失败压成一句话。
    fn admit_file(&self, event: &HookEvent, sha: &str) -> Result<PathBuf, String> {
        if event.file_stored == Some(false) {
            return Err(
                "stored=false (Suricata did not persist this file; refusing to guess a spool path)"
                    .to_string(),
            );
        }
        if !sha.is_empty() && !is_hex_hash(sha) {
            return Err(format!(
                "bad-file-sha256: {sha:?} (expect 32/40/64 hex chars)"
            ));
        }
        match self.resolve_file_path(event, sha) {
            Some(path) => Ok(path),
            None => {
                if self.config.file_spool_dir.is_none() {
                    Err("file-not-locatable: --file-spool-dir 未配置且事件没有可用的 file_path"
                        .to_string())
                } else if event
                    .file_path
                    .as_deref()
                    .is_some_and(|p| !p.is_empty())
                {
                    Err(format!(
                        "file-not-found: file_path 指向的文件不存在，且 spool dir 中没有 sha={sha}"
                    ))
                } else {
                    Err(format!("file-not-found: spool dir 中不存在 sha={sha} 的文件"))
                }
            }
        }
    }

    /// 投递 triage 任务（有界队列，非阻塞）。
    ///
    /// 背压/丢弃策略：队列满时丢弃该文件事件并计数（`triage_dropped`），同时落一条
    /// `failed(triage-queue-full)` 文档；worker 已退出时计入 `triage_dropped` 并把流水线
    /// 标记为不可用（hook listener 随后非零退出）。决策线程永远不会被外部命令阻塞。
    fn submit_triage(&self, job: TriageJob) {
        match self.triage_tx.try_send(job) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(job)) => {
                self.health.record_triage_dropped();
                eprintln!(
                    "xbits: triage queue full (depth={TRIAGE_QUEUE_DEPTH}); dropping file sha={}",
                    job.sha
                );
                let doc = file_triage_document(
                    &job.event,
                    "failed",
                    None,
                    Some("triage-queue-full (dropped; triage worker busy)"),
                    job.intel.as_ref(),
                );
                self.docs.emit(&doc, false);
            }
            Err(mpsc::TrySendError::Disconnected(job)) => {
                self.health.record_triage_dropped();
                self.health
                    .fail("triage worker is not running (queue disconnected)");
                eprintln!(
                    "xbits: triage worker unavailable; dropping file sha={}",
                    job.sha
                );
                let doc = file_triage_document(
                    &job.event,
                    "failed",
                    None,
                    Some("triage-worker-unavailable (dropped)"),
                    job.intel.as_ref(),
                );
                self.docs.emit(&doc, false);
            }
        }
    }

    /// 定位转存文件：优先事件里的绝对路径，其次 file-store v2 布局 `<dir>/<sha[0:2]>/<sha>`。
    ///
    /// `sha` 来自不可信事件（hook socket 0666），只接受合法 hex 哈希才拼接路径：
    /// 非法值不会进入字节切片或路径拼接，调用方按"明确失败"处理（见 `handle_file`）。
    fn resolve_file_path(&self, event: &HookEvent, sha: &str) -> Option<PathBuf> {
        if let Some(p) = event.file_path.as_deref().filter(|p| !p.is_empty()) {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        let dir = self.config.file_spool_dir.as_ref()?;
        if !is_hex_hash(sha) {
            return None;
        }
        // 已校验为 ASCII hex，`get(0..2)` 必然落在 char 边界（不再用 `&sha[0..2]`）。
        let prefix = sha.get(0..2)?;
        let nested = dir.join(prefix).join(sha);
        if nested.is_file() {
            return Some(nested);
        }
        let flat = dir.join(sha);
        if flat.is_file() {
            return Some(flat);
        }
        None
    }

    fn emit_file_stage(
        &self,
        event: &HookEvent,
        status: &str,
        result: Option<Value>,
        note: Option<String>,
        intel: Option<&EventIntelAnnotations>,
    ) {
        let doc = file_triage_document(event, status, result.as_ref(), note.as_deref(), intel);
        // to_es 判定见 `file_triage_to_es`：已知威胁命中必须进 ES（即使 triage 判 clean/失败/跳类）。
        let to_es = file_triage_to_es(status, result.as_ref(), intel);
        self.emit(&doc, to_es);
    }

    /// 委托给共享文档出口（分析线程与 triage worker 使用同一份 sink 配置与计数）。
    fn emit(&self, doc: &Value, to_es: bool) {
        self.docs.emit(doc, to_es);
    }
}

fn normalize_verdict(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "true_positive" | "true-positive" | "true" | "tp" => "true_positive".into(),
        "false_positive" | "false-positive" | "false" | "fp" => "false_positive".into(),
        _ => "uncertain".into(),
    }
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn payload_features(payload: &str) -> Value {
    let lower = payload.to_ascii_lowercase();
    let printable = payload
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .count();
    let ratio = if payload.is_empty() {
        0.0
    } else {
        printable as f64 / payload.chars().count() as f64
    };
    json!({
        "length": payload.chars().count(),
        "printable_ratio": (ratio * 1000.0).round() / 1000.0,
        "has_url": lower.contains("http://") || lower.contains("https://"),
        "has_html": lower.contains("<script") || lower.contains("<html"),
        "has_sql": lower.contains("union") && lower.contains("select")
            || lower.contains("information_schema") || lower.contains("sleep("),
        "has_traversal": lower.contains("../") || lower.contains("..\\"),
        "has_command": lower.contains("cmd.exe") || lower.contains("powershell")
            || lower.contains("/bin/sh") || lower.contains("whoami"),
        "has_base64": lower.contains("base64") || lower.contains("atob("),
        "looks_binary": ratio < 0.85,
    })
}

fn normalized_document(
    event: &HookEvent,
    alert: &EngineAlert,
    decision: &Decision,
    payload: &str,
    max_payload: usize,
) -> Value {
    let mut doc = json!({
        "@timestamp": alert.timestamp.clone(),
        "event": {
            "kind": "alert",
            "module": "xbits",
            "dataset": "xbits.events",
        },
        "rule": {
            "id": alert.signature_id.to_string(),
            "name": alert.signature.clone(),
            "xbits_rule_id": alert.rule_id.clone(),
            "category": event.category.clone(),
            "severity": event.severity.clone(),
        },
        "network": {
            "transport": alert.proto.clone(),
            "src_ip": alert.src.clone(),
            "src_port": alert.sport,
            "dst_ip": alert.dst.clone(),
            "dst_port": alert.dport,
        },
        "suricata": {
            "flow_id": alert.flow_id.clone(),
            "community_id": alert.community_id.clone(),
            "action": event.action.clone(),
            "app_proto": event.app_proto.clone(),
            "tx_id": event.tx_id,
        },
        "xbits": {
            "verdict": decision.verdict.clone(),
            "confidence": decision.confidence,
            "score": alert.score,
            "reason": decision.reason.clone(),
            "evidence": decision.evidence.clone(),
            "validator_used": decision.validator_used,
            // 情报决策依据：命中项、白名单命中/基线提示与决策标签（见 engine.rs 的 INTEL_* 常量）
            "intel_decision": alert.intel_decision.clone(),
        },
        "intel": alert.intel.clone(),
        "allowlist": alert.allowlist.clone(),
        "payload": {
            "text": truncate(payload, max_payload),
            "truncated": payload.chars().count() > max_payload,
            "features": payload_features(payload),
        },
        "zeek": alert.context.clone(),
    });
    // validator 的结论单独成字段：不覆盖 `reason`（intel-* 决策依据优先，见 decide/Decision）。
    // 只有 validator 真的返回过 reason 时才出现该字段，保持既有文档 schema 干净。
    if let Some(validator_reason) = decision.validator_reason.as_ref() {
        doc["xbits"]["validator_reason"] = Value::String(validator_reason.clone());
    }
    doc
}

/// 文件静态 triage 的跟踪文档：每个阶段一条，event.status 标记 received/analyzing/completed/failed/skipped。
/// `intel` 为引擎在进 triage 前给出的情报标注（命中项 + 决策标签），每个阶段都带上。
/// 冲突语义：triage 判 clean/未知但 xbits 命中已知威胁时，`xbits.intel_conflict=true`，
/// `xbits.verdict` 以情报为准（malicious），原始 triage 结论保留在 `xbits.triage_verdict`/`xbits.triage`，
/// 并在 `xbits.note` 追加 `intel-conflict: ...`——不静默采用 triage 的 clean（见 file_triage_to_es）。
fn file_triage_document(
    event: &HookEvent,
    status: &str,
    triage: Option<&Value>,
    note: Option<&str>,
    intel: Option<&EventIntelAnnotations>,
) -> Value {
    let verdict = triage
        .and_then(|t| t.get("verdict"))
        .cloned()
        .unwrap_or(Value::Null);
    let score = triage
        .and_then(|t| t.get("score"))
        .cloned()
        .unwrap_or(Value::Null);
    let category = triage
        .and_then(|t| t.pointer("/type/category"))
        .cloned()
        .unwrap_or(Value::Null);
    let magic = event.file_magic.clone().map(Value::from).unwrap_or_else(|| {
        triage
            .and_then(|t| t.pointer("/type/magic"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    // 情报优先（R2/V-03 闭环）：xbits 已知威胁命中而 triage 判 clean 时，不得把 clean 当最终结论静默采用。
    // 对外 verdict 记为 malicious（以 xbits 情报为准），原始 triage 结论保留在 xbits.triage_verdict / xbits.triage。
    let verdict_text = verdict.as_str().unwrap_or("");
    let threat_hit = intel.is_some_and(EventIntelAnnotations::threat_hit);
    let intel_conflict = threat_hit
        && status == "completed"
        && !matches!(verdict_text, "malicious" | "suspicious");
    let effective_verdict = if intel_conflict {
        Value::from("malicious")
    } else {
        verdict.clone()
    };
    let note = if intel_conflict {
        let conflict_note = format!(
            "intel-conflict: xbits threat hit overrides triage verdict '{}'",
            if verdict_text.is_empty() { "unknown" } else { verdict_text }
        );
        Some(match note.filter(|n| !n.is_empty()) {
            Some(existing) => format!("{existing}; {conflict_note}"),
            None => conflict_note,
        })
    } else {
        note.map(|n| n.to_string())
    };
    json!({
        "@timestamp": event.timestamp.clone().or_else(|| event.ts.clone()).unwrap_or_default(),
        "event": {
            "kind": "file_triage",
            "module": "xbits",
            "dataset": "xbits.file_triage",
            "status": status,
        },
        "file": {
            "id": event.file_sha256.clone().or_else(|| event.flow_id.clone()).unwrap_or_default(),
            "sha256": event.file_sha256.clone(),
            "sha1": event.file_sha1.clone(),
            "md5": event.file_md5.clone(),
            "name": event.file_name.clone(),
            "magic": magic,
            "size": event.file_size,
            "stored": event.file_stored,
            "path": event.file_path.clone(),
        },
        "network": {
            "transport": event.proto.clone(),
            "src_ip": event.src.clone(),
            "src_port": event.sport,
            "dst_ip": event.dst.clone(),
            "dst_port": event.dport,
        },
        "suricata": {
            "flow_id": event.flow_id.clone(),
            "community_id": event.community_id.clone(),
            "app_proto": event.app_proto.clone(),
            "tx_id": event.tx_id,
        },
        "xbits": {
            "stage": status,
            "note": note,
            "category": category,
            "verdict": effective_verdict,
            "triage_verdict": verdict,
            "score": score,
            "triage": triage.cloned().unwrap_or(Value::Null),
            // 情报决策依据：文件哈希命中等（由引擎在进 triage 前给出，见 hook.rs）；每个阶段都带。
            "intel_decision": intel.and_then(EventIntelAnnotations::decision),
            // triage 判 clean/未知但 xbits 命中已知威胁 → true（以情报为准，见上方注释）
            "intel_conflict": intel_conflict,
        },
        "intel": intel.and_then(|i| i.threat.clone()),
        "allowlist": intel.and_then(EventIntelAnnotations::allowlist_document),
    })
}

enum Job {
    Event(HookEvent),
    Alert(HookEvent, EngineAlert),
    File(HookEvent, Option<EventIntelAnnotations>),
}

/// 异步分析与输出流水线。Suricata hook 线程只负责入队，避免工具验证阻塞。
///
/// 健康语义：`health.is_available()` 为 false 表示分析不再工作（线程 panic 退出或
/// 入队连续失败达到阈值），调用方（hook listener）必须把它当作故障处理而不是继续静默运行。
pub struct AnalysisPipeline {
    tx: Sender<Job>,
    health: Arc<PipelineHealth>,
}

impl AnalysisPipeline {
    pub fn start(config: AnalysisConfig) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        let health = Arc::new(PipelineHealth::new());
        // 先乐观置为可用再起线程：避免"线程还没跑到第一条指令，hook 首次检查就误判失败"的竞态。
        // 线程在 panic 时会把状态改成 fail；启动期入队的 Job 由 channel 缓冲，init 后处理。
        health.set_available(true);
        let docs = Arc::new(DocumentEmitter::new(&config, Arc::clone(&health)));

        // 独立 triage worker（有界队列）：默认 30s 的外部命令只在 worker 线程执行，
        // 分析线程只做决策与投递，不再被 triage 阻塞（pending 超时判定保持灵敏）。
        let (triage_tx, triage_rx) = mpsc::sync_channel::<TriageJob>(TRIAGE_QUEUE_DEPTH);
        let worker = TriageWorker::new(&config, Arc::clone(&docs), Arc::clone(&health));
        let worker_health = Arc::clone(&health);
        let worker_spawn = thread::Builder::new()
            .name("xbits-triage".into())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| worker.run(triage_rx)));
                if let Err(payload) = outcome {
                    worker_health.fail(format!(
                        "triage worker panicked: {}",
                        describe_panic(payload)
                    ));
                }
            });
        if let Err(err) = worker_spawn {
            health.fail(format!("cannot spawn triage worker: {err}"));
            return Err(err);
        }

        let thread_health = Arc::clone(&health);
        let analysis_docs = Arc::clone(&docs);
        let spawn = thread::Builder::new()
            .name("xbits-analysis".into())
            .spawn(move || {
                let mut analyzer = match catch_unwind(AssertUnwindSafe(|| {
                    Analyzer::new_with_health(
                        config,
                        Arc::clone(&thread_health),
                        analysis_docs,
                        triage_tx,
                    )
                })) {
                    Ok(analyzer) => analyzer,
                    Err(payload) => {
                        thread_health.fail(format!(
                            "analysis thread panicked during init: {}",
                            describe_panic(payload)
                        ));
                        return;
                    }
                };
                if analyzer.health.config_errors() > 0 {
                    eprintln!(
                        "xbits: analysis pipeline started with {} metadata load error(s); suppression metadata may be missing",
                        analyzer.health.config_errors()
                    );
                }
                let tick = analyzer.config.pending_context_timeout;
                loop {
                    match rx.recv_timeout(tick) {
                        Ok(job) => {
                            let outcome = catch_unwind(AssertUnwindSafe(|| match job {
                                Job::Event(event) => analyzer.observe(event),
                                Job::Alert(event, alert) => analyzer.process(event, alert),
                                Job::File(event, intel) => analyzer.handle_file(event, intel),
                            }));
                            if let Err(payload) = outcome {
                                thread_health.fail(format!(
                                    "analysis thread panicked while handling a job: {}",
                                    describe_panic(payload)
                                ));
                                break;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let outcome = catch_unwind(AssertUnwindSafe(|| {
                                analyzer.flush_expired_pending()
                            }));
                            if let Err(payload) = outcome {
                                thread_health.fail(format!(
                                    "analysis thread panicked while flushing pending alerts: {}",
                                    describe_panic(payload)
                                ));
                                break;
                            }
                        }
                        // sender 被丢弃 = 进程正常收尾；不算失败。
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
        if let Err(err) = spawn {
            health.fail(format!("cannot spawn analysis thread: {err}"));
            return Err(err);
        }
        Ok(Self { tx, health })
    }

    /// 健康状况（线程存活标志 + 各类错误计数）。
    pub fn health(&self) -> &PipelineHealth {
        &self.health
    }

    pub fn is_available(&self) -> bool {
        self.health.is_available()
    }

    pub fn failure_reason(&self) -> Option<String> {
        self.health.failure_reason()
    }

    /// 入队。失败必须记录（计数 + stderr）；连续失败达阈值后把流水线标记为不可用，
    /// 由 hook listener 的健康探测转成非零退出——不允许"发送失败当没发生"。
    fn submit_job(&self, job: Job) {
        match self.tx.send(job) {
            Ok(()) => self.health.note_send_success(),
            Err(err) => {
                let consecutive = self.health.record_send_failure();
                eprintln!(
                    "xbits: analysis job send failed (consecutive={consecutive}): {err}"
                );
                if consecutive >= SEND_FAILURE_THRESHOLD {
                    self.health.fail(format!(
                        "analysis job channel closed after {consecutive} consecutive send failures"
                    ));
                }
            }
        }
    }

    pub fn submit_event(&self, event: HookEvent) {
        self.submit_job(Job::Event(event));
    }

    pub fn submit_alert(&self, event: HookEvent, alert: EngineAlert) {
        self.submit_job(Job::Alert(event, alert));
    }

    /// 提交"文件已转存"事件（含引擎给出的情报标注），触发静态 triage 编排。
    pub fn submit_file(&self, event: HookEvent, intel: Option<EventIntelAnnotations>) {
        self.submit_job(Job::File(event, intel));
    }

    /// 兼容旧调用：按告警事件提交。
    pub fn submit(&self, event: HookEvent, alert: EngineAlert) {
        self.submit_alert(event, alert);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::EventIntelAnnotations;

    /// 测试只经 `Default` + 结构体更新语法构造：`EngineAlert` 新增字段时自动跟随，
    /// 不会再出现"测试构造器漏字段导致 cargo test 编译不过"。
    fn alert() -> EngineAlert {
        EngineAlert {
            timestamp: "2026-01-01T00:00:00Z".into(),
            signature_id: 9103001,
            signature: "test".into(),
            community_id: "1:test".into(),
            src: "203.0.113.9".into(),
            dst: "10.0.0.80".into(),
            sport: 40001,
            dport: 80,
            proto: "TCP".into(),
            flow_id: "123".into(),
            score: 20,
            confidence: 80,
            evidence: "test".into(),
            reason: "test".into(),
            rule_id: "test".into(),
            uid: Some("C1".into()),
            ..Default::default()
        }
    }

    fn event() -> HookEvent {
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "alert".into();
        // EVE 侧的近似字段齐全：header/file/lua/raw-uri 都故意不给，
        // 只给 EVE 能表示的 uri/payload，验证它们不会被拿去兜底。
        ev.uri = Some("/normalized".into());
        ev.payload = Some("cGF5bG9hZA==".into());
        ev.src = Some("203.0.113.9".into());
        ev.dst = Some("10.0.0.80".into());
        ev.sport = Some(40001);
        ev.dport = Some(80);
        ev.proto = Some("TCP".into());
        ev.sid = Some(9103001);
        ev
    }

    fn meta(buffers: &[&str]) -> MatchBufferMeta {
        MatchBufferMeta {
            buffers: buffers.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn meta_app_tx_lua() -> MatchBufferMeta {
        MatchBufferMeta {
            buffers: vec!["lua".to_string()],
            primary: Some("lua".to_string()),
            has_payload: false,
            source: None,
            app_tx_lua: true,
        }
    }

    fn context(
        buffer: &str,
        value: &str,
        contexts: &mut HashMap<String, MatchContextEntry>,
    ) {
        let mut ev = event();
        ev.kind = "match_context".into();
        ev.match_context_buffer = Some(buffer.into());
        ev.match_context_value = Some(value.into());
        let key = match_context_key(&ev).unwrap();
        contexts.insert(
            key,
            MatchContextEntry {
                value: value.into(),
                at: Instant::now(),
            },
        );
    }

    #[test]
    fn canonicalizes_suricata_buffer_names() {
        assert_eq!(canonical_buffer_name("http_uri"), "http.uri");
        assert_eq!(canonical_buffer_name("http_raw_uri"), "http.uri.raw");
        assert_eq!(canonical_buffer_name("http_header"), "http.header");
        assert_eq!(canonical_buffer_name("file_data"), "file.data");
        assert_eq!(canonical_buffer_name("dns_query"), "dns.query");
        // 已是统一名或未知名原样返回
        assert_eq!(canonical_buffer_name("http.uri.raw"), "http.uri.raw");
        assert_eq!(canonical_buffer_name("lua"), "lua");
        assert_eq!(canonical_buffer_name("new_buffer"), "new_buffer");
    }

    #[test]
    fn no_metadata_never_builds_key() {
        // 即使有 payload 与完整 match_context，无 match_buffers 元数据也必须拒绝建 key。
        let mut contexts = HashMap::new();
        context("payload", "cGF5bG9hZA==", &mut contexts);
        assert!(suppression_key(&event(), &alert(), None, &contexts).is_none());
        assert!(suppression_key(&event(), &alert(), Some(&meta(&[])), &contexts).is_none());
    }

    #[test]
    fn context_only_buffers_ignore_eve_approximation() {
        // context-only buffer 只接受 match_context 精确值；
        // EVE 侧即使有 payload/uri 也不得兜底。无导出 => 无 key。
        for buffer in CONTEXT_ONLY_BUFFERS {
            assert!(
                suppression_key(&event(), &alert(), Some(&meta(&[buffer])), &HashMap::new())
                    .is_none(),
                "{buffer} must not fall back to EVE fields"
            );
        }
    }

    #[test]
    fn app_tx_lua_meta_explicitly_unsuppressible() {
        // app-tx Lua 规则（buffers=["lua"] + app_tx_lua=true）：
        // 没有 match_context 时 key 必须为 None（不近似、不抑制）。
        assert!(
            suppression_key(&event(), &alert(), Some(&meta_app_tx_lua()), &HashMap::new())
                .is_none()
        );
        assert!(meta_app_tx_lua().app_tx_lua);
    }

    #[test]
    fn context_only_buffers_use_exact_exported_value() {
        // Suricata 内部名（下划线）导出的 match_context 必须归一后命中元数据里的点号名。
        let cases = [
            ("http_header", "http.header", "dXNlci1hZ2VudA=="),
            ("file_data", "file.data", "ZmlsZQ=="),
            ("http_raw_uri", "http.uri.raw", "L3Jhdy91cmk="),
            ("lua", "lua", "bHVh"),
        ];
        for (exported, declared, value) in cases {
            let mut contexts = HashMap::new();
            context(exported, value, &mut contexts);
            let key = suppression_key(&event(), &alert(), Some(&meta(&[declared])), &contexts)
                .unwrap_or_else(|| panic!("{declared} should build key from exact context"));
            assert!(key.contains(&format!("{declared}={value}")));
        }
    }

    #[test]
    fn payload_buffer_uses_exact_context_when_present() {
        let mut contexts = HashMap::new();
        context("payload", "ZXhhY3Q=", &mut contexts);
        let key = suppression_key(&event(), &alert(), Some(&meta(&["payload"])), &contexts).unwrap();
        assert!(key.contains("payload=ZXhhY3Q="));
    }

    #[test]
    fn normalizes_false_positive_verdict() {
        assert_eq!(normalize_verdict("false-positive"), "false_positive".to_string());
        assert_eq!(normalize_verdict("FP"), "false_positive".to_string());
        assert_eq!(normalize_verdict("maybe"), "uncertain".to_string());
    }

    #[test]
    fn fp_confidence_gates_whitelisting() {
        let mut d = Decision {
            verdict: "false_positive".into(),
            confidence: 95,
            reason: String::new(),
            evidence: Vec::new(),
            validator_used: true,
            validator_reason: None,
        };
        assert!(may_whitelist(&d, 90));
        d.confidence = 60;
        assert!(!may_whitelist(&d, 90));
        d.confidence = 95;
        d.verdict = "uncertain".into();
        assert!(!may_whitelist(&d, 90));
        d.verdict = "true_positive".into();
        assert!(!may_whitelist(&d, 90));
    }

    #[test]
    fn defers_alert_until_match_context_arrives() {
        // 顺序问题根治：context-only buffer 未到时，告警挂起；context 到达后立即判定。
        let mut analyzer = Analyzer::new(AnalysisConfig::default());
        analyzer
            .match_buffers
            .insert("9103001".to_string(), meta(&["http.header"]));
        let alert = alert();
        let ev = event();
        // 无 context：应当挂起，不立即判定
        assert!(analyzer.should_defer_for_context(&ev, &alert));
        analyzer.process(ev.clone(), alert.clone());
        assert_eq!(analyzer.pending.len(), 1);
        // 补齐精确 context（导出名 http_header 归一为 http.header）后应能建 key
        context("http_header", "dXNlcg==", &mut analyzer.match_contexts);
        analyzer.flush_ready_pending();
        assert_eq!(analyzer.pending.len(), 0);
        let key = suppression_key(
            &ev,
            &alert,
            analyzer.match_buffers.get("9103001"),
            &analyzer.match_contexts,
        );
        assert!(key.unwrap().contains("http.header=dXNlcg=="));
    }

    #[test]
    fn expired_pending_fails_closed() {
        // 超时仍无 context：flush 后清空挂起，且不建立抑制 key。
        let mut analyzer = Analyzer::new(AnalysisConfig {
            pending_context_timeout: Duration::from_millis(0),
            ..Default::default()
        });
        analyzer
            .match_buffers
            .insert("9103001".to_string(), meta(&["http.header"]));
        let alert = alert();
        let ev = event();
        analyzer.process(ev.clone(), alert.clone());
        assert_eq!(analyzer.pending.len(), 1);
        analyzer.flush_expired_pending();
        assert_eq!(analyzer.pending.len(), 0);
        assert!(suppression_key(
            &ev,
            &alert,
            analyzer.match_buffers.get("9103001"),
            &analyzer.match_contexts
        )
        .is_none());
    }

    #[test]
    fn truncates_payload() {
        assert_eq!(truncate("abcdef", 3), "abc".to_string());
    }

    #[test]
    fn file_triage_document_marks_stage_and_sha() {
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        ev.file_sha256 = Some("a".repeat(64));
        ev.file_name = Some("shell.php".into());
        let triage = json!({
            "ok": true, "verdict": "malicious", "score": 100,
            "type": {"category": "script"}
        });
        let doc = file_triage_document(&ev, "completed", Some(&triage), None, None);
        assert_eq!(doc["event"]["kind"], "file_triage");
        assert_eq!(doc["event"]["status"], "completed");
        assert_eq!(doc["file"]["sha256"], "a".repeat(64));
        assert_eq!(doc["xbits"]["verdict"], "malicious");
        assert_eq!(doc["xbits"]["category"], "script");
        assert!(doc["intel"].is_null());
    }

    #[test]
    fn file_triage_document_carries_intel_annotation() {
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        ev.file_md5 = Some("aa".repeat(16));
        let intel = EventIntelAnnotations {
            threat: Some(json!([{"type": "md5", "value": "aa".repeat(16)}])),
            allowlist: None,
            public_dns_off_baseline: false,
        };
        let doc = file_triage_document(&ev, "received", None, None, Some(&intel));
        assert_eq!(doc["xbits"]["intel_decision"], "threat-hit");
        assert_eq!(doc["intel"][0]["type"], "md5");
    }

    // ---- 文件情报进 triage / 命中推 ES（R1 收尾、V-03 闭环）----

    fn sha256_hit_intel(value: &str) -> EventIntelAnnotations {
        EventIntelAnnotations {
            threat: Some(json!([{"type": "sha256", "value": value}])),
            allowlist: None,
            public_dns_off_baseline: false,
        }
    }

    #[test]
    fn triage_request_input_carries_file_intel_and_omits_when_absent() {
        let path = std::env::temp_dir().join("xbits-triage-input-blob.bin");
        let sha = "ab".repeat(32);
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        ev.file_sha256 = Some(sha.clone());
        ev.file_name = Some("blob.bin".into());

        let ann = sha256_hit_intel(&sha);
        let input = triage_request_input(&ev, &path, &sha, Some(&ann));
        // triage 在 --stdin 下不再读本地名单，情报必须由这里传下去。
        assert_eq!(input["intel"]["threat"][0]["type"], "sha256");
        assert_eq!(input["intel"]["threat"][0]["value"], sha.as_str());
        assert!(input["intel"]["allowlist"]
            .as_array()
            .is_some_and(|a| a.is_empty()));

        // 没有情报时不带 intel 键，triage 记为 xbits-payload(none)，行为不变。
        let plain = triage_request_input(&ev, &path, &sha, None);
        assert!(plain.get("intel").is_none());
    }

    #[test]
    fn file_intel_hit_marks_conflict_and_pushes_to_es() {
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        let sha = "cd".repeat(32);
        ev.file_sha256 = Some(sha.clone());
        let ann = sha256_hit_intel(&sha);

        let clean = json!({"verdict": "clean", "score": 10, "type": {"category": "binary"}});
        // triage 判 clean 但 xbits 命中黑 hash：必须推 ES（不然命中被静默丢弃）。
        assert!(file_triage_to_es("completed", Some(&clean), Some(&ann)));
        let doc = file_triage_document(&ev, "completed", Some(&clean), None, Some(&ann));
        assert_eq!(doc["xbits"]["verdict"], "malicious"); // 以情报为准
        assert_eq!(doc["xbits"]["triage_verdict"], "clean"); // 原始 triage 结论仍保留
        assert_eq!(doc["xbits"]["intel_conflict"], true);
        assert_eq!(doc["xbits"]["intel_decision"], "threat-hit");
        assert_eq!(doc["intel"][0]["type"], "sha256");
        assert!(doc["xbits"]["note"]
            .as_str()
            .unwrap_or("")
            .contains("intel-conflict"));

        // failed / skipped 阶段的已知威胁命中同样推 ES（超时、坏 JSON、类别跳过都不能静默丢）
        assert!(file_triage_to_es("failed", None, Some(&ann)));
        assert!(file_triage_to_es("skipped", Some(&clean), Some(&ann)));
        // received/analyzing 只落分析文件，避免重复推送
        assert!(!file_triage_to_es("received", None, Some(&ann)));

        // 无情报时行为不变：clean 不推 ES，文档不冲突
        assert!(!file_triage_to_es("completed", Some(&clean), None));
        let plain = file_triage_document(&ev, "completed", Some(&clean), None, None);
        assert_eq!(plain["xbits"]["verdict"], "clean");
        assert_eq!(plain["xbits"]["intel_conflict"], false);
        // 达到 malicious 时照旧推 ES
        let bad = json!({"verdict": "malicious", "score": 90});
        assert!(file_triage_to_es("completed", Some(&bad), None));
    }

    #[test]
    fn triage_worker_sends_intel_and_es_receives_threat_doc() {
        let dir = std::env::temp_dir().join(format!("xbits-triage-es-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let captured = dir.join("input.json");
        let es_out = dir.join("es.jsonl");
        let config = AnalysisConfig {
            // 先把 stdin 落盘，再输出 clean JSON（模拟 triage 判 clean）。
            triage_command: Some(format!(
                "tee \"{}\" >/dev/null; printf '{{\"verdict\":\"clean\",\"score\":5,\"type\":{{\"category\":\"binary\"}}}}'",
                captured.display()
            )),
            triage_categories: Vec::new(),
            es_command: Some(format!("cat >> \"{}\"", es_out.display())),
            ..Default::default()
        };
        let health = Arc::new(PipelineHealth::new());
        let docs = Arc::new(DocumentEmitter::new(&config, Arc::clone(&health)));
        let mut worker = TriageWorker::new(&config, docs, Arc::clone(&health));

        let sha = "ef".repeat(32);
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        ev.file_sha256 = Some(sha.clone());
        ev.file_name = Some("evil.bin".into());
        worker.process(TriageJob {
            event: ev,
            path: dir.join("evil.bin"),
            sha: sha.clone(),
            intel: Some(sha256_hit_intel(&sha)),
        });

        // 1) triage 收到的 stdin 真的带 intel（否则 --stdin 下无法判 known_bad）
        let sent = std::fs::read_to_string(&captured).unwrap_or_default();
        assert!(sent.contains("\"intel\""), "triage input missing intel: {sent}");
        assert!(sent.contains(&sha), "triage input missing hash: {sent}");

        // 2) triage 判 clean，但 xbits 情报命中 → 文档仍推 ES，且带 intel/intel_decision/conflict
        let es = std::fs::read_to_string(&es_out).unwrap_or_default();
        assert!(!es.trim().is_empty(), "ES sink got no document");
        assert!(es.contains("\"intel_conflict\":true"), "es doc: {es}");
        assert!(es.contains("\"intel_decision\":\"threat-hit\""), "es doc: {es}");
        assert!(es.contains("\"stage\":\"completed\""), "es doc: {es}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalized_document_carries_intel_and_decision() {
        let mut al = alert();
        al.intel = Some(json!([{"type": "ip", "value": "203.0.113.9"}]));
        al.allowlist = Some(json!({"hits": [{"type": "domain", "value": "a.example", "list": "example"}]}));
        al.intel_decision = Some("threat-hit".into());
        let decision = Decision {
            verdict: "uncertain".into(),
            confidence: al.confidence,
            reason: "intel-threat".into(),
            evidence: Vec::new(),
            validator_used: false,
            validator_reason: None,
        };
        let doc = normalized_document(&event(), &al, &decision, "", 64);
        assert_eq!(doc["intel"][0]["value"], "203.0.113.9");
        assert_eq!(doc["allowlist"]["hits"][0]["list"], "example");
        assert_eq!(doc["xbits"]["intel_decision"], "threat-hit");
        assert_eq!(doc["xbits"]["reason"], "intel-threat");
    }

    #[test]
    fn decide_writes_intel_reason_and_keeps_validator_state_in_evidence() {
        let analyzer = Analyzer::new(AnalysisConfig::default());
        let mut al = alert();
        al.intel_decision = Some("allowlist-downgraded".into());
        al.allowlist = Some(json!({"hits": [{"type": "ip", "value": "10.0.0.80"}]}));
        let decision = analyzer.decide(&event(), &al);
        assert_eq!(decision.reason, "intel-allowlist");
        assert!(decision.evidence.iter().any(|e| e == "intel_decision=allowlist-downgraded"));
        assert!(decision.evidence.iter().any(|e| e == "validator-missing"));
        // 没有情报决策时保持原有语义
        let plain = analyzer.decide(&event(), &alert());
        assert_eq!(plain.reason, "validator-missing");
    }

    #[test]
    fn validator_reason_does_not_override_intel_decision_reason() {
        // 模拟 CI 的 stub validator：返回固定的空泛 reason（stub-validator）。
        // 命令先 `cat` 掉 stdin 再输出，避免子进程不读 stdin 时写管道 EPIPE。
        let analyzer = Analyzer::new(AnalysisConfig {
            validator_command: Some(
                r#"cat >/dev/null; printf '{"verdict":"uncertain","confidence":60,"reason":"stub-validator"}'"#
                    .to_string(),
            ),
            ..Default::default()
        });

        // 有情报决策：reason 必须保留 intel-*，validator 的结论单独记录（R2）。
        let mut al = alert();
        al.intel_decision = Some("threat-hit".into());
        al.intel = Some(json!([{"type": "ip", "value": "203.0.113.9"}]));
        let decision = analyzer.decide(&event(), &al);
        assert!(decision.validator_used, "validator 应该被执行");
        assert_eq!(decision.reason, "intel-threat");
        assert_eq!(decision.validator_reason.as_deref(), Some("stub-validator"));
        assert!(decision
            .evidence
            .iter()
            .any(|e| e == "validator-reason=stub-validator"));

        // 最终告警文档能同时看出"情报参与过决策"与 validator 结论。
        let doc = normalized_document(&event(), &al, &decision, "", 64);
        assert_eq!(doc["xbits"]["reason"], "intel-threat");
        assert_eq!(doc["xbits"]["validator_reason"], "stub-validator");
        assert_eq!(doc["xbits"]["intel_decision"], "threat-hit");

        // 没有情报决策时保持原语义：validator reason 作为主 reason。
        let plain = analyzer.decide(&event(), &alert());
        assert_eq!(plain.reason, "stub-validator");
        assert_eq!(plain.validator_reason.as_deref(), Some("stub-validator"));
    }

    #[test]
    fn resolve_file_path_uses_filestore_v2_layout() {
        let base = std::env::temp_dir().join(format!("xbits-ft-{}", std::process::id()));
        let sha = "b".repeat(64);
        let sub = base.join(sha.get(0..2).unwrap());
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join(&sha);
        std::fs::write(&file, b"x").unwrap();
        let analyzer = Analyzer::new(AnalysisConfig {
            file_spool_dir: Some(base.clone()),
            ..Default::default()
        });
        let mut ev = HookEvent::default();
        ev.file_sha256 = Some(sha.clone());
        let got = analyzer.resolve_file_path(&ev, &sha);
        assert_eq!(got, Some(file));
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- 可观测性（V-07/S-04）----

    #[test]
    fn rejects_non_hex_sha_without_panicking() {
        // hook socket 0666：file_sha256 完全不可信，任何非 hex 值都不得进入字节切片/路径拼接。
        let analyzer = Analyzer::new(AnalysisConfig {
            file_spool_dir: Some(std::env::temp_dir()),
            ..Default::default()
        });
        let ev = HookEvent::default();
        assert!(analyzer.resolve_file_path(&ev, "恶意多字节").is_none());
        assert!(analyzer.resolve_file_path(&ev, "").is_none());
        assert!(analyzer.resolve_file_path(&ev, "../../etc/passwd").is_none());
        assert!(!is_hex_hash(&"a".repeat(63)));
        assert!(!is_hex_hash(&"z".repeat(64)));
        assert!(is_hex_hash(&"b".repeat(64)));
        assert!(is_hex_hash(&"c".repeat(32)));
        assert!(is_hex_hash(&"d".repeat(40)));
    }

    #[test]
    fn metadata_parse_failure_is_reported() {
        let dir = std::env::temp_dir().join(format!("xbits-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("sid_library.json");
        std::fs::write(&bad, "{ this is not json").unwrap();
        let (map, ok) = load_meta(&Some(bad));
        assert!(map.is_empty());
        assert!(!ok, "解析失败必须返回失败标记，而不是静默空表");
        let (missing, missing_ok) = load_meta(&Some(dir.join("missing.json")));
        assert!(missing.is_empty());
        assert!(!missing_ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn document_errors_and_missing_sinks_are_counted() {
        let dir = std::env::temp_dir().join(format!("xbits-emit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 1) analysis_file 指向目录 → 打开失败必须计数；同时因未配 ES，to_es 文档也应计入无 sink
        let analyzer = Analyzer::new(AnalysisConfig {
            analysis_file: Some(dir.clone()),
            ..Default::default()
        });
        analyzer.emit(&json!({"event": {"kind": "alert"}}), true);
        assert_eq!(analyzer.health.document_errors(), 1);
        assert_eq!(analyzer.health.documents_without_sink(), 1);

        // 2) 完全没有 sink：to_es=false 的文档也不得静默消失
        let analyzer = Analyzer::new(AnalysisConfig::default());
        analyzer.emit(&json!({"event": {"kind": "file_triage"}}), false);
        analyzer.emit(&json!({"event": {"kind": "alert"}}), true);
        assert_eq!(analyzer.health.documents_without_sink(), 2);
        assert_eq!(analyzer.health.document_errors(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_health_failure_is_detectable_and_counted() {
        let health = PipelineHealth::new();
        assert!(!health.is_available());
        health.set_available(true);
        assert!(health.is_available());
        health.fail("worker panicked: boom");
        assert!(!health.is_available());
        assert_eq!(
            health.failure_reason().as_deref(),
            Some("worker panicked: boom")
        );
        // 连续失败计数可观察
        assert_eq!(health.record_send_failure(), 1);
        assert_eq!(health.record_send_failure(), 2);
        assert_eq!(health.send_failures(), 2);
        health.record_config_error();
        health.record_document_error();
        assert_eq!(health.config_errors(), 1);
        assert_eq!(health.document_errors(), 1);
        // failure reason 只记录第一次，便于定位根因
        health.fail("second");
        assert_eq!(
            health.failure_reason().as_deref(),
            Some("worker panicked: boom")
        );
    }

    // ---- triage 阶段语义 / 进程组 / 队列隔离（V-08）----

    #[test]
    fn run_shell_distinguishes_success_nonzero_timeout_and_utf8() {
        match run_shell("printf ok", "", Duration::from_secs(5)) {
            ShellOutcome::Success(out) => assert_eq!(out, "ok"),
            other => panic!("expected Success, got {other:?}"),
        }
        match run_shell("echo boom >&2; exit 7", "", Duration::from_secs(5)) {
            ShellOutcome::NonZeroExit { code, stderr } => {
                assert_eq!(code, Some(7));
                assert!(stderr.contains("boom"), "stderr={stderr}");
            }
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
        // 超时必须显式返回 Timeout（而不是空串），并真的杀掉进程组。
        let started = Instant::now();
        match run_shell("sleep 5", "", Duration::from_millis(100)) {
            ShellOutcome::Timeout {
                after_ms,
                kill_error,
            } => {
                assert!(after_ms >= 100, "after_ms={after_ms}");
                assert!(kill_error.is_none(), "process-group kill failed: {kill_error:?}");
                assert!(
                    started.elapsed() < Duration::from_secs(3),
                    "timeout was not enforced: {:?}",
                    started.elapsed()
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        // 非 UTF-8 stdout 必须显式区分，不要退化成"JSON 解析失败"。
        // 用 0xC3 0x28 组成非法 UTF-8 序列（dash 的 \0377 只会产生 0x1F+'7'，仍是合法 UTF-8）。
        match run_shell(r"printf '\303\050'", "", Duration::from_secs(5)) {
            ShellOutcome::OutputNotUtf8(_) => {}
            other => panic!("expected OutputNotUtf8, got {other:?}"),
        }
    }

    #[test]
    fn admit_file_rejects_stored_false_even_if_spool_has_file() {
        let base = std::env::temp_dir().join(format!("xbits-admit-{}", std::process::id()));
        let sha = "c".repeat(64);
        let sub = base.join(sha.get(0..2).unwrap());
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(&sha), b"x").unwrap();
        let analyzer = Analyzer::new(AnalysisConfig {
            file_spool_dir: Some(base.clone()),
            ..Default::default()
        });
        let mut ev = HookEvent::default();
        ev.file_sha256 = Some(sha.clone());
        ev.file_stored = Some(false);
        // Suricata 明确说没落盘：即使 spool 里恰好有同名文件也不能拿来 triage。
        let err = analyzer.admit_file(&ev, &sha).unwrap_err();
        assert!(err.contains("stored=false"), "{err}");

        ev.file_stored = Some(true);
        let path = analyzer.admit_file(&ev, &sha).expect("spool hit");
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn admit_file_explains_bad_sha_and_missing_file() {
        let base = std::env::temp_dir().join(format!("xbits-admit2-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let analyzer = Analyzer::new(AnalysisConfig {
            file_spool_dir: Some(base.clone()),
            ..Default::default()
        });
        let ev = HookEvent::default();
        let err = analyzer.admit_file(&ev, "恶意多字节").unwrap_err();
        assert!(err.starts_with("bad-file-sha256"), "{err}");
        let err = analyzer
            .admit_file(&ev, &"d".repeat(64))
            .unwrap_err();
        assert!(err.contains("file-not-found"), "{err}");

        let no_spool = Analyzer::new(AnalysisConfig::default());
        let err = no_spool.admit_file(&ev, &"d".repeat(64)).unwrap_err();
        assert!(err.contains("file-not-locatable"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn triage_queue_full_is_counted_and_documented() {
        let dir = std::env::temp_dir().join(format!("xbits-queue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("docs.jsonl");
        let config = AnalysisConfig {
            analysis_file: Some(out.clone()),
            ..Default::default()
        };
        let health = Arc::new(PipelineHealth::new());
        let docs = Arc::new(DocumentEmitter::new(&config, Arc::clone(&health)));
        // 容量 1 且没有消费者：第二次投递必然 Full。
        let (triage_tx, _triage_rx) = mpsc::sync_channel::<TriageJob>(1);
        let analyzer = Analyzer::new_with_health(config, Arc::clone(&health), docs, triage_tx);
        let sha = "e".repeat(64);
        let mut ev = HookEvent::default();
        ev.source = "suricata".into();
        ev.kind = "file_stored".into();
        ev.file_sha256 = Some(sha.clone());
        for _ in 0..2 {
            analyzer.submit_triage(TriageJob {
                event: ev.clone(),
                path: PathBuf::from("/nonexistent/spool/file"),
                sha: sha.clone(),
                intel: None,
            });
        }
        assert_eq!(health.triage_dropped(), 1);
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        assert!(text.contains("triage-queue-full"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn triage_worker_gone_marks_pipeline_unavailable() {
        // 测试构造器的 triage 接收端已丢弃：投递必须明确失败并把流水线标记为不可用。
        let analyzer = Analyzer::new(AnalysisConfig::default());
        let sha = "f".repeat(64);
        let mut ev = HookEvent::default();
        ev.kind = "file_stored".into();
        ev.file_sha256 = Some(sha.clone());
        analyzer.submit_triage(TriageJob {
            event: ev,
            path: PathBuf::from("/nonexistent/spool/file"),
            sha,
            intel: None,
        });
        assert_eq!(analyzer.health.triage_dropped(), 1);
        assert!(!analyzer.health.is_available());
        assert!(analyzer
            .health
            .failure_reason()
            .unwrap_or_default()
            .contains("triage worker"));
    }
}