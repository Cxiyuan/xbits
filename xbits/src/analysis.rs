use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::EngineAlert;
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
        }
    }
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
    reason: String,
    evidence: Vec<String>,
    validator_used: bool,
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

fn load_meta(path: &Option<PathBuf>) -> HashMap<String, RuleMeta> {
    let Some(path) = path else {
        return HashMap::new();
    };
    match fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(err) => {
            eprintln!("xbits: cannot load metadata {}: {err}", path.display());
            HashMap::new()
        }
    }
}

fn load_match_buffers(path: &Option<PathBuf>) -> HashMap<String, MatchBufferMeta> {
    let Some(path) = path else {
        return HashMap::new();
    };
    match fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(err) => {
            eprintln!("xbits: cannot load match buffers {}: {err}", path.display());
            HashMap::new()
        }
    }
}

fn run_shell(command: &str, input: &str, timeout: Duration) -> io::Result<String> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut stream) = stdout {
            let _ = stream.read_to_string(&mut out);
        }
        if let Some(mut stream) = stderr {
            let _ = stream.read_to_string(&mut err);
        }
        let _ = tx.send((out, err));
    });

    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }

    let (out, err) = rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|_| (String::new(), String::new()));
    if out.trim().is_empty() && !err.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, err.trim().to_string()));
    }
    Ok(out)
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
}

impl Analyzer {
    fn new(config: AnalysisConfig) -> Self {
        let sid_library = load_meta(&config.sid_library);
        let rules_meta = load_meta(&config.rules_meta);
        let match_buffers = load_match_buffers(&config.match_buffers);
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
            reason: "engine-alert".into(),
            evidence: if alert.evidence.is_empty() {
                Vec::new()
            } else {
                vec![alert.evidence.clone()]
            },
            validator_used: false,
        };
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
            match run_shell(
                command,
                &serde_json::to_string(&request).unwrap_or_default(),
                self.config.validator_timeout,
            ) {
                Ok(output) => match serde_json::from_str::<ValidatorDecision>(&output) {
                    Ok(v) => {
                        decision.verdict = normalize_verdict(&v.verdict);
                        decision.confidence = v.confidence.unwrap_or(decision.confidence).min(100);
                        if !v.reason.is_empty() {
                            decision.reason = v.reason;
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
                Err(err) => {
                    decision
                        .evidence
                        .push(format!("validator-error={err}"));
                }
            }
        }

        if !decision.validator_used {
            // 没有验证器或验证器不可用时，保持 uncertain：
            // 宁可不建立白名单，也不凭空判定 true_positive/false_positive。
            decision.verdict = "uncertain".into();
            decision.reason = if self.config.validator_command.is_some() {
                "validator-unavailable".into()
            } else {
                "validator-missing".into()
            };
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

    fn emit(&self, doc: &Value, to_es: bool) {
        let line = match serde_json::to_string(doc) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("xbits: normalized document serialize error: {err}");
                return;
            }
        };
        if let Some(path) = self.config.analysis_file.as_ref() {
            if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{line}");
            }
        }
        if !to_es {
            return;
        }
        if let Some(url) = self.config.es_url.as_ref() {
            if let Err(err) = post_http_json(url, &line, self.config.es_auth.as_deref()) {
                eprintln!("xbits: Elasticsearch write failed: {err}");
            }
        }
        if let Some(command) = self.config.es_command.as_ref() {
            if let Err(err) = run_shell(command, &line, Duration::from_secs(10)) {
                eprintln!("xbits: ES command failed: {err}");
            }
        }
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
    json!({
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
        },
        "payload": {
            "text": truncate(payload, max_payload),
            "truncated": payload.chars().count() > max_payload,
            "features": payload_features(payload),
        },
        "zeek": alert.context.clone(),
    })
}

enum Job {
    Event(HookEvent),
    Alert(HookEvent, EngineAlert),
}

/// 异步分析与输出流水线。Suricata hook 线程只负责入队，避免工具验证阻塞。
pub struct AnalysisPipeline {
    tx: Sender<Job>,
}

impl AnalysisPipeline {
    pub fn start(config: AnalysisConfig) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        thread::Builder::new()
            .name("xbits-analysis".into())
            .spawn(move || {
                let mut analyzer = Analyzer::new(config);
                let tick = analyzer.config.pending_context_timeout;
                loop {
                    match rx.recv_timeout(tick) {
                        Ok(Job::Event(event)) => analyzer.observe(event),
                        Ok(Job::Alert(event, alert)) => analyzer.process(event, alert),
                        Err(mpsc::RecvTimeoutError::Timeout) => analyzer.flush_expired_pending(),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        Ok(Self { tx })
    }

    pub fn submit_event(&self, event: HookEvent) {
        let _ = self.tx.send(Job::Event(event));
    }

    pub fn submit_alert(&self, event: HookEvent, alert: EngineAlert) {
        let _ = self.tx.send(Job::Alert(event, alert));
    }

    /// 兼容旧调用：按告警事件提交。
    pub fn submit(&self, event: HookEvent, alert: EngineAlert) {
        self.submit_alert(event, alert);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            event: None,
            alert_kind: None,
            alert_name: None,
            severity: None,
            uid: Some("C1".into()),
            context: None,
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
            has_payload: true,
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
}