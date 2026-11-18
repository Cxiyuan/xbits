use std::collections::HashMap;
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
    #[serde(default)]
    primary: Option<String>,
    #[serde(default)]
    has_payload: bool,
    #[serde(default)]
    source: Option<String>,
}

struct Decision {
    verdict: String,
    confidence: u64,
    reason: String,
    evidence: Vec<String>,
    validator_used: bool,
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

fn match_context_key(event: &HookEvent) -> Option<String> {
    let buffer = event.match_context_buffer.as_deref()?;
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
            "lua" | "http.header" | "http.request_header" | "http.response_header"
            | "file.data" => None,
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
        let context_key = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            event.source,
            alert.signature_id,
            alert.src,
            alert.sport,
            alert.dst,
            alert.dport,
            alert.proto,
            buffer
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

struct Analyzer {
    config: AnalysisConfig,
    sid_library: HashMap<String, RuleMeta>,
    rules_meta: HashMap<String, RuleMeta>,
    match_buffers: HashMap<String, MatchBufferMeta>,
    match_contexts: HashMap<String, MatchContextEntry>,
    whitelist: SuppressionStore,
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
        let key = suppression_key(
            &event,
            &alert,
            self.match_buffers.get(&alert.signature_id.to_string()),
            &self.match_contexts,
        );
        let context_used = match (&key, self.match_buffers.get(&alert.signature_id.to_string())) {
            (Some(_), Some(meta)) => meta
                .buffers
                .iter()
                .any(|b| b == "lua" || b == "http.header" || b == "file.data"),
            _ => false,
        };
        if context_used && self.match_contexts.is_empty() {
            // 依赖 match_context 导出的 SID 在没有导出通道时必须显式失败，
            // 不允许静默回退成“不抑制/乱抑制”。
            eprintln!(
                "xbits: sid {} requires match_context but none received; skipping suppression",
                alert.signature_id
            );
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
        let doc = normalized_document(&event, &alert, &decision, payload, self.config.max_payload);
        let is_false_positive = decision.is_false_positive();
        if is_false_positive {
            if let Some(key) = key {
                self.whitelist.add(key);
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
                while let Ok(job) = rx.recv() {
                    match job {
                        Job::Event(event) => analyzer.observe(event),
                        Job::Alert(event, alert) => analyzer.process(event, alert),
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

    #[test]
    fn normalizes_false_positive_verdict() {
        assert_eq!(normalize_verdict("false-positive"), "false_positive".to_string());
        assert_eq!(normalize_verdict("FP"), "false_positive".to_string());
        assert_eq!(normalize_verdict("maybe"), "uncertain".to_string());
    }

    #[test]
    fn truncates_payload() {
        assert_eq!(truncate("abcdef", 3), "abc".to_string());
    }
}