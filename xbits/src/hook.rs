use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::analysis::AnalysisPipeline;
use crate::engine::Engine;
use crate::model::{HookEvent, Rule};

/// 空闲维护节拍（R5-1）：连接上无数据超过该间隔就触发一次引擎维护，
/// 让挂起告警的 TTL 过期 / 计数 / 降级输出与"是否有新事件"解耦。
const MAINTENANCE_TICK: Duration = Duration::from_millis(200);
/// accept 空闲时的轮询间隔（无连接时也要按 tick 推进维护，但不忙等）。
const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(20);

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

/// 分析流水线 / 引擎不可用时返回错误：让进程以非零退出，而不是静默降级继续跑。
///
/// 触发来源：分析线程 panic 退出，或入队连续失败达到阈值（见 `PipelineHealth`）。
/// 消息里同时带两层指标，且**字段名不混用**：
/// - 分析层：`pending_expired` / `pending_overflow`（等 match_context 的告警）；
/// - 引擎层：`engine_pending_expired` / `engine_pending_overflow` / `engine_contexts_expired` /
///   `engine_scores_expired` / `engine_scores_evicted`（R4-1：引擎计数真正导出并被消费）。
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
    let engine_stats = engine
        .map(|engine| {
            format!(
                ", engine_pending_expired={}, engine_pending_overflow={}, engine_contexts_expired={}, engine_scores_expired={}, engine_scores_evicted={}",
                engine.pending_expired(),
                engine.pending_overflow(),
                engine.contexts_expired(),
                engine.scores_expired(),
                engine.scores_evicted()
            )
        })
        .unwrap_or_default();
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
fn maintenance<W: Write + ?Sized>(
    engine: &mut Engine,
    pipeline: Option<&AnalysisPipeline>,
    writer: &mut W,
) -> io::Result<()> {
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
    Ok(())
}

/// 处理一条连接：带 read_timeout 的读取循环 + 跨读/跨超时的**残留半行缓冲**。
///
/// R5-1：超时不是错误——超时即触发一次引擎维护（所以挂起告警的 TTL 不再依赖下一条事件）；
/// 同时半行 JSON 必须留在 `pending` 缓冲里，绝不因超时丢失。
fn serve_stream<W: Write + ?Sized>(
    stream: UnixStream,
    engine: &mut Engine,
    pipeline: Option<&AnalysisPipeline>,
    writer: &mut W,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(MAINTENANCE_TICK))?;
    let mut reader = BufReader::new(stream);
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                // 对端关闭：把最后一行（可能没有换行符）也处理掉，然后结束连接。
                if !pending.is_empty() {
                    let line = String::from_utf8_lossy(&pending).into_owned();
                    pending.clear();
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        handle_line(trimmed, engine, pipeline, writer)?;
                    }
                }
                break;
            }
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);
                while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
                    let mut line_bytes = Vec::with_capacity(pos);
                    line_bytes.extend_from_slice(&pending[..pos]);
                    pending.drain(..=pos);
                    let line = String::from_utf8_lossy(&line_bytes);
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    handle_line(trimmed, engine, pipeline, writer)?;
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                // 空闲 tick：推进引擎维护（过期降级告警要能按时输出，R5-1）。
                maintenance(engine, pipeline, writer)?;
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
    run_hook_listener_full(socket_path, rules, writer, pipeline, None)
}

/// 完整版 listener：可挂载统一情报服务（threat-intel + allowlist），
/// 引擎告警将携带 intel / allowlist 标注。
pub fn run_hook_listener_full<W: Write + ?Sized>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
    pipeline: Option<&AnalysisPipeline>,
    intel: Option<std::sync::Arc<crate::intel::IntelService>>,
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

    let mut engine = Engine::new(rules);
    if let Some(ref intel) = intel {
        engine = engine.with_intel(intel.clone());
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

    // R5-1：listener 需要"无事件也按 tick 维护"。accept 设为非阻塞，用短睡眠轮询，
    // 空闲时按 MAINTENANCE_TICK 节流地推进引擎维护（挂起告警的 TTL 不再依赖下一条事件）。
    listener.set_nonblocking(true)?;
    let mut last_maintenance = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // 新连接时复查分析流水线健康（线程可能已在无流量期间退出）。
                ensure_pipeline_healthy(pipeline, Some(&engine))?;
                serve_stream(stream, &mut engine, pipeline, writer)?;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if last_maintenance.elapsed() >= MAINTENANCE_TICK {
                    maintenance(&mut engine, pipeline, writer)?;
                    last_maintenance = Instant::now();
                }
                std::thread::sleep(ACCEPT_IDLE_SLEEP);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}
