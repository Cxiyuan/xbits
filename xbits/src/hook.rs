use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::analysis::AnalysisPipeline;
use crate::engine::Engine;
use crate::model::{HookEvent, Rule};

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
    ev.extra = v.as_object().cloned().unwrap_or_default();
    Some(ev)
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
    eprintln!(
        "xbits: hook listener on {} (rules={})",
        socket_path,
        engine.rules_len()
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(err) => {
                eprintln!("xbits: hook accept error: {err}");
                continue;
            }
        };
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(err) => {
                    eprintln!("xbits: hook read error: {err}");
                    break;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ev: HookEvent = match parse_event(trimmed) {
                Some(v) => v,
                None => {
                    eprintln!("xbits: bad hook event: {trimmed}");
                    continue;
                }
            };
            if ev.kind.eq_ignore_ascii_case("match_context") {
                if let Some(pipeline) = pipeline {
                    pipeline.submit_event(ev);
                }
                continue;
            }
            for alert in engine.process(&ev) {
                if let Some(pipeline) = pipeline {
                    pipeline.submit_alert(ev.clone(), alert.clone());
                }
                match serde_json::to_string(&alert) {
                    Ok(json) => {
                        writeln!(writer, "{json}")?;
                        writer.flush()?;
                    }
                    Err(err) => eprintln!("xbits: serialize alert error: {err}"),
                }
            }
        }
    }

    Ok(())
}
