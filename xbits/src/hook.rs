use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

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
pub fn run_hook_listener<W: Write>(
    socket_path: &str,
    rules: Vec<Rule>,
    writer: &mut W,
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
            for alert in engine.process(&ev) {
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
