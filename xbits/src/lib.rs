//! xbits · Suricata EVE -> Zeek event bridge
//!
//! Reads Suricata EVE JSON from a Unix stream socket, filters alert records,
//! normalizes them, and writes one JSON object per line to stdout.
//! The output is consumed by `xbits/zeek/xbits_suricata.zeek` through Zeek's
//! raw Input reader in execute/stream mode.

use std::io::{self, BufRead, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub timestamp: String,
    pub signature_id: u64,
    pub signature: String,
    pub community_id: String,
    pub src: String,
    pub dst: String,
    pub sport: u64,
    pub dport: u64,
    pub proto: String,
    pub flow_id: String,
}

pub fn parse_eve_line(line: &str) -> Option<Alert> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("event_type")?.as_str()? != "alert" {
        return None;
    }

    let alert = value.get("alert")?;
    let signature_id = alert.get("signature_id")?.as_u64()?;
    let signature = alert
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let community_id = value
        .get("community_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let src = value
        .get("src_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dst = value
        .get("dest_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let sport = value.get("src_port").and_then(Value::as_u64).unwrap_or(0);
    let dport = value.get("dest_port").and_then(Value::as_u64).unwrap_or(0);
    let proto = value
        .get("proto")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let flow_id = value
        .get("flow_id")
        .map(|v| match v {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();

    Some(Alert {
        timestamp,
        signature_id,
        signature,
        community_id,
        src,
        dst,
        sport,
        dport,
        proto,
        flow_id,
    })
}

pub fn alert_to_json(alert: &Alert) -> String {
    serde_json::json!({
        "timestamp": alert.timestamp,
        "signature_id": alert.signature_id,
        "signature": alert.signature,
        "community_id": alert.community_id,
        "src": alert.src,
        "dst": alert.dst,
        "sport": alert.sport,
        "dport": alert.dport,
        "proto": alert.proto,
        "flow_id": alert.flow_id,
    })
    .to_string()
}

/// Process an EVE JSON stream. Only alert records are written.
pub fn stream_to_writer<R: BufRead, W: Write>(mut reader: R, writer: &mut W) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(alert) = parse_eve_line(trimmed) {
            writeln!(writer, "{}", alert_to_json(&alert))?;
            writer.flush()?;
        }
    }
}

struct SocketFile {
    path: PathBuf,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Listen on a Unix stream socket. Suricata is the connecting client for
/// `eve-log.filetype: unix_stream`, so xbits must own the listening side.
/// With `once=false`, accept Suricata reconnects until the process is stopped.
pub fn run_listener(socket_path: &str, writer: &mut impl Write, once: bool) -> io::Result<()> {
    let path = Path::new(socket_path);
    if path.exists() {
        let file_type = std::fs::metadata(path)?.file_type();
        if !file_type.is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{socket_path} exists and is not a Unix socket"),
            ));
        }
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    // Suricata normally runs as a different user than xbits. The socket is
    // local-only; deployment should still protect its parent directory.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let _guard = SocketFile {
        path: path.to_path_buf(),
    };

    loop {
        let (stream, _) = listener.accept()?;
        let reader = io::BufReader::new(stream);
        if let Err(err) = stream_to_writer(reader, writer) {
            if once {
                return Err(err);
            }
            eprintln!("xbits: EVE stream error: {err}");
        }
        if once {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::thread;

    #[test]
    fn parses_alert_and_ignores_non_alert() {
        let alert = parse_eve_line(
            include_str!("../testdata/alert.jsonl")
                .lines()
                .next()
                .unwrap(),
        )
        .expect("alert");
        assert_eq!(alert.signature_id, 9103001);
        assert_eq!(alert.community_id, "1:testCID=");
        assert_eq!(alert.src, "203.0.113.9");
        assert_eq!(alert.dport, 80);
        assert!(parse_eve_line(r#"{"event_type":"flow","community_id":"1:testCID="}"#).is_none());
    }

    #[test]
    fn stream_filters_alerts() {
        let input = include_str!("../testdata/alert.jsonl");
        let mut out = Vec::new();
        stream_to_writer(Cursor::new(input), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"signature_id\":9103001"));
        assert!(text.contains("\"community_id\":\"1:testCID=\""));
    }

    #[test]
    fn serves_alert_from_unix_socket_once() {
        let path = PathBuf::from(format!(
            "/tmp/xbits-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_string = path.to_str().expect("utf-8 socket path").to_string();
        let input = include_str!("../testdata/alert.jsonl").to_string();
        let server = thread::spawn(move || {
            let mut out = Vec::new();
            run_listener(&path_string, &mut out, true).expect("listen");
            out
        });

        for _ in 0..100 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut stream = UnixStream::connect(&path).expect("connect to xbits");
        stream.write_all(input.as_bytes()).expect("write EVE lines");
        drop(stream);

        let out = server.join().expect("server thread");
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"signature_id\":9103001"));
    }
}
