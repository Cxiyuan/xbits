use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use xbits::analysis::{AnalysisConfig, AnalysisPipeline};
use xbits::hook::run_hook_listener_with_analysis;
use xbits::model::Rule;

fn load_rules(path: Option<String>) -> io::Result<Vec<Rule>> {
    match path {
        None => Ok(Vec::new()),
        Some(path) => {
            let data = fs::read_to_string(&path)?;
            serde_json::from_str::<Vec<Rule>>(&data).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad rules file {path}: {err}"),
                )
            })
        }
    }
}

fn parse_u64(value: Option<String>, name: &str) -> io::Result<u64> {
    value
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} value missing")))?
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("bad {name}: {err}")))
}

fn main() -> io::Result<()> {
    let mut socket = String::from("/var/run/suricata/eve.sock");
    let mut hook_socket: Option<String> = None;
    let mut rules_file: Option<String> = None;
    let mut alert_file: Option<String> = None;
    let mut once = false;
    let mut stdin_mode = false;
    let mut validator_command: Option<String> = None;
    let mut validator_timeout_ms: u64 = 5000;
    let mut sid_library: Option<PathBuf> = None;
    let mut rules_meta: Option<PathBuf> = None;
    let mut es_url: Option<String> = None;
    let mut es_command: Option<String> = None;
    let mut es_auth: Option<String> = None;
    let mut analysis_file: Option<PathBuf> = None;
    let mut match_buffers: Option<PathBuf> = None;
    let mut suppression_ttl_sec: u64 = 300;
    let mut fp_confidence: u64 = 90;
    let mut max_payload: usize = 16384;
    let mut pending_context_ms: u64 = 500;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--socket value missing")
                })?;
            }
            "--hook-socket" => {
                hook_socket = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--hook-socket value missing")
                })?);
            }
            "--rules" => {
                rules_file = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--rules value missing")
                })?);
            }
            "--alert-file" | "--out-file" => {
                alert_file = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--alert-file value missing")
                })?);
            }
            "--validator-cmd" => {
                validator_command = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--validator-cmd value missing")
                })?);
            }
            "--validator-timeout-ms" => {
                validator_timeout_ms = parse_u64(args.next(), "--validator-timeout-ms")?;
            }
            "--sid-library" => {
                sid_library = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--sid-library value missing")
                })?));
            }
            "--rules-meta" => {
                rules_meta = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--rules-meta value missing")
                })?));
            }
            "--es-url" => {
                es_url = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--es-url value missing")
                })?);
            }
            "--es-command" => {
                es_command = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--es-command value missing")
                })?);
            }
            "--es-auth" => {
                es_auth = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--es-auth value missing")
                })?);
            }
            "--analysis-file" => {
                analysis_file = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--analysis-file value missing")
                })?));
            }
            "--match-buffers" => {
                match_buffers = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--match-buffers value missing")
                })?));
            }
            "--suppression-ttl-sec" => {
                suppression_ttl_sec = parse_u64(args.next(), "--suppression-ttl-sec")?;
            }
            "--fp-confidence" => {
                fp_confidence = parse_u64(args.next(), "--fp-confidence")?;
            }
            "--max-payload" => {
                max_payload = parse_u64(args.next(), "--max-payload")? as usize;
            }
            "--pending-context-ms" => {
                pending_context_ms = parse_u64(args.next(), "--pending-context-ms")?;
            }
            "--once" => once = true,
            "--stdin" => stdin_mode = true,
            "--help" | "-h" => {
                println!(
                    "xbits: Suricata EVE / thin-hook -> Zeek event stream + central engine\n\
                     usage:\n\
                       xbits [--socket PATH] [--once]        # Suricata EVE unix_stream bridge\n\
                       xbits --hook-socket PATH [--rules R] [--alert-file F]  # hook + central engine\n\
                       xbits --stdin                         # offline EVE stdin\n\
                     analysis options (with --hook-socket):\n\
                       --validator-cmd CMD --validator-timeout-ms N\n\
                       --sid-library FILE --rules-meta FILE\n\
                       --es-url http://host:9200/index/_doc | --es-command CMD\n\
                       --es-auth HEADER --analysis-file FILE --match-buffers FILE\n\
                       --suppression-ttl-sec N --fp-confidence N --max-payload N --pending-context-ms N"
                );
                return Ok(());
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
    }

    let rules = load_rules(rules_file)?;
    let mut out: Box<dyn io::Write> = match alert_file {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(io::stdout()),
    };

    if let Some(path) = hook_socket {
        let analysis_enabled = validator_command.is_some()
            || sid_library.is_some()
            || rules_meta.is_some()
            || es_url.is_some()
            || es_command.is_some()
            || analysis_file.is_some()
            || match_buffers.is_some();
        let pipeline = if analysis_enabled {
            let config = AnalysisConfig {
                validator_command,
                validator_timeout: Duration::from_millis(validator_timeout_ms.max(1)),
                sid_library,
                rules_meta,
                es_url,
                es_command,
                es_auth,
                analysis_file,
                match_buffers,
                suppression_ttl: Duration::from_secs(suppression_ttl_sec.max(1)),
                fp_confidence: fp_confidence.min(100),
                max_payload: max_payload.max(64),
                pending_context_timeout: Duration::from_millis(pending_context_ms.max(1)),
            };
            Some(AnalysisPipeline::start(config)?)
        } else {
            None
        };
        return run_hook_listener_with_analysis(&path, rules, &mut *out, pipeline.as_ref());
    }

    if stdin_mode {
        let stdin = io::stdin();
        return xbits::stream_to_writer(stdin.lock(), &mut out);
    }

    xbits::run_listener(&socket, &mut out, once)
}
