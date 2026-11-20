use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use xbits::analysis::{AnalysisConfig, AnalysisPipeline};
use xbits::hook::run_hook_listener_full;
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
    let mut triage_command: Option<String> = None;
    let mut triage_timeout_ms: u64 = 30000;
    let mut file_spool_dir: Option<PathBuf> = None;
    let mut triage_categories: Vec<String> = vec![
        "binary".into(),
        "script".into(),
        "document".into(),
        "archive".into(),
    ];
    let mut triage_cache_ttl_sec: u64 = 3600;
    let mut threat_intel_dir: Option<PathBuf> = None;
    let mut allowlist_dir: Option<PathBuf> = None;
    let mut success_rules: Option<PathBuf> = None;

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
            "--triage-cmd" => {
                triage_command = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--triage-cmd value missing")
                })?);
            }
            "--triage-timeout-ms" => {
                triage_timeout_ms = parse_u64(args.next(), "--triage-timeout-ms")?;
            }
            "--file-spool-dir" => {
                file_spool_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--file-spool-dir value missing")
                })?));
            }
            "--triage-categories" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--triage-categories value missing")
                })?;
                triage_categories = value
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect();
            }
            "--triage-cache-ttl-sec" => {
                triage_cache_ttl_sec = parse_u64(args.next(), "--triage-cache-ttl-sec")?;
            }
            "--threat-intel-dir" => {
                threat_intel_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--threat-intel-dir value missing")
                })?));
            }
            "--allowlist-dir" => {
                allowlist_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--allowlist-dir value missing")
                })?));
            }
            "--success-rules" => {
                success_rules = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--success-rules value missing")
                })?));
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
                       --suppression-ttl-sec N --fp-confidence N --max-payload N --pending-context-ms N\n\
                       静态 triage: --triage-cmd CMD --triage-timeout-ms N --file-spool-dir DIR\n\
                                    --triage-categories binary,script,document,archive --triage-cache-ttl-sec N\n\
                       情报查询(需显式指定，未指定即不启用):\n\
                         --threat-intel-dir DIR   # 读 ip.txt/domain.txt/md5.txt/sha1.txt/sha256.txt（威胁方向，参与评分）\n\
                         --allowlist-dir DIR      # 读 domain.txt/ip.txt/public_dns.txt（白名单，参与降级）\n\
                       请求→响应关联(V-14 方案①,未指定即关闭):\n\
                         --success-rules FILE     # success_rules.json（请求→响应配对，correlated 字段 + 计数）"
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
    // success_rules 关联表（V-14 方案①）：配置了就必须成功加载——读取/解析失败直接
    // 退出，绝不静默降级成"无关联继续跑"（否则"交 xbits"的关联承诺又一次变成空话）。
    let success = match success_rules {
        Some(path) => Some(xbits::analysis::load_success_rules(&path)?),
        None => None,
    };
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
            || match_buffers.is_some()
            || triage_command.is_some()
            || file_spool_dir.is_some();
        // 启用了分析但一个文档 sink 都没有 → 启动即失败：
        // 否则审计/ES 文档只能被丢弃（"报个日志就算完"不接受）。
        if analysis_enabled && analysis_file.is_none() && es_url.is_none() && es_command.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "analysis is enabled but no document sink is configured: \
                 pass --analysis-file and/or --es-url/--es-command \
                 (otherwise every analysis document would be dropped)",
            ));
        }
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
                triage_command,
                triage_timeout: Duration::from_millis(triage_timeout_ms.max(1)),
                file_spool_dir,
                triage_categories,
                triage_cache_ttl: Duration::from_secs(triage_cache_ttl_sec.max(1)),
                success_rules_path: success_rules,
            };
            Some(AnalysisPipeline::start(config)?)
        } else {
            None
        };
        let intel = std::sync::Arc::new(xbits::intel::IntelService::load(
            threat_intel_dir.as_ref(),
            allowlist_dir.as_ref(),
        ));
        return run_hook_listener_full(
            &path,
            rules,
            &mut *out,
            pipeline.as_ref(),
            Some(intel),
            success,
        );
    }

    if stdin_mode {
        let stdin = io::stdin();
        return xbits::stream_to_writer(stdin.lock(), &mut out);
    }

    xbits::run_listener(&socket, &mut out, once)
}
