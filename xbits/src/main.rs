use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufWriter;

use xbits::hook::run_hook_listener;
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

fn main() -> io::Result<()> {
    let mut socket = String::from("/var/run/suricata/eve.sock");
    let mut hook_socket: Option<String> = None;
    let mut rules_file: Option<String> = None;
    let mut alert_file: Option<String> = None;
    let mut once = false;
    let mut stdin_mode = false;

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
            "--once" => once = true,
            "--stdin" => stdin_mode = true,
            "--help" | "-h" => {
                println!(
                    "xbits: Suricata EVE / thin-hook -> Zeek event stream + central engine\n\
                     usage:\n\
                       xbits [--socket PATH] [--once]        # Suricata EVE unix_stream bridge\n\
                       xbits --hook-socket PATH [--rules R] [--alert-file F]  # hook + central engine\n\
                       xbits --stdin                         # offline EVE stdin"
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
        return run_hook_listener(&path, rules, &mut *out);
    }

    if stdin_mode {
        let stdin = io::stdin();
        return xbits::stream_to_writer(stdin.lock(), &mut out);
    }

    xbits::run_listener(&socket, &mut out, once)
}
