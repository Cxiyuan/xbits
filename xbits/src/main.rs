use std::env;
use std::io;

fn main() -> io::Result<()> {
    let mut socket = String::from("/var/run/suricata/eve.sock");
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
            "--once" => once = true,
            "--stdin" => stdin_mode = true,
            "--help" | "-h" => {
                println!(
                    "xbits: Suricata EVE -> normalized Zeek event stream\n\
                     usage: xbits [--socket PATH] [--once] [--stdin]"
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

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if stdin_mode {
        let stdin = io::stdin();
        return xbits::stream_to_writer(stdin.lock(), &mut out);
    }
    xbits::run_listener(&socket, &mut out, once)
}
