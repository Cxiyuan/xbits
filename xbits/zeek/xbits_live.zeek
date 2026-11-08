# CI-only live harness: xbits listens on the workspace-mounted socket and
# Suricata 8.0.8 connects to it with eve-log.filetype=unix_stream.

@load ./xbits_correlate

redef Xbits::command = "/work/xbits/target/release/xbits --socket /work/test/xbits_run/eve.sock";
redef LogAscii::use_json = T;
redef exit_only_after_terminate = T;
