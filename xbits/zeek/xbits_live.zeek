# CI-only live harness: xbits listens on the workspace-mounted socket and
# Suricata 8.0.8 connects to it with eve-log.filetype=unix_stream.

@load ./xbits_correlate

redef Xbits::command = "/work/xbits/target/release/xbits --socket /work/测试用例/xbits_run/eve.sock --once";
redef Xbits::input_mode = Input::MANUAL;
redef LogAscii::use_json = T;
redef exit_only_after_terminate = T;

event Input::end_of_data(name: string, source: string)
{
    if ( name == "xbits-suricata" )
        terminate();
}

event InputRaw::process_finished(name: string, source: string,
                                 exit_code: count, signal_exit: bool)
{
    terminate();
}
