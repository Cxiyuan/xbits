# CI-only Zeek test harness: run the Rust xbits bridge in stdin mode and
# verify that a normalized Suricata alert raises Xbits::suricata_alert and
# produces the correlation log.

@load ./xbits_correlate

redef Xbits::command = "cat /work/xbits/testdata/alert.jsonl | /work/xbits/target/release/xbits --stdin";
redef LogAscii::use_json = T;
redef exit_only_after_terminate = T;

event zeek_init() &priority=-10
{
    schedule 10sec { terminate(); }
}

event Input::end_of_data(name: string, source: string)
{
    print fmt("xbits-test: end_of_data name=%s source=%s", name, source);
    if ( name == "xbits-suricata" )
        terminate();
}

event InputRaw::process_finished(name: string, source: string,
                                 exit_code: count, signal_exit: bool)
{
    print fmt("xbits-test: process_finished name=%s code=%d signal=%s",
              name, exit_code, signal_exit);
}

event Xbits::xbits_raw_line(description: Input::EventDescription,
                            tpe: Input::Event, line: string)
{
    print fmt("xbits-test: raw_line=%s", line);
}
