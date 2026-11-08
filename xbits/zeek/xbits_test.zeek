# CI-only Zeek test harness: run the Rust xbits bridge in stdin mode and
# verify that a normalized Suricata alert raises Xbits::suricata_alert and
# produces the correlation log.

@load ./xbits_correlate

redef Xbits::command = "cat /work/xbits/testdata/alert.jsonl | /work/xbits/target/release/xbits --stdin";
redef LogAscii::use_json = T;
redef exit_only_after_terminate = T;

event Input::end_of_data(name: string, source: string)
{
    if ( name == "xbits-suricata" )
        terminate();
}
