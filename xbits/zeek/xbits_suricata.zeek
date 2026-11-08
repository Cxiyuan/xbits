# ============================================================================
# xbits · Suricata EVE -> Zeek event bridge (Zeek 9.0.1)
# ----------------------------------------------------------------------------
# This script starts a Rust helper (`xbits`) as a child process through Zeek's
# raw Input reader. The helper connects to Suricata EVE `unix_stream` and
# prints normalized alert JSONL; each line raises Xbits::suricata_alert.
#
# No EVE log file and no Community-ID log join are used. The event is pushed
# into the Zeek event loop as soon as Suricata emits the alert.
# ============================================================================

@load base/init-bare
@load base/frameworks/input
@load base/frameworks/input/readers/raw

module Xbits;

export {
    type Alert: record {
        timestamp: string &optional;
        signature_id: count &optional;
        signature: string &optional;
        community_id: string &optional;
        src: string &optional;
        dst: string &optional;
        sport: count &optional;
        dport: count &optional;
        proto: string &optional;
        flow_id: string &optional;
    };

    ## Raised synchronously from the Input event with a parsed Suricata alert.
    global suricata_alert: event(rec: Alert);

    ## Raw JSONL line event used by the Input framework.
    global xbits_raw_line: event(description: Input::EventDescription,
                                  tpe: Input::Event, line: string);

    ## Override in site/local policy or in tests.
    global command: string = "xbits --socket /var/run/suricata/eve.sock" &redef;
    global input_mode: Input::Mode = Input::STREAM &redef;

    ## Set by zeek_init after Input::add_event succeeds.
    global input_ready: bool = F;
}

type RawLine: record {
    line: string;
};

event xbits_raw_line(description: Input::EventDescription, tpe: Input::Event,
                     line: string)
{
    local parsed = from_json(line, Xbits::Alert);
    if ( ! parsed$valid )
        return;

    event Xbits::suricata_alert(parsed$v as Xbits::Alert);
}

event zeek_init() &priority=10
{
    local ok = Input::add_event([
        $source=fmt("%s |", Xbits::command),
        $name="xbits-suricata",
        $reader=Input::READER_RAW,
        $mode=Xbits::input_mode,
        $fields=RawLine,
        $ev=Xbits::xbits_raw_line,
        $want_record=F
    ]);
    Xbits::input_ready = ok;
    if ( ! ok )
        print "xbits: Input::add_event failed";
}
