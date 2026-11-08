# ============================================================================
# xbits · event-driven Suricata -> Zeek correlation (Zeek 9.0.1)
# ----------------------------------------------------------------------------
# xbits_suricata.zeek raises Xbits::suricata_alert directly from the Rust
# bridge. This script consumes that event, updates per-host risk and joins it
# with Zeek's live connection/HTTP state by Community ID / 5-tuple. There is
# no log-file join.
# ============================================================================

@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load ./xbits_suricata

module Xbits;

export {
    redef enum Log::ID += { CORRELATION_LOG };

    type CorrelationInfo: record {
        ts: time &log;
        uid: string &log &optional;
        community_id: string &log &optional;
        signature_id: count &log;
        signature: string &log;
        src: addr &log;
        dst: addr &log;
        score: count &log;
        reason: string &log;
        scenario: string &log;
        related_sids: vector of count &log;
    };

    global host_score: table[addr] of count &default=0 &create_expire=10min;
    global conn_uid_by_cid: table[string] of string &create_expire=10min;
    global last_signature: table[addr] of count &default=0 &create_expire=10min;
}

event zeek_init()
{
    Log::create_stream(Xbits::CORRELATION_LOG,
                       [$columns=CorrelationInfo, $path="xbits_correlation"]);
}

function log_event(rec: Xbits::Alert, reason: string, score: count)
{
    if ( ! rec?$src || ! rec?$dst || ! rec?$signature_id
         || rec$src == "" || rec$dst == "" )
        return;

    local sid = rec$signature_id;
    local src = to_addr(rec$src);
    local dst = to_addr(rec$dst);
    if ( src == 0.0.0.0 || dst == 0.0.0.0 )
        return;

    local cid = "";
    if ( rec?$community_id )
        cid = rec$community_id;
    local sig = "";
    if ( rec?$signature )
        sig = rec$signature;
    local uid = "";
    if ( cid in conn_uid_by_cid )
        uid = conn_uid_by_cid[cid];

    Log::write(Xbits::CORRELATION_LOG, [
        $ts=network_time(),
        $uid=uid,
        $community_id=cid,
        $signature_id=sid,
        $signature=sig,
        $src=src,
        $dst=dst,
        $score=score,
        $reason=reason,
        $scenario="xbits-cross-engine",
        $related_sids=vector(sid)
    ]);
    Log::flush(Xbits::CORRELATION_LOG);
}

event new_connection(c: connection)
{
    conn_uid_by_cid[community_id_v1(c$id)] = c$uid;
}

event Xbits::suricata_alert(rec: Xbits::Alert)
{
    local src = to_addr(rec$src);
    if ( src == 0.0.0.0 )
        return;

    host_score[src] += 10;
    last_signature[src] = rec$signature_id;

    # Immediate correlation result, not a post-hoc log join.
    log_event(rec, "suricata_alert", host_score[src]);

    if ( host_score[src] >= 20 )
        log_event(rec, "host_risk_high", host_score[src]);
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if ( c$id$orig_h !in last_signature )
        return;

    # A prior Suricata alert has already raised this host's risk in memory.
    local rec = Xbits::Alert(
        $signature_id=last_signature[c$id$orig_h],
        $signature="suricata-alert-followed-by-http",
        $community_id=community_id_v1(c$id),
        $src=fmt("%s", c$id$orig_h),
        $dst=fmt("%s", c$id$resp_h),
        $sport=port_to_count(c$id$orig_p),
        $dport=port_to_count(c$id$resp_p),
        $proto="TCP",
        $flow_id=""
    );
    log_event(rec, "alert_then_http", host_score[c$id$orig_h]);
}
