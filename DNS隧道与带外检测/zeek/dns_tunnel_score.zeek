@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns

module DNS_Tunnel_Correlation;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        community_id: string &log &optional;
        scenario: string &log;
        reason: string &log;
        src: addr &log;
        dst: addr &log;
        score: count &log;
        related_sids: string &log;
    };

    type Stats: record {
        total: count &default=0;
        unique: set[string];
        nx: count &default=0;
        logged: bool &default=F;
    };

    global stats: table[addr] of Stats &create_expire=5min;
}

event zeek_init()
{
    Log::create_stream(DNS_Tunnel_Correlation::LOG, [$columns=Info, $path="dns_correlation"]);
}

function emit(c: connection, reason: string, score: count, sids: string)
{
    Log::write(DNS_Tunnel_Correlation::LOG, [
        $ts=network_time(),
        $uid=c$uid,
        $community_id=community_id_v1(c$id),
        $scenario="dns-tunnel",
        $reason=reason,
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $score=score,
        $related_sids=sids
    ]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( query == "" || /^_/ in query ) {
        return;
    }

    local s = c$id$orig_h;
    if ( s !in stats ) {
        stats[s] = Stats();
    }
    local st = stats[s];
    st$total += 1;
    add st$unique[query];

    if ( ! st$logged && st$total >= 50 ) {
        local reason = "query_burst";
        if ( qtype == 16 ) {
            reason = "txt_burst";
        }
        emit(c, reason, st$total, "9109103,9109201,9109202");
        st$logged = T;
    }
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
    if ( is_orig || ! msg?$rcode || msg$rcode != 3 ) {
        return;
    }

    local s = c$id$orig_h;
    if ( s !in stats ) {
        stats[s] = Stats();
    }
    local st = stats[s];
    st$nx += 1;
    if ( ! st$logged && st$nx >= 30 ) {
        emit(c, "nxdomain_burst", st$nx, "9109001,9109002,9109201");
        st$logged = T;
    }
}
