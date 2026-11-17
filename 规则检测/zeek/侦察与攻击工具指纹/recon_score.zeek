@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http

module Recon_Correlation;

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
        nf: count &default=0;
        fb: count &default=0;
        logged: bool &default=F;
    };

    global stats: table[addr] of Stats &create_expire=5min;
}

event zeek_init()
{
    Log::create_stream(Recon_Correlation::LOG, [$columns=Info, $path="recon_correlation"]);
}

function emit(c: connection, reason: string, score: count)
{
    Log::write(Recon_Correlation::LOG, [
        $ts=network_time(),
        $uid=c$uid,
        $community_id=community_id_v1(c$id),
        $scenario="recon",
        $reason=reason,
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $score=score,
        $related_sids="9101028,9101103,9101104,9101109"
    ]);
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local s = c$id$orig_h;
    if ( s !in stats ) {
        stats[s] = Stats();
    }
    local st = stats[s];
    st$total += 1;
    add st$unique[unescaped_URI];
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    local s = c$id$orig_h;
    if ( s !in stats ) {
        stats[s] = Stats();
    }
    local st = stats[s];
    if ( code == 404 ) {
        st$nf += 1;
    } else if ( code == 403 ) {
        st$fb += 1;
    }

    # Suricata 的 threshold 与 Zeek 的计数窗口可能相差一个流；
    # 在 50/51 两个相邻连接上各输出一次，保证社区 ID 可关联。
    if ( st$total >= 50 && st$total <= 60 && (st$nf + st$fb) >= 40 ) {
        emit(c, "scan_404_burst", st$nf + st$fb);
        st$logged = T;
    } else if ( st$total >= 50 && st$total <= 60 && |st$unique| >= 20 ) {
        emit(c, "unique_uri_burst", |st$unique|);
        st$logged = T;
    }
}
