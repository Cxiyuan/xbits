@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http

module Backdoor_Correlation;

# Zeek 只做行为分析：这里只统计同一源 IP 的重复 URI/请求频率，
# 不再做 cmd=、shell.php 等内容签名匹配（那属于 Suricata）。
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

    type C2Stats: record {
        requests: count &default=0;
        uris: set[string];
        logged: bool &default=F;
    };

    global c2stats: table[addr] of C2Stats &create_expire=5min;
}

event zeek_init()
{
    Log::create_stream(Backdoor_Correlation::LOG, [$columns=Info, $path="backdoor_correlation"]);
}

function emit(c: connection, reason: string, score: count, sids: string)
{
    Log::write(Backdoor_Correlation::LOG, [
        $ts=network_time(),
        $uid=c$uid,
        $community_id=community_id_v1(c$id),
        $scenario="backdoor-c2",
        $reason=reason,
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $score=score,
        $related_sids=sids
    ]);
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local s = c$id$orig_h;
    if ( s !in c2stats ) {
        c2stats[s] = C2Stats();
    }
    local st = c2stats[s];
    st$requests += 1;
    add st$uris[unescaped_URI];
    if ( ! st$logged && st$requests >= 10 && |st$uris| <= 3 ) {
        emit(c, "c2_repeated_http", st$requests, "9110002,9110005,9110007");
        st$logged = T;
    }
}