module Backdoor_Correlation;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        community_id: string &log &optional;
        scenario: string &log;
        reason: string &log;
        status: count &log &default=0;
        src: addr &log;
        dst: addr &log;
        score: count &log;
        related_sids: string &log;
    };

    type Pending: record {
        reason: string;
        sids: string;
    };

    type C2Stats: record {
        count: count &default=0;
        uris: set[string];
        logged: bool &default=F;
    };

    global pending: table[string] of Pending &create_expire=5min;
    global bodies: table[string] of string &create_expire=5min;
    global c2stats: table[addr] of C2Stats &create_expire=5min;
}

event zeek_init()
{
    Log::create_stream(Backdoor_Correlation::LOG, [$columns=Info, $path="backdoor_correlation"]);
}

function mark(c: connection, reason: string, sids: string)
{
    if ( c$uid !in pending ) {
        pending[c$uid] = Pending($reason=reason, $sids=sids);
    }
}

function emit(c: connection, reason: string, status: count, score: count, sids: string)
{
    Log::write(Backdoor_Correlation::LOG, [
        $ts=network_time(),
        $uid=c$uid,
        $community_id=community_id_v1(c$id),
        $scenario="backdoor-c2",
        $reason=reason,
        $status=status,
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $score=score,
        $related_sids=sids
    ]);
}

function inspect(c: connection, text: string)
{
    local t = to_lower(text);
    if ( /cmd=/ in t || /z0=/ in t || /z1=/ in t || /pass=/ in t
        || /exec=/ in t || /shell\.php/ in t ) {
        mark(c, "webshell-command", "9104002,9104003");
    }
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    bodies[c$uid] = "";
    inspect(c, unescaped_URI);

    local s = c$id$orig_h;
    if ( s !in c2stats ) {
        c2stats[s] = C2Stats();
    }
    local st = c2stats[s];
    st$count += 1;
    add st$uris[unescaped_URI];
    if ( ! st$logged && st$count >= 10 && |st$uris| <= 3 ) {
        emit(c, "c2_repeated_http", 0, st$count, "9110002,9110005,9110007");
        st$logged = T;
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig ) {
        inspect(c, value);
    }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if ( ! is_orig ) {
        return;
    }
    local b = "";
    if ( c$uid in bodies ) {
        b = bodies[c$uid];
    }
    if ( |b| < 16384 ) {
        b += data;
        bodies[c$uid] = b;
    }
    inspect(c, b);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if ( c$uid !in pending ) {
        return;
    }
    local p = pending[c$uid];
    emit(c, p$reason, code, 1, p$sids);
    delete pending[c$uid];
    if ( c$uid in bodies ) {
        delete bodies[c$uid];
    }
}
