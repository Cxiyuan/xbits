##! xbits app-id：基于 Zeek 的应用识别引擎库（骨架）
##! 目标：SNI/Host/UA/JA3/DNS 等信号 -> 应用/类别/置信度，输出 app_identity.log。
##! 状态：脚手架；协议事件接入（ssl_client_hello/http_request/dns_request）待按 Zeek 9.0.1 核验后添加。

module XbitsAppId;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time   &log;
        uid:         string &log &optional;
        orig_h:      addr   &log;
        orig_p:      port   &log &optional;
        resp_h:      addr   &log;
        resp_p:      port   &log &optional;
        app:         string &log &default="-";
        category:    string &log &default="-";
        client_app:  string &log &default="-";
        server_app:  string &log &default="-";
        confidence:  double &log &default=0.0;
        method:      string &log &default="-";
        evidence:    string &log &default="-";
    };

    ## 域名后缀 -> 应用（如 "facebook.com" -> "Facebook"）
    global sni_suffix_to_app: table[string] of string &default="" &redef;

    ## UA 子串 -> 客户端应用（如 "dropbox" -> "Dropbox"）
    global ua_substr_to_app: table[string] of string &default="" &redef;

    ## 应用 -> 类别（social/cloud/remote/p2p/vpn/...）
    global app_category: table[string] of string &default="unknown" &redef;

    ## 由外部脚本/协议事件调用：为某连接记录一次识别结果
    global note_app: function(c: connection, app: string, category: string, evidence: string, confidence: double);
    global lookup_suffix: function(name: string): string;
    global lookup_ua: function(ua: string): string;
}

# 每连接暂存（key = c$uid）
global per_conn: table[string] of Info;

function lookup_suffix(name: string): string
    {
    if ( name == "" )
        return "";

    local n = to_lower(name);
    local parts = split_string(n, /\./);
    local m = |parts|;
    local k = 0;

    while ( k < m )
        {
        local suf = "";
        local j = k;
        while ( j < m )
            {
            if ( j > k )
                suf = suf + ".";
            suf = suf + parts[j];
            j += 1;
            }
        if ( suf in sni_suffix_to_app )
            return sni_suffix_to_app[suf];
        k += 1;
        }
    return "";
    }

function lookup_ua(ua: string): string
    {
    if ( ua == "" )
        return "";

    local u = to_lower(ua);
    for ( k in ua_substr_to_app )
        {
        if ( strstr(u, k) >= 0 )
            return ua_substr_to_app[k];
        }
    return "";
    }

function note_app(c: connection, app: string, category: string, evidence: string, confidence: double)
    {
    local key = c$uid;
    if ( key !in per_conn )
        per_conn[key] = Info($ts=network_time(), $uid=key,
                             $orig_h=c$id$orig_h, $orig_p=c$id$orig_p,
                             $resp_h=c$id$resp_h, $resp_p=c$id$resp_p);
    local r = per_conn[key];
    r$app = app;
    r$category = category;
    r$evidence = evidence;
    r$confidence = confidence;
    per_conn[key] = r;
    }

event zeek_init()
    {
    Log::create_stream(XbitsAppId::LOG, [$columns=XbitsAppId::Info, $path="app_identity"]);
    }

event connection_state_remove(c: connection)
    {
    local key = c$uid;
    if ( key in per_conn )
        {
        local r = per_conn[key];
        r$ts = network_time();
        Log::write(XbitsAppId::LOG, r);
        delete per_conn[key];
        }
    }

# ---------------------------------------------------------------------------
# TODO（待 Zeek 9.0.1 核验字段后接入）：
#   event ssl_client_hello(c: connection, info: SSL::ClientHello) { ... info$sni ... }
#   event http_request(c: connection, info: http_request)        { ... info$host/ info$user_agent ... }
#   event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) { ... }
#   命中后调用 XbitsAppId::note_app(...)。
# ---------------------------------------------------------------------------
