##! DNS tunnel / OOB request-side detection for Zeek 9.0.1.
##!
##! This is the Zeek counterpart of the Suricata request-side Lua heuristics.
##! It intentionally stays request-side; response TXT/NULL payload analysis is
##! covered by the Suricata rules.

@load base/frameworks/notice
@load base/protocols/dns

module DNS_Tunnel;

export {
    redef enum Notice::Type += {
        OOB_Callback,
        Encoded_Qname,
        Compact_Label_Qname,
        Long_Label_Qname,
    };

    global oob_domains: set[string] = {
        "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun",
        "oast.me", "oastify.com", "interact.sh", "ceye.io", "dnslog.cn",
        "dnslog.top", "burpcollaborator.net", "requestrepo.com", "xss.ht",
        "canarytokens.com",
    };
}

function is_hex_label(s: string): bool
    {
    return /^[0-9a-f]+$/ == s;
    }

function is_rfc4122_uuid(s: string): bool
    {
    if ( |s| != 36 )
        return F;
    if ( ! (/^[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$/ == s) )
        return F;

    local version = sub_bytes(s, 15, 1);
    local variant = sub_bytes(s, 20, 1);
    if ( version != "1" && version != "2" && version != "3" &&
         version != "4" && version != "5" )
        return F;
    if ( variant != "8" && variant != "9" && variant != "a" && variant != "b" )
        return F;
    return T;
    }

function is_service_label(s: string): bool
    {
    return |s| > 0 && sub_bytes(s, 1, 1) == "_";
    }

function matches_suffix(q: string, domain: string): bool
    {
    local qparts = split_string(q, /\./);
    local dparts = split_string(domain, /\./);
    if ( |qparts| < |dparts| )
        return F;
    local offset = |qparts| - |dparts|;
    for ( i in dparts )
        {
        if ( qparts[offset + i] != dparts[i] )
            return F;
        }
    return T;
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    # A=1, CNAME=5, TXT=16, AAAA=28
    if ( qtype != 1 && qtype != 5 && qtype != 16 && qtype != 28 )
        return;

    local q = to_lower(query);
    if ( |q| > 0 && sub_bytes(q, |q|, 1) == "." )
        q = sub_bytes(q, 1, |q| - 1);
    if ( |q| < 6 )
        return;

    local parts = split_string(q, /\./);
    if ( |parts| < 2 )
        return;

    for ( i in parts )
        {
        if ( is_service_label(parts[i]) )
            return;
        }

    # OOB callback: require a token label before the platform suffix.
    local max_token = 0;
    for ( i in parts )
        {
        if ( i < |parts| - 2 && |parts[i]| > max_token )
            max_token = |parts[i]|;
        }
    if ( max_token >= 6 )
        {
        for ( domain in oob_domains )
            {
            if ( matches_suffix(q, domain) )
                {
                NOTICE([$note=OOB_Callback,
                        $msg=fmt("OOB callback domain: %s", query),
                        $sub=query,
                        $conn=c]);
                return;
                }
            }
        }

    local first = parts[0];

    # 32 hex or RFC 4122 UUID in the first label.
    if ( (|first| == 32 && is_hex_label(first)) ||
         (|first| == 36 && is_rfc4122_uuid(first)) )
        {
        NOTICE([$note=Encoded_Qname,
                $msg=fmt("Encoded first label: %s", query),
                $sub=query,
                $conn=c]);
        return;
        }

    # Long single label (60-63), alphanumeric only.
    for ( i in parts )
        {
        if ( |parts[i]| >= 60 && /^[0-9a-zA-Z]+$/ == parts[i] )
            {
            NOTICE([$note=Long_Label_Qname,
                    $msg=fmt("Long label qname: %s", query),
                    $sub=query,
                    $conn=c]);
            return;
            }
        }

    # Compact single-character hex labels: require a long stream.
    local singles = 0;
    for ( i in parts )
        {
        if ( |parts[i]| == 1 && is_hex_label(parts[i]) )
            singles = singles + 1;
        else
            break;
        }
    if ( singles >= 12 )
        {
        NOTICE([$note=Compact_Label_Qname,
                $msg=fmt("Compact single-character labels: %s", query),
                $sub=query,
                $conn=c]);
        }
    }
