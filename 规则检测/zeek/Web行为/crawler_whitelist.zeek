##! 搜索引擎爬虫白名单（由 convert_probe_zeek.py 生成）。
##! UA 命中爬虫特征但源 IP 不在爬虫网段 → 伪造爬虫告警。
##! 与自研脚本一致使用 Log 框架，便于 -b 模式加载与 xbits 消费。

module XbitsCrawler;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        orig_h: addr &log;
        host: string &log;
        uri: string &log;
        ua: string &log;
        msg: string &log;
    };

    global spider_hosts: set[addr] = {
        65.52.108.142,
        74.125.75.3,
        74.125.64.81,
        74.125.44.82,
        74.125.158.86,
        74.125.156.82,
        65.52.108.146,
        72.30.142.223,
        67.195.37.168,
        67.195.37.154,
        202.160.180.198,
        202.160.180.176,
        202.160.180.118,
        202.160.179.16,
        202.160.179.127,
        202.160.178.70,
        110.75.176.30,
        110.75.176.29,
        110.75.176.28,
        110.75.176.27,
        110.75.176.26,
        110.75.176.25,
        110.75.173.176,
        61.135.217.27,
        61.135.249.9,
        61.135.249.89,
        61.135.249.78,
        61.135.249.75,
        61.135.249.62,
        61.135.249.6,
        61.135.249.59,
        61.135.249.37,
        61.135.249.32,
        61.135.249.249,
        61.135.249.239,
        61.135.249.236,
        61.135.249.232,
        61.135.249.231,
        61.135.249.229,
        61.135.249.220,
        61.135.249.216,
        61.135.249.213,
        61.135.249.210,
        61.135.249.191,
        61.135.249.187,
        61.135.249.175,
        61.135.249.171,
        61.135.249.146,
        61.135.249.144,
        61.135.249.143,
        61.135.220.9,
        61.135.220.3,
        220.181.108.100,
        180.149.130.1,
        180.76.5.66,
    };

    global spider_nets: set[subnet] = {
        180.149.130.0/24,
        220.181.51.0/24,
        123.125.71.0/24,
        67.221.235.0/24,
        66.249.68.0/24,
        66.249.67.0/24,
        203.208.60.0/24,
        66.249.72.0/24,
    };

    global spider_ua_patterns: set[string] = {
        "Googlebot",
        "Baiduspider",
        "Yahoo! Slurp",
        "bingbot",
        "360Spider",
        "Sosospider",
        "Sogou Web Spider",
        "Sogou Push Spider",
        "sogou spider",
        "YodaoBot",
        "msnbot",
    };

    global is_spider_ua: function(ua: string): bool;
    global is_spider_addr: function(a: addr): bool;
}

function is_spider_ua(ua: string): bool
    {
    if ( ua == "" )
        return F;
    for ( p in spider_ua_patterns )
        if ( p in ua )
            return T;
    return F;
    }

function is_spider_addr(a: addr): bool
    {
    if ( a in spider_hosts )
        return T;
    for ( n in spider_nets )
        if ( a in n )
            return T;
    return F;
    }

event zeek_init()
    {
    Log::create_stream(XbitsCrawler::LOG, [$columns=XbitsCrawler::Info,
                                          $path="crawler_impersonation"]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! c$http?$user_agent )
        return;
    local ua = c$http$user_agent;
    if ( is_spider_ua(ua) && ! is_spider_addr(c$id$orig_h) )
        Log::write(XbitsCrawler::LOG, [$ts=network_time(),
                                       $orig_h=c$id$orig_h,
                                       $host=c$http$host,
                                       $uri=unescaped_URI,
                                       $ua=ua,
                                       $msg=fmt("crawler UA from non-crawler host: %s", c$id$orig_h)]);
    }
