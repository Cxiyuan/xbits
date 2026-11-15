##! scan.zeek —— 扫描工具识别统一检测（消费 扫描工具/*.sig 签名 + 行为聚合）
##!
##! 目标：把"已知工具 UA 签名"与"脚本扫描行为"融合，高精度（近零误报）识别扫描器。
##! 依据：app-id/docs/{nmap-dpi, custom-scanner-library-fingerprints, script-scan-precise-detection}.md
##! 状态：**待 Zeek 9.0.1 编译/回放验证**（事件签名/字段已按 source/xbits-zeek 9.0.1 源码核对）。
##!
##! 判定原则：具体工具 UA（Tier A）可直接判；否则必须"行为证据"才能判 scanner（避免把正常脚本客户端误判）。

module XbitsScan;

@load ./main
@load ../../扫描工具

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time   &log;
		src:            addr   &log;
		verdict:        string &log &default="scanner";
		tool:           string &log &default="-";
		category:       string &log &default="scanner";
		confidence:     double &log &default=0.0;
		requests:       count  &log &default=0;
		distinct_uri:   count  &log &default=0;
		hit_404_403:    count  &log &default=0;
		distinct_dport: count  &log &default=0;
		lib:            string &log &default="-";
		evidence:       string &log &default="";
	};

	# ---- 可调阈值（&redef，按真实基线校准）----
	global dir_uri_threshold:    count  = 50   &redef;  # 目录爆破：不同 URI 数
	global dir_404_ratio:        double = 0.70 &redef;  # 目录爆破：404/403 占比
	global port_threshold:       count  = 20   &redef;  # 端口扫描：不同目的端口数
	global script_req_threshold: count  = 50   &redef;  # 脚本客户端：请求数
	global whitelist: set[addr] &redef;                 # 白名单（监控/业务/压测等）
}

type S: record {
	first:      time;
	requests:   count  &default=0;
	uris:       set[string];
	n403:       count  &default=0;
	n404:       count  &default=0;
	dports:     set[port];
	tools:      set[string];   # 命中的具体工具（来自 scanner_ua_* / scanner_hdr_*）
	nmap_a:     bool   &default=F;
	nmap_b:     count  &default=0;
	dns_bind:   bool   &default=F;
	lib:        string &default="";
	nonbrowser: bool   &default=F;
	reported:   bool   &default=F;
};

global st: table[addr] of S &create_expire=300sec;

function classify_lib(ua: string): string
	{
	local u = to_lower(ua);
	if ( /^python-requests\// in u ) return "python-requests";
	if ( /^python-httpx\//    in u ) return "python-httpx";
	if ( /^python-urllib3\//  in u ) return "python-urllib3";
	if ( /^python-urllib\//   in u ) return "python-urllib";
	if ( /aiohttp\//          in u ) return "aiohttp";
	if ( /^go-http-client\//  in u ) return "go-http-client";
	if ( /^curl\//            in u ) return "curl";
	if ( /^wget\//            in u ) return "wget";
	if ( /^java\//            in u ) return "java";
	if ( /^okhttp\//          in u ) return "okhttp";
	if ( /^libwww-perl\//     in u ) return "libwww-perl";
	if ( /^lwp::simple\//     in u ) return "lwp-simple";
	if ( /^reqwest\//         in u ) return "reqwest";
	return "other";
	}

function ensure(src: addr)
	{
	if ( src !in st )
		st[src] = S($first=network_time(), $uris=set(), $dports=set(), $tools=set());
	}

function judge(src: addr)
	{
	if ( src in whitelist )
		return;
	if ( src !in st )
		return;
	local s = st[src];
	if ( s$reported )
		return;

	local evid: string = "";
	local score: count = 0;
	local tool: string = "";

	# 具体工具（签名 UA/头）——高精确
	if ( |s$tools| > 0 )
		{
		for ( t in s$tools ) { if ( tool == "" ) tool = t; }
		score += 6;
		evid = evid + "|tool_ua=" + tool;
		}
	if ( s$nmap_a )
		{
		tool = "nmap";
		score += 6;
		evid = evid + "|nmap_probe(TierA)";
		}

	local uris = |s$uris|;
	local hits = s$n403 + s$n404;
	local dports = |s$dports|;
	local behavior = F;

	if ( uris >= dir_uri_threshold && s$requests > 0 )
		{
		local ratio = hits * 1.0 / s$requests;
		if ( ratio >= dir_404_ratio )
			{
			score += 3; behavior = T;
			evid = evid + fmt("|dir_brute uris=%d hit404_403=%d req=%d", uris, hits, s$requests);
			}
		}
	if ( dports >= port_threshold )
		{
		score += 3; behavior = T;
		evid = evid + fmt("|port_scan dports=%d", dports);
		}
	if ( s$nmap_b >= 2 && tool == "" )
		{
		tool = "nmap"; score += 4;
		evid = evid + fmt("|nmap_probe(TierB x%d)", s$nmap_b);
		}
	if ( s$lib != "" && s$lib != "other" && s$lib != "no-ua" && s$nonbrowser && s$requests >= script_req_threshold )
		{
		score += 1;
		evid = evid + "|script_lib=" + s$lib;
		}
	if ( s$dns_bind )
		{
		score += 1;
		evid = evid + "|dns_version_bind";
		}

	local verdict = F;
	local conf: double = 0.0;
	if ( tool != "" && score >= 5 )
		{ verdict = T; conf = 0.90; }
	else if ( behavior && score >= 3 )
		{ verdict = T; tool = "unknown"; conf = 0.75; }

	if ( ! verdict )
		return;

	local toolstr = tool;
	if ( toolstr == "" )
		toolstr = "-";
	local libstr = s$lib;
	if ( libstr == "" )
		libstr = "-";

	local rec = Info($ts=network_time(), $src=src, $verdict="scanner",
	                 $tool=toolstr, $category="scanner", $confidence=conf,
	                 $requests=s$requests, $distinct_uri=uris,
	                 $hit_404_403=hits, $distinct_dport=dports,
	                 $lib=libstr, $evidence=evid);
	Log::write(XbitsScan::LOG, rec);

	s$reported = T;
	st[src] = s;
	}

event zeek_init()
	{
	Log::create_stream(XbitsScan::LOG, [$columns=Info, $path="scan_report"]);
	}

# 签名命中：msg 即 .sig 里的 event "..." 字符串
event signature_match(state: signature_state, msg: string, data: string)
	{
	local src = state$conn$id$orig_h;
	if ( ! state$is_orig )
		src = state$conn$id$resp_h;
	if ( src in whitelist )
		return;
	ensure(src);
	local s = st[src];

	if ( (/^scanner_ua_/ in msg) || (/^scanner_hdr_/ in msg) )
		{
		local parts = split_string(msg, /_/);
		if ( |parts| >= 3 )
			add s$tools[parts[2]];
		}
	else if ( /^nmap_tierA_/ in msg )
		{
		s$nmap_a = T;
		}
	else if ( /^nmap_tierB_/ in msg )
		{
		s$nmap_b += 1;
		}

	st[src] = s;
	judge(src);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	ensure(src);
	local s = st[src];
	s$requests += 1;
	add s$uris[original_URI];
	add s$dports[c$id$resp_p];
	if ( c?$http && c$http?$user_agent )
		{
		local lib = classify_lib(c$http$user_agent);
		s$lib = lib;
		if ( lib != "other" )
			s$nonbrowser = T;
		}
	st[src] = s;
	judge(src);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	if ( src !in st )
		return;
	local s = st[src];
	if ( code == 403 ) s$n403 += 1;
	if ( code == 404 ) s$n404 += 1;
	st[src] = s;
	judge(src);
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	if ( query == "version.bind" || query == "hostname.bind" )
		{
		ensure(src);
		local s = st[src];
		s$dns_bind = T;
		st[src] = s;
		judge(src);
		}
	}
