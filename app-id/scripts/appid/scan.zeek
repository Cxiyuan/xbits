##! scan.zeek —— 扫描工具识别（v2：结构性行为 + 签名，弱化"纯阈值"触发）
##!
##! 目标：高精度（近零误报）识别扫描器；**不再有"单一计数阈值即命中"的路径**。
##! 依据：app-id/docs/{nmap-dpi, custom-scanner-library-fingerprints, script-scan-precise-detection, qa-scan-tools}.md
##! 状态：**待 Zeek 9.0.1 编译/回放验证**（事件签名/字段按 source/xbits-zeek 9.0.1 源码核对）。
##!
##! 识别层级：
##!  1) 具体工具：.sig 命中（HTTP/1 明文） + 脚本层 UA 匹配（HTTP/2/分片亦可）→ 直判具体工具
##!  2) 行为：目录爆破/端口扫描必须是"多条件结构性证据"，不再单靠一个计数阈值
##!  3) 弱线索（脚本库/version.bind/nmap TierB）：只作佐证，绝不单独判定

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

	# ---- 结构性行为阈值/比例（&redef，需按基线校准）----
	global dir_uri_threshold:  count  = 50   &redef;  # 单(源,host)不同 URI 数
	global dir_404_ratio:      double = 0.70 &redef;  # 404+403 / requests
	global dir_uniq_ratio:     double = 0.80 &redef;  # 不同URI / requests（枚举特征）
	global dir_static_max:     double = 0.10 &redef;  # 静态资源占比上限
	global port_threshold:     count  = 20   &redef;  # 不同目的端口数
	global port_nodata_ratio:  double = 0.70 &redef;  # 无载荷连接占比（SYN/探测特征）
	global script_req_threshold: count = 50  &redef;  # 脚本库弱线索：请求数
	global whitelist: set[addr] &redef;               # 白名单
}

# 每源状态
type S: record {
	first:      time;
	requests:   count  &default=0;
	dports:     set[port];
	conns:      count  &default=0;
	nodata:     count  &default=0;
	tools:      set[string];
	nmap_a:     bool   &default=F;
	nmap_b:     count  &default=0;
	dns_bind:   bool   &default=F;
	dir_brute:  bool   &default=F;
	dir_uris:   count  &default=0;
	dir_hits:   count  &default=0;
	port_scan:  bool   &default=F;
	lib:        string &default="";
	nonbrowser: bool   &default=F;
	reported:   bool   &default=F;
	reported_tool: string &default="";
};

# 每(源,host) 目录爆破状态
type HostS: record {
	requests: count &default=0;
	uris:     set[string];
	n403:     count &default=0;
	n404:     count &default=0;
	static:   count &default=0;
};

global st:    table[addr] of S &create_expire=300sec;
global hosts: table[addr, string] of HostS &create_expire=300sec;

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

# 脚本层 UA -> 具体工具（HTTP/2 经 HPACK 解码后 c$http$user_agent 仍可得；补 .sig 在 h2/分片下的漏报）
function ua_to_tool(ua: string): string
	{
	local u = to_lower(ua);
	if ( /fuzz faster u fool/ in u ) return "ffuf";
	if ( /^gobuster\// in u ) return "gobuster";
	if ( /^feroxbuster\// in u ) return "feroxbuster";
	if ( /dirbuster/ in u ) return "dirbuster";
	if ( /^sqlmap\// in u ) return "sqlmap";
	if ( /nuclei/ in u ) return "nuclei";
	if ( /nikto\// in u ) return "nikto";
	if ( /wpscan/ in u ) return "wpscan";
	if ( /acunetix/ in u ) return "acunetix";
	if ( /nessus/ in u ) return "nessus";
	if ( /openvas/ in u ) return "openvas";
	if ( /whatweb\// in u ) return "whatweb";
	if ( /^httpx\// in u ) return "httpx";
	if ( /^arjun\// in u ) return "arjun";
	if ( /wafw00f/ in u ) return "wafw00f";
	if ( /commix/ in u ) return "commix";
	if ( /xsstrike/ in u ) return "xsstrike";
	if ( /shodan\// in u ) return "shodan";
	if ( /censysinspect\// in u ) return "censys";
	if ( /expanse\// in u ) return "expanse";
	if ( /l9explore/ in u ) return "l9explore";
	if ( /^zgrab\// in u ) return "zgrab";
	if ( /^masscan\// in u ) return "masscan";
	if ( /zmeu/ in u ) return "zmeu";
	if ( /morfeus/ in u ) return "morfeus";
	if ( /nmap scripting engine/ in u ) return "nmap";
	return "";
	}

function ensure(src: addr)
	{
	if ( src !in st )
		st[src] = S($first=network_time(), $dports=set(), $tools=set());
	}

function ensure_host(src: addr, host: string)
	{
	if ( [src, host] !in hosts )
		hosts[src, host] = HostS($uris=set());
	}

function judge(src: addr)
	{
	if ( src in whitelist )
		return;
	if ( src !in st )
		return;
	local s = st[src];

	local evid: string = "";
	local tool: string = "";

	# 具体工具：签名（.sig）/ 脚本层 UA
	if ( |s$tools| > 0 )
		{
		for ( t in s$tools ) { if ( tool == "" ) tool = t; }
		evid = evid + "|tool_ua=" + tool;
		}
	if ( s$nmap_a )
		{
		tool = "nmap";
		evid = evid + "|nmap_probe(TierA)";
		}

	# 结构性行为（非纯阈值）：目录爆破 / 端口扫描 已在各自处按多条件置位
	local structural = F;
	if ( s$dir_brute ) { structural = T; evid = evid + "|dir_brute"; }
	if ( s$port_scan ) { structural = T; evid = evid + "|port_scan"; }

	# 弱线索（只作佐证，不单独判定）
	if ( s$nmap_b >= 2 && tool == "" )
		evid = evid + fmt("|nmap_tierB(x%d)", s$nmap_b);
	if ( s$lib != "" && s$lib != "other" && s$lib != "no-ua" && s$nonbrowser && s$requests >= script_req_threshold )
		evid = evid + "|script_lib=" + s$lib;
	if ( s$dns_bind )
		evid = evid + "|dns_version_bind";

	local verdict = F;
	local conf: double = 0.0;
	if ( tool != "" )
		{ verdict = T; conf = 0.90; }          # 具体工具字面 = 高精确
	else if ( structural )
		{ verdict = T; tool = "unknown"; conf = 0.75; }  # 结构性行为（多条件）才判 scanner

	if ( ! verdict )
		return;                                  # 只有弱线索 → 不判

	# 去重/可升级：已报过则仅在"出现新的具体工具"时再报（如先 unknown，后识别出 gobuster）
	if ( s$reported && (tool == "" || tool == s$reported_tool) )
		return;

	local toolstr = tool;
	if ( toolstr == "" ) toolstr = "-";
	local libstr = s$lib;
	if ( libstr == "" ) libstr = "-";

	local rec = Info($ts=network_time(), $src=src, $verdict="scanner",
	                 $tool=toolstr, $category="scanner", $confidence=conf,
	                 $requests=s$requests, $distinct_uri=s$dir_uris,
	                 $hit_404_403=s$dir_hits, $distinct_dport=|s$dports|,
	                 $lib=libstr, $evidence=evid);
	Log::write(XbitsScan::LOG, rec);

	s$reported = T;
	s$reported_tool = tool;
	st[src] = s;
	}

# 目录爆破：按 (源,host) 的多结构条件判定（不同URI数 + 404/403比 + 唯一比 + 静态占比）
function judge_host(src: addr, host: string)
	{
	if ( src in whitelist )
		return;
	if ( host == "-" )          # 无 Host 的 HTTP/1.0 请求无法按目标主机聚合，避免跨主机误判
		return;
	if ( [src, host] !in hosts )
		return;
	local h = hosts[src, host];
	if ( h$requests < dir_uri_threshold )
		return;
	local uris = |h$uris|;
	local hits = h$n403 + h$n404;
	local ratio = hits * 1.0 / h$requests;
	local uniq = uris * 1.0 / h$requests;
	local staticr = h$static * 1.0 / h$requests;
	if ( (ratio >= dir_404_ratio) && (uniq >= dir_uniq_ratio) && (staticr <= dir_static_max) )
		{
		ensure(src);
		local s = st[src];
		s$dir_brute = T;
		s$dir_uris = uris;
		s$dir_hits = hits;
		st[src] = s;
		judge(src);
		}
	}

event zeek_init()
	{
	Log::create_stream(XbitsScan::LOG, [$columns=Info, $path="scan_report"]);
	}

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
		{ s$nmap_a = T; }
	else if ( /^nmap_tierB_/ in msg )
		{ s$nmap_b += 1; }
	st[src] = s;
	judge(src);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	local host = "-";
	if ( c?$http && c$http?$host )
		host = c$http$host;
	ensure(src);
	local s = st[src];
	s$requests += 1;
	add s$dports[c$id$resp_p];
	if ( c?$http && c$http?$user_agent )
		{
		local ua = c$http$user_agent;
		local lib = classify_lib(ua);
		s$lib = lib;
		if ( lib != "other" )
			s$nonbrowser = T;
		local ut = ua_to_tool(ua);
		if ( ut != "" )
			add s$tools[ut];
		}
	st[src] = s;

	if ( host != "-" )
		{
		ensure_host(src, host);
		local h = hosts[src, host];
		h$requests += 1;
		add h$uris[original_URI];
		if ( /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)(\?|$)/ in to_lower(original_URI) )
			h$static += 1;
		hosts[src, host] = h;
		}

	judge(src);
	judge_host(src, host);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	local host = "-";
	if ( c?$http && c$http?$host )
		host = c$http$host;
	if ( [src, host] in hosts )
		{
		local h = hosts[src, host];
		if ( code == 403 ) h$n403 += 1;
		if ( code == 404 ) h$n404 += 1;
		hosts[src, host] = h;
		}
	judge_host(src, host);
	}

# 端口扫描：统计所有连接的目的端口 + "无载荷连接"占比（结构性，非单阈值）
event connection_state_remove(c: connection)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	ensure(src);
	local s = st[src];
	add s$dports[c$id$resp_p];
	s$conns += 1;
	if ( c$orig$size == 0 )
		s$nodata += 1;
	st[src] = s;

	if ( |s$dports| >= port_threshold && s$conns > 0 )
		{
		local nr = s$nodata * 1.0 / s$conns;
		if ( nr >= port_nodata_ratio )
			{
			local s2 = st[src];
			s2$port_scan = T;
			st[src] = s2;
			judge(src);
			}
		}
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
