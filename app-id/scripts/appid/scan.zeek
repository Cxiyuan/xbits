##! scan.zeek —— 扫描工具识别（v3：B+ 模型；结构性行为确认 + 阈值下调）
##!
##! 目标：高精度（近零误报）识别扫描器；sig/UA 不再"单凭一次"随意触发，但确定性字面可自证。
##! 依据：app-id/docs/{nmap-dpi, custom-scanner-library-fingerprints, script-scan-precise-detection, qa-scan-tools}.md
##! 状态：**待 Zeek 9.0.1 编译/回放验证**（事件签名/字段按 source/xbits-zeek 9.0.1 源码核对）。
##!
##! 识别层级（模型 B+）：
##!  1) 确定性/品牌字面（.sig / ua_to_tool）→ 可"字面自证"（单发也可判）
##!  2) nmap 探针序列（≥2 个 TierB 探针）→ 判 nmap
##!  3) 结构性行为（目录爆破/端口扫描的多条件）→ 判 scanner（有候选则标工具）
##!  4) 弱线索（通用库 UA / version.bind）→ 仅旁证，绝不单独判定

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

	# ---- 结构性行为阈值/比例（&redef，已下调以提升召回；靠多条件+白名单控误报）----
	global dir_uri_threshold:  count  = 20   &redef;  # 单(源,host)不同 URI 数
	global dir_404_ratio:      double = 0.60 &redef;  # 404+403 / requests
	global dir_uniq_ratio:     double = 0.70 &redef;  # 不同URI / requests（枚举特征）
	global dir_static_max:     double = 0.20 &redef;  # 静态资源占比上限
	global port_threshold:     count  = 10   &redef;  # 不同目的端口数
	global port_nodata_ratio:  double = 0.60 &redef;  # 无载荷连接占比（SYN/探测特征）
	global script_req_threshold: count = 20  &redef;  # 脚本库弱线索：请求数
	global whitelist: set[addr] &redef;               # 白名单
	global shadow_mode: bool = F &redef;              # 影子模式：照常记录，evidence 标 shadow
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

# 每连接暂存（请求行 URI + 已解析 Host），供 http_header 阶段回填（http_request 时 c$http$host/UA 尚未填充）
type CH: record {
	src:  addr;
	uri:  string;
	host: string &default="-";
};
global ch: table[string] of CH &create_expire=300sec;

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
	if ( /(^|[^a-z0-9])dirbuster([^a-z0-9]|$)/ in u ) return "dirbuster";
	if ( /^sqlmap\// in u ) return "sqlmap";
	if ( /(^|[^a-z0-9])nuclei([^a-z0-9]|$)/ in u ) return "nuclei";
	if ( /nikto\// in u ) return "nikto";
	if ( /(^|[^a-z0-9])wpscan([^a-z0-9]|$)/ in u ) return "wpscan";
	if ( /(^|[^a-z0-9])acunetix([^a-z0-9]|$)/ in u ) return "acunetix";
	if ( /(^|[^a-z0-9])nessus([^a-z0-9]|$)/ in u ) return "nessus";
	if ( /(^|[^a-z0-9])openvas([^a-z0-9]|$)/ in u ) return "openvas";
	if ( /whatweb\// in u ) return "whatweb";
	if ( /^httpx\/[0-9]/ in u ) return "httpx";
	if ( /^arjun\// in u ) return "arjun";
	if ( /(^|[^a-z0-9])wafw00f([^a-z0-9]|$)/ in u ) return "wafw00f";
	if ( /(^|[^a-z0-9])commix([^a-z0-9]|$)/ in u ) return "commix";
	if ( /(^|[^a-z0-9])xsstrike([^a-z0-9]|$)/ in u ) return "xsstrike";
	if ( /shodan\// in u ) return "shodan";
	if ( /censysinspect\// in u ) return "censys";
	if ( /expanse\// in u ) return "expanse";
	if ( /(^|[^a-z0-9])l9explore([^a-z0-9]|$)/ in u ) return "l9explore";
	if ( /^zgrab\// in u ) return "zgrab";
	if ( /^masscan\// in u ) return "masscan";
	if ( /(^|[^a-z0-9])zmeu([^a-z0-9]|$)/ in u ) return "zmeu";
	if ( /(^|[^a-z0-9])morfeus([^a-z0-9]|$)/ in u ) return "morfeus";
	if ( /(^|[^a-z0-9])w3af([^a-z0-9]|$)/ in u ) return "w3af";
	if ( /(^|[^a-z0-9])wapiti([^a-z0-9]|$)/ in u ) return "wapiti";
	if ( /(^|[^a-z0-9])arachni([^a-z0-9]|$)/ in u ) return "arachni";
	if ( /(^|[^a-z0-9])skipfish([^a-z0-9]|$)/ in u ) return "skipfish";
	if ( /^wfuzz\// in u ) return "wfuzz";
	if ( /(^|[^a-z0-9])netsparker([^a-z0-9]|$)/ in u ) return "netsparker";
	if ( /(^|[^a-z0-9])appscan([^a-z0-9]|$)/ in u ) return "appscan";
	if ( /(^|[^a-z0-9])webinspect([^a-z0-9]|$)/ in u ) return "webinspect";
	if ( /(^|[^a-z0-9])qualys([^a-z0-9]|$)/ in u ) return "qualys";
	if ( /(^|[^a-z0-9])nexpose([^a-z0-9]|$)/ in u ) return "nexpose";
	if ( /(^|[^a-z0-9])appspider([^a-z0-9]|$)/ in u ) return "appspider";
	if ( /(^|[^a-z0-9])dalfox([^a-z0-9]|$)/ in u ) return "dalfox";
	if ( /(^|[^a-z0-9])kiterunner([^a-z0-9]|$)/ in u ) return "kiterunner";
	if ( /(^|[^a-z0-9])joomscan([^a-z0-9]|$)/ in u ) return "joomscan";
	if ( /(^|[^a-z0-9])droopescan([^a-z0-9]|$)/ in u ) return "droopescan";
	if ( /(^|[^a-z0-9])cmseek([^a-z0-9]|$)/ in u ) return "cmseek";
	if ( /(^|[^a-z0-9])testssl([^a-z0-9]|$)/ in u ) return "testssl";
	if ( /(^|[^a-z0-9])sslscan([^a-z0-9]|$)/ in u ) return "sslscan";
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
	local strong = F;

	# ① 确定性/品牌字面（.sig / ua_to_tool）——B+ 允许"字面自证"
	if ( |s$tools| > 0 )
		{
		for ( t in s$tools ) { if ( tool == "" ) tool = t; }
		strong = T;
		evid = evid + "|strong_tool=" + tool;
		}
	if ( s$nmap_a )
		{ tool = "nmap"; strong = T; evid = evid + "|strong:nmap_probe(TierA)"; }

	# ② 结构性行为确认：目录爆破 / 端口扫描（多条件）
	local structural = F;
	if ( s$dir_brute ) { structural = T; evid = evid + "|dir_brute"; }
	if ( s$port_scan ) { structural = T; evid = evid + "|port_scan"; }

	# ③ 探针序列确认（nmap 版本探测：≥2 个 TierB 探针）
	local probe_seq = ( s$nmap_b >= 2 );

	# ④ 弱线索（仅旁证）
	local weak = 0;
	if ( s$nmap_b >= 1 && ! probe_seq ) { weak += 1; evid = evid + fmt("|nmap_tierB(x%d)", s$nmap_b); }
	if ( s$lib != "" && s$lib != "other" && s$lib != "no-ua" && s$nonbrowser && s$requests >= script_req_threshold )
		{ weak += 1; evid = evid + "|script_lib=" + s$lib; }
	if ( s$dns_bind ) { weak += 1; evid = evid + "|dns_version_bind"; }

	# ---- 模型B+ 判定：strong(字面) / 探针序列 / 结构性行为 均可确认；弱线索不单独判 ----
	local verdict = F;
	local conf: double = 0.0;
	if ( strong )
		{ verdict = T; conf = 0.90; evid = evid + "|confirmed_by:strong_literal"; }
	else if ( probe_seq )
		{ verdict = T; tool = "nmap"; conf = 0.80; evid = evid + "|confirmed_by:probe_sequence"; }
	else if ( structural )
		{
		verdict = T;
		if ( tool == "" ) tool = "unknown";
		if ( tool == "unknown" ) conf = 0.75; else conf = 0.90;
		evid = evid + "|confirmed_by:structural";
		}

	if ( ! verdict )
		return;                                  # 无 strong/序列/结构性确认 → 不判（弱线索仅旁证）

	if ( shadow_mode )
		evid = evid + "|shadow";

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
	ensure(src);
	local s = st[src];
	s$requests += 1;
	add s$dports[c$id$resp_p];
	st[src] = s;
	ch[c$uid] = CH($src=src, $uri=original_URI);
	judge(src);
	}

# 请求头阶段：Host/User-Agent 在此才由基础 HTTP 分析器填入（http_request 时尚未填充）
event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! is_orig )
		return;
	if ( c$uid !in ch )
		return;
	local src = ch[c$uid]$src;
	if ( src in whitelist )
		return;
	local hname = to_lower(name);
	if ( hname == "host" )
		{
		local cur = ch[c$uid];
		cur$host = value;
		ch[c$uid] = cur;
		ensure_host(src, value);
		local h = hosts[src, value];
		h$requests += 1;
		add h$uris[ch[c$uid]$uri];
		if ( /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)(\?|$)/ in to_lower(ch[c$uid]$uri) )
			h$static += 1;
		hosts[src, value] = h;
		judge_host(src, value);
		}
	else if ( hname == "user-agent" )
		{
		ensure(src);
		local s = st[src];
		local lib = classify_lib(value);
		s$lib = lib;
		if ( lib != "other" )
			s$nonbrowser = T;
		local ut = ua_to_tool(value);
		if ( ut != "" )
			add s$tools[ut];
		st[src] = s;
		judge(src);
		}
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local src = c$id$orig_h;
	if ( src in whitelist )
		return;
	local host = "-";
	if ( c$uid in ch )
		host = ch[c$uid]$host;
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
	if ( c$uid in ch )
		delete ch[c$uid];
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
