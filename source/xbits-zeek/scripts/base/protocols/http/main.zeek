##! Implements base functionality for HTTP analysis.  The logging model is
##! to log request/response pairs and all relevant metadata together in
##! a single record.

@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels
@load base/protocols/conn/removal-hooks

module HTTP;

export {
	redef enum Log::ID += { LOG };

	## Well-known ports for HTTP.
	const ports = {
		80/tcp, 81/tcp, 631/tcp, 1080/tcp, 3128/tcp,
		8000/tcp, 8080/tcp, 8888/tcp,
	} &redef;

	global log_policy: Log::PolicyHook;

	## Indicate a type of attack or compromise in the record to be logged.
	type Tags: enum {
		## Placeholder.
		EMPTY
	};

	## This setting changes if passwords used in Basic-Auth are captured or
	## not.
	option default_capture_password = F;

	## xbits: 每方向每实体 Body 片段最大采集字节数（安全相关类型；超出置截断标记）
	const xbits_max_body_bytes = 4096 &redef;

	## The record type which contains the fields of the HTTP log.
	type Info: record {
		## Timestamp for when the request happened.
		ts:                      time      &log;
		## Unique ID for the connection.
		uid:                     string    &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                      conn_id   &log;
		## Represents the pipelined depth into the connection of this
		## request/response transaction.
		trans_depth:             count     &log;
		## Verb used in the HTTP request (GET, POST, HEAD, etc.).
		method:                  string    &log &optional;
		## Value of the HOST header.
		host:                    string    &log &optional;
		## URI used in the request.
		uri:                     string    &log &optional;
		## Value of the "referer" header.  The comment is deliberately
		## misspelled like the standard declares, but the name used here
		## is "referrer", spelled correctly.
		referrer:                string    &log &optional;
		## Value of the version portion of the reply. If you require
		## message-level detail, consider the :zeek:see:`http_request` and
		## :zeek:see:`http_reply` events, which report each message's
		## version string.
		version:		string	   &log &optional;
		## Value of the User-Agent header from the client.
		user_agent:              string    &log &optional;
		## Value of the Origin header from the client.
		origin:                  string    &log &optional;
		## Actual uncompressed content size of the data transferred from
		## the client.
		request_body_len:        count     &log &default=0;
		## Actual uncompressed content size of the data transferred from
		## the server.
		response_body_len:       count     &log &default=0;
		## Status code returned by the server.
		status_code:             count     &log &optional;
		## Status message returned by the server.
		status_msg:              string    &log &optional;
		## Last seen 1xx informational reply code returned by the server.
		info_code:               count     &log &optional;
		## Last seen 1xx informational reply message returned by the server.
		info_msg:                string    &log &optional;
		## A set of indicators of various attributes discovered and
		## related to a particular request/response pair.
		tags:                    set[Tags] &log;

		## Username if basic-auth is performed for the request.
		username:                string    &log &optional;
		## Password if basic-auth is performed for the request.
		password:                string    &log &optional;

		## Determines if the password will be captured for this request.
		capture_password:        bool      &default=default_capture_password;

		## All of the headers that may indicate if the request was proxied.
		proxied:                 set[string] &log &optional;

		## Indicates if this request can assume 206 partial content in
		## response.
		range_request:           bool      &default=F;

		## ===== xbits: Web 安全分析扩展字段（全部落 http.log） =====
		## 完整请求/响应头（JSON：头名[大写]->值；重复头以 ", " 合并）
		request_headers:  string &log &optional;
		response_headers: string &log &optional;
		## 请求 Cookie 原值 / 响应所有 Set-Cookie 值
		cookie:     string &log &optional;
		set_cookie: vector of string &log &optional;
		## 完整认证信息
		authorization:             string &log &optional;
		authorization_scheme:      string &log &optional;
		authorization_credentials: string &log &optional;   # Basic 自动解码为 user:pass
		proxy_authorization:       string &log &optional;
		## Query 参数 / 表单字段（JSON：名->值）
		query_params: string &log &optional;
		form_fields:  string &log &optional;
		## 请求/响应 Content-Type（小写 type/subtype）
		req_content_type:  string &log &optional;
		resp_content_type: string &log &optional;
		## 请求/响应安全相关 Body 片段（限长）+ 截断标记
		req_body_excerpt:    string &log &optional;
		resp_body_excerpt:   string &log &optional;
		req_body_truncated:  bool &log &default=F;
		resp_body_truncated: bool &log &default=F;
		## JSON/XML 请求正文原文（限长）
		json_body: string &log &optional;
		xml_body:  string &log &optional;
	};

	## Structure to maintain state for an HTTP connection with multiple
	## requests and responses.
	type State: record {
		## Pending requests.
		pending:          table[count] of Info;
		## Current request in the pending queue.
		current_request:  count                &default=0;
		## Current response in the pending queue.
		current_response: count                &default=0;
		## Track the current deepest transaction.
		## This is meant to cope with missing requests
		## and responses.
		trans_depth:      count                &default=0;
	};

	## A list of HTTP headers typically used to indicate proxied requests.
	option proxy_headers: set[string] = {
		"FORWARDED",
		"X-FORWARDED-FOR",
		"X-FORWARDED-FROM",
		"CLIENT-IP",
		"VIA",
		"XROXY-CONNECTION",
		"PROXY-CONNECTION",
	};

	## A list of HTTP methods. Other methods will generate a weird. Note
	## that the HTTP analyzer will only accept methods consisting solely
	## of letters ``[A-Za-z]``.
	option http_methods: set[string] = {
		"GET", "POST", "HEAD", "OPTIONS",
		"PUT", "DELETE", "TRACE", "CONNECT",
		# HTTP methods for distributed authoring:
		"PROPFIND", "PROPPATCH", "MKCOL",
		"COPY", "MOVE", "LOCK", "UNLOCK",
		"POLL", "REPORT", "SUBSCRIBE", "BMOVE",
		"SEARCH",
		# Proposed standard: https://www.rfc-editor.org/info/rfc10008
		"QUERY",
	};

	## Event that can be handled to access the HTTP record as it is sent on
	## to the logging framework.
	global log_http: event(rec: Info);

	## HTTP finalization hook.  Remaining HTTP info may get logged when it's called.
	global finalize_http: Conn::RemovalHook;

	## The maximum number of bytes that a single string field can contain when
	## logging. If a string reaches this limit, the log output for the field will be
	## truncated. Setting this to zero disables the limiting. HTTP has no maximum
	## length for various fields such as the URI, so this is set to zero by default.
	##
	## .. zeek:see:: Log::default_max_field_string_bytes
	const default_max_field_string_bytes = 0 &redef;
}

# Add the http state tracking fields to the connection record.
redef record connection += {
	http:        Info  &optional;
	http_state:  State &optional;
};


# Initialize the HTTP logging stream and ports.
event zeek_init() &priority=5
	{
	Log::create_stream(HTTP::LOG, Log::Stream($columns=Info, $ev=log_http, $path="http", $policy=log_policy,
	                                          $max_field_string_bytes=HTTP::default_max_field_string_bytes));
	Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, ports);
	}

function code_in_range(c: count, min: count, max: count) : bool
	{
	return c >= min && c <= max;
	}

function new_http_session(c: connection): Info
	{
	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;
	tmp$trans_depth = ++c$http_state$trans_depth;
	return tmp;
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}

	# These deal with new requests and responses.
	if ( is_orig )
		{
		if ( c$http_state$current_request !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_request] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_request];
		}
	else
		{
		if ( c$http_state$current_response !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_response] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_response];
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}

	# Request/response tracking exists to account for HTTP pipelining.
	# It fails if more responses have been seen than requests. If that
	# happens, just fast-forward current_request such that the next
	# response matches the in-flight request.
	if ( c$http_state$current_request < c$http_state$current_response )
		{
		Reporter::conn_weird("HTTP_response_before_request", c);
		c$http_state$current_request = c$http_state$current_response;
		}

	# Too many requests are pending for which we have not yet observed a
	# reply. This might be due to excessive HTTP pipelining, one-sided
	# traffic capture, or the responder side of the HTTP analyzer having
	# been disabled. In any case, we simply log out all pending requests
	# to make room for a new one. Any matching of pipelined requests and
	# responses is most likely totally off anyhow.
	if ( max_pending_requests > 0 && |c$http_state$pending| > max_pending_requests )
		{
		Reporter::limit_reached_weird("HTTP_excessive_pipelining", c, |c$http_state$pending|,
		                              max_pending_requests, "HTTP");

		if ( c$http_state$current_response == 0 )
			++c$http_state$current_response;

		while ( c$http_state$current_response < c$http_state$current_request )
			{
			local cr = c$http_state$current_response;
			if ( cr in c$http_state$pending )
				{
				Log::write(HTTP::LOG, c$http_state$pending[cr]);
				delete c$http_state$pending[cr];
				}
			else
				{
				# The above should have been true...
				# Reporter::error(fmt("Expected pending request at %d", cr));
				}

			++c$http_state$current_response;
			}
		}

	++c$http_state$current_request;
	set_state(c, T);

	c$http$method = method;
	c$http$uri = unescaped_URI;

	if ( method !in http_methods )
		Reporter::conn_weird("unknown_HTTP_method", c, method);
	}

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}

	# If the last response was an informational 1xx, we're still expecting
	# the real response to the request, so don't create a new Info record yet.
	if ( c$http_state$current_response !in c$http_state$pending ||
	     (c$http_state$pending[c$http_state$current_response]?$status_code &&
	       ! code_in_range(c$http_state$pending[c$http_state$current_response]$status_code, 100, 199)) )
		{
		++c$http_state$current_response;
		}
	set_state(c, F);

	c$http$status_code = code;
	c$http$status_msg = reason;
	c$http$version = version;

	if ( code_in_range(code, 100, 199) )
		{
		c$http$info_code = code;
		c$http$info_msg = reason;
		}

	if ( c$http?$method && c$http$method == "CONNECT" && code == 200 )
		{
		# Copy this conn_id and set the orig_p to zero because in the case of CONNECT
		# proxies there will be potentially many source ports since a new proxy connection
		# is established for each proxied connection.  We treat this as a singular
		# "tunnel".
		local tid = copy(c$id);
		tid$orig_p = 0/tcp;
		Tunnel::register(Tunnel::EncapsulatingConn($cid=tid, $tunnel_type=Tunnel::HTTP));
		}
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	set_state(c, is_orig);

	if ( is_orig ) # client headers
		{
		if ( name == "REFERER" )
			c$http$referrer = value;

		else if ( name == "HOST" )
			# Per #1844, we record the original host header, including any port
			# specification if present.
			c$http$host = value;

		else if ( name == "RANGE" )
			c$http$range_request = T;

		else if ( name == "ORIGIN" )
			c$http$origin = value;

		else if ( name == "USER-AGENT" )
			c$http$user_agent = value;

		else if ( name in proxy_headers )
				{
				if ( ! c$http?$proxied )
					c$http$proxied = set();
				add c$http$proxied[fmt("%s -> %s", name, value)];
				}

		else if ( name == "AUTHORIZATION" || name == "PROXY-AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64_conn(c$id, sub(value, /[bB][aA][sS][iI][cC][[:blank:]]+/, ""));
				local up = split_string1(userpass, /:/);
				if ( |up| == 2 )
					{
					c$http$username = up[0];
					if ( c$http$capture_password )
						c$http$password = up[1];
					}
				else
					{
					c$http$username = fmt("<problem-decoding> (%s)", value);
					if ( c$http$capture_password )
						c$http$password = userpass;
					}
				}
			}
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
	{
	set_state(c, is_orig);

	if ( is_orig )
		c$http$request_body_len = stat$body_length;
	else
		c$http$response_body_len = stat$body_length;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
	{
	# The reply body is done so we're ready to log.
	if ( ! is_orig )
		{
		# If the response was an informational 1xx, we're still expecting
		# the real response later, so we'll continue using the same record.
		if ( ! (c$http?$status_code && code_in_range(c$http$status_code, 100, 199)) )
			{
			Log::write(HTTP::LOG, c$http);
			delete c$http_state$pending[c$http_state$current_response];
			}
		}
	}

hook finalize_http(c: connection)
	{
	# Flush all pending but incomplete request/response pairs.
	if ( c?$http_state )
		{
		for ( r, info in c$http_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 ) next;
			Log::write(HTTP::LOG, info);
			}
		}
	}

# ============================================================================
# xbits: HTTP 扩展字段采集（完整头/Cookie/认证/Query/表单/JSON/XML/安全 Body 片段）
# 直接内置于 HTTP 解析脚本；全部字段写 http.log（HTTP::Info），不新建日志/脚本。
# ============================================================================
type XbitsBState: record {
	method:      string &default="";
	req_ct:      string &default="";
	resp_ct:     string &default="";
	req_len:     count  &default=0;
	resp_len:    count  &default=0;
	req_buf:     string &default="";
	resp_buf:    string &default="";
	req_trunc:   bool   &default=F;
	resp_trunc:  bool   &default=F;
};

global xbits_bs: table[string] of XbitsBState &create_expire=300sec;
# multipart 各 part 的字段名（来自 Content-Disposition 头）
global xbits_form_names: table[string] of set[string] &create_expire=300sec;

function xbits_hdrs_to_json(hlist: mime_header_list): string
	{
	local m: table[string] of string = table();
	for ( i in hlist )
		{
		local nm = hlist[i]$name;
		local vv = hlist[i]$value;
		if ( nm in m )
			m[nm] = m[nm] + ", " + vv;
		else
			m[nm] = vv;
		}
	return to_json(m);
	}

function xbits_kv_to_json(q: string, sep: pattern): string
	{
	local m: table[string] of string = table();
	if ( q == "" )
		return to_json(m);
	local pairs = split_string(q, sep);
	for ( idx in pairs )
		{
		local p = pairs[idx];
		local kv = split_string1(p, /=/);
		local k = unescape_URI(kv[0]);
		local v = "";
		if ( |kv| > 1 )
			v = unescape_URI(kv[1]);
		if ( k == "" )
			next;
		if ( k in m )
			m[k] = m[k] + "," + v;
		else
			m[k] = v;
		}
	return to_json(m);
	}

function xbits_capture_type(ct: string, method: string, is_orig: bool): bool
	{
	local t = to_lower(ct);
	if ( t == "" )
		return is_orig && (method == "POST" || method == "PUT" || method == "PATCH");
	if ( /application\/x-www-form-urlencoded/ in t ) return T;
	if ( /multipart\/form-data/ in t ) return T;
	if ( /json/ in t ) return T;
	if ( /xml/ in t ) return T;
	if ( /graphql/ in t ) return T;
	if ( /text\/plain/ in t ) return T;
	if ( is_orig ) return F;
	if ( /text\/html/ in t ) return T;
	if ( /javascript/ in t ) return T;
	return F;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=0
	{
	if ( c$uid !in xbits_bs )
		xbits_bs[c$uid] = XbitsBState();
	local st = xbits_bs[c$uid];
	st$method = method;
	xbits_bs[c$uid] = st;

	if ( c?$http )
		{
		local parts = split_string1(original_URI, /\?/);
		if ( |parts| > 1 )
			c$http$query_params = xbits_kv_to_json(parts[1], /&/);
		else
			c$http$query_params = "{}";
		}
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=0
	{
	if ( ! c?$http )
		return;
	if ( c$uid !in xbits_bs )
		xbits_bs[c$uid] = XbitsBState();
	local st = xbits_bs[c$uid];

	if ( is_orig )
		c$http$request_headers = xbits_hdrs_to_json(hlist);
	else
		c$http$response_headers = xbits_hdrs_to_json(hlist);

	local setc: vector of string = vector();
	for ( i in hlist )
		{
		local nm = hlist[i]$name;
		local vv = hlist[i]$value;
		if ( nm == "CONTENT-TYPE" )
			{
			if ( is_orig )
				st$req_ct = to_lower(vv);
			else
				st$resp_ct = to_lower(vv);
			}
		if ( is_orig && nm == "COOKIE" )
			c$http$cookie = vv;
		else if ( is_orig && nm == "AUTHORIZATION" )
			{
			c$http$authorization = vv;
			local sp = split_string_n(vv, /[[:blank:]]+/, F, 2);
			if ( |sp| > 0 )
				{
				c$http$authorization_scheme = to_lower(sp[0]);
				if ( |sp| > 1 )
					{
					local cred = sp[1];
					if ( to_lower(sp[0]) == "basic" )
						cred = decode_base64_conn(c$id, cred);
					c$http$authorization_credentials = cred;
					}
				}
			}
		else if ( is_orig && nm == "PROXY-AUTHORIZATION" )
			c$http$proxy_authorization = vv;
		else if ( ! is_orig && nm == "SET-COOKIE" )
			setc += vv;
		}
	xbits_bs[c$uid] = st;
	if ( ! is_orig && |setc| > 0 )
		c$http$set_cookie = setc;
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=0
	{
	if ( is_orig && name == "CONTENT-DISPOSITION" && /[[:blank:]]name=\"/ in value )
		{
		local parts = split_string(value, /\"/);
		if ( |parts| > 1 && parts[1] != "" )
			{
			if ( c$uid !in xbits_form_names )
				xbits_form_names[c$uid] = set();
			add xbits_form_names[c$uid][parts[1]];
			}
		}
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) &priority=0
	{
	if ( c$uid !in xbits_bs )
		xbits_bs[c$uid] = XbitsBState();
	local st = xbits_bs[c$uid];
	local ct = to_lower(ty + "/" + subty);
	if ( is_orig )
		st$req_ct = ct;
	else
		st$resp_ct = ct;
	xbits_bs[c$uid] = st;

	if ( c?$http )
		{
		if ( is_orig )
			c$http$req_content_type = ct;
		else
			c$http$resp_content_type = ct;
		}
	}

event http_begin_entity(c: connection, is_orig: bool) &priority=0
	{
	if ( c$uid !in xbits_bs )
		xbits_bs[c$uid] = XbitsBState();
	local st = xbits_bs[c$uid];
	if ( is_orig )
		{
		st$req_buf = "";
		st$req_len = 0;
		st$req_trunc = F;
		}
	else
		{
		st$resp_buf = "";
		st$resp_len = 0;
		st$resp_trunc = F;
		}
	xbits_bs[c$uid] = st;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=0
	{
	if ( c$uid !in xbits_bs )
		return;
	local st = xbits_bs[c$uid];
	local ct = is_orig ? st$req_ct : st$resp_ct;
	local do_cap = xbits_capture_type(ct, st$method, is_orig);

	if ( is_orig )
		{
		st$req_len += length;
		if ( do_cap && ! st$req_trunc )
			{
			local room = xbits_max_body_bytes - |st$req_buf|;
			if ( length <= room )
				st$req_buf = st$req_buf + data;
			else
				{
				if ( room > 0 )
					st$req_buf = st$req_buf + sub_bytes(data, 0, room);
				st$req_trunc = T;
				}
			}
		}
	else
		{
		st$resp_len += length;
		if ( do_cap && ! st$resp_trunc )
			{
			local room_r = xbits_max_body_bytes - |st$resp_buf|;
			if ( length <= room_r )
				st$resp_buf = st$resp_buf + data;
			else
				{
				if ( room_r > 0 )
					st$resp_buf = st$resp_buf + sub_bytes(data, 0, room_r);
				st$resp_trunc = T;
				}
			}
		}
	xbits_bs[c$uid] = st;
	}

event http_end_entity(c: connection, is_orig: bool) &priority=0
	{
	if ( ! c?$http || c$uid !in xbits_bs )
		return;
	local st = xbits_bs[c$uid];
	local ct = to_lower(is_orig ? st$req_ct : st$resp_ct);

	if ( is_orig )
		{
		c$http$req_content_type = st$req_ct;
		if ( st$req_len > 0 )
			{
			c$http$req_body_excerpt = st$req_buf;
			c$http$req_body_truncated = st$req_trunc;
			}
		if ( /application\/x-www-form-urlencoded/ in ct )
			c$http$form_fields = xbits_kv_to_json(st$req_buf, /&/);
		else if ( /multipart\/form-data/ in ct || ( c$uid in xbits_form_names && |xbits_form_names[c$uid]| > 0 ) )
			{
			local fm: table[string] of string = table();
			if ( c$uid in xbits_form_names )
				{
				for ( nm in xbits_form_names[c$uid] )
					fm[nm] = "";
				delete xbits_form_names[c$uid];
				}
			c$http$form_fields = to_json(fm);
			}
		if ( /json/ in ct )
			c$http$json_body = st$req_buf;
		if ( /xml/ in ct )
			c$http$xml_body = st$req_buf;
		}
	else
		{
		c$http$resp_content_type = st$resp_ct;
		if ( st$resp_len > 0 )
			{
			c$http$resp_body_excerpt = st$resp_buf;
			c$http$resp_body_truncated = st$resp_trunc;
			}
		}
	}

event connection_state_remove(c: connection)
	{
	if ( c$uid in xbits_bs )
		delete xbits_bs[c$uid];
	if ( c$uid in xbits_form_names )
		delete xbits_form_names[c$uid];
	}
