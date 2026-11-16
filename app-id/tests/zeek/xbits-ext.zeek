##! xbits HTTP 扩展解析（完整头/关键头值/Cookie/认证/Query/表单/JSON/XML/安全相关 Body 片段）
##!
##! 目标：在默认 http.log 之外补齐 Web 安全分析需要的 HTTP 字段，并对过大的 Body 做“按类型 + 限长 + 截断标记”的安全裁剪：
##!   - 完整请求/响应头（JSON，含值）；Cookie / Set-Cookie 值；完整 Authorization / Proxy-Authorization（Basic 自动解码）
##!   - Query 参数（名+值，JSON）；表单（urlencoded 全量 / multipart 尽力提取 name，JSON）
##!   - JSON / XML 正文原文（限长）；安全相关类型正文片段（限长）+ 截断标记；二进制/媒体类型不正文采集（仅长度/文件框架哈希）
##!
##! 说明：Zeek 9.0.1 无 HTTP/2 分析器，本扩展仅作用于 HTTP/1.x（明文）。

@load base/protocols/http/main
@load base/protocols/http/entities
@load base/utils/strings

module HTTP;

export {
	## 每方向 Body 片段最大采集字节数（超出置截断标记）
	global xbits_max_body_bytes: count = 4096 &redef;

	redef record Info += {
		## 完整请求头（JSON 对象：头名[大写]->值；重复头以 ", " 合并）
		request_headers:  string &log &optional;
		## 完整响应头（JSON 对象）
		response_headers: string &log &optional;
		## 请求 Cookie 头原值
		cookie:           string &log &optional;
		## 响应所有 Set-Cookie 值
		set_cookie:       vector of string &log &optional;
		## Authorization 原值
		authorization:    string &log &optional;
		## 认证方案（basic/bearer/...）
		authorization_scheme: string &log &optional;
		## 认证凭据（Basic 自动 base64 解码为 user:pass；其它原样）
		authorization_credentials: string &log &optional;
		## Proxy-Authorization 原值
		proxy_authorization: string &log &optional;
		## Query 参数（JSON 对象：名->值）
		query_params:     string &log &optional;
		## 表单字段（JSON 对象：名->值；multipart 尽力提取 name）
		form_fields:      string &log &optional;
		## 请求/响应 Content-Type（type/subtype）
		req_content_type:  string &log &optional;
		resp_content_type: string &log &optional;
		## 安全相关请求/响应 Body 片段（限长）
		req_body_excerpt:  string &log &optional;
		resp_body_excerpt: string &log &optional;
		## Body 是否被截断（超过 xbits_max_body_bytes）
		req_body_truncated:  bool &log &default=F;
		resp_body_truncated: bool &log &default=F;
		## JSON/XML 请求正文原文（限长；便于下游直接解析）
		json_body: string &log &optional;
		xml_body:  string &log &optional;
	};
}

type BState: record {
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

global bs: table[string] of BState &create_expire=300sec;
# multipart 子实体的字段名（来自各 part 的 Content-Disposition 头，key=uid）
global form_names: table[string] of set[string] &create_expire=300sec;

function hdrs_to_json(hlist: mime_header_list): string
	{
	local m: table[string] of string = table();
	for ( i in hlist )
		{
		local nm = hlist[i]$name;   # 已转大写
		local vv = hlist[i]$value;
		if ( nm in m )
			m[nm] = m[nm] + ", " + vv;
		else
			m[nm] = vv;
		}
	return to_json(m);
	}

function kv_to_json(q: string, sep: pattern): string
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

function multipart_names_to_json(body: string): string
	{
	local m: table[string] of string = table();
	# 按双引号切分：形如 ...; name="field" 的前一段以 “ name=” 结尾，下一段即字段名
	local parts = split_string(body, /\"/);
	local i = 1;
	while ( i < |parts| )
		{
		if ( /[[:blank:]]name=$/ in parts[i-1] )
			{
			local nm = parts[i];
			if ( nm != "" )
				m[nm] = "";
			}
		i += 1;
		}
	return to_json(m);
	}

function capture_type(ct: string, method: string, is_orig: bool): bool
	{
	local t = to_lower(ct);
	if ( t == "" )
		{
		# 无 Content-Type：仅对可能的请求体方法采集
		return is_orig && (method == "POST" || method == "PUT" || method == "PATCH");
		}
	if ( /application\/x-www-form-urlencoded/ in t ) return T;
	if ( /multipart\/form-data/ in t ) return T;
	if ( /json/ in t ) return T;
	if ( /xml/ in t ) return T;
	if ( /graphql/ in t ) return T;
	if ( /text\/plain/ in t ) return T;
	if ( is_orig ) return F;
	# 响应侧安全相关文本类型
	if ( /text\/html/ in t ) return T;
	if ( /javascript/ in t ) return T;
	return F;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=0
	{
	if ( c$uid !in bs )
		bs[c$uid] = BState();
	local st = bs[c$uid];
	st$method = method;
	bs[c$uid] = st;

	if ( c?$http )
		{
		local parts = split_string1(original_URI, /\?/);
		if ( |parts| > 1 )
			c$http$query_params = kv_to_json(parts[1], /&/);
		else
			c$http$query_params = "{}";
		}
	}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=0
	{
	if ( ! c?$http )
		return;
	if ( c$uid !in bs )
		bs[c$uid] = BState();
	local st = bs[c$uid];

	if ( is_orig )
		c$http$request_headers = hdrs_to_json(hlist);
	else
		c$http$response_headers = hdrs_to_json(hlist);

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
	bs[c$uid] = st;
	if ( ! is_orig && |setc| > 0 )
		c$http$set_cookie = setc;
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=0
	{
	# multipart/form-data 各 part 的字段名来自 Content-Disposition
	if ( is_orig && name == "CONTENT-DISPOSITION" && /[[:blank:]]name=\"/ in value )
		{
		local parts = split_string(value, /\"/);
		if ( |parts| > 1 && parts[1] != "" )
			{
			if ( c$uid !in form_names )
				form_names[c$uid] = set();
			add form_names[c$uid][parts[1]];
			}
		}
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string) &priority=0
	{
	if ( c$uid !in bs )
		bs[c$uid] = BState();
	local st = bs[c$uid];
	local ct = to_lower(ty + "/" + subty);
	if ( is_orig )
		st$req_ct = ct;
	else
		st$resp_ct = ct;
	bs[c$uid] = st;

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
	if ( c$uid !in bs )
		bs[c$uid] = BState();
	local st = bs[c$uid];
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
	bs[c$uid] = st;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=0
	{
	if ( c$uid !in bs )
		return;
	local st = bs[c$uid];
	local ct = is_orig ? st$req_ct : st$resp_ct;
	local do_cap = capture_type(ct, st$method, is_orig);

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
	bs[c$uid] = st;
	}

event http_end_entity(c: connection, is_orig: bool) &priority=0
	{
	if ( ! c?$http || c$uid !in bs )
		return;
	local st = bs[c$uid];
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
			c$http$form_fields = kv_to_json(st$req_buf, /&/);
		else if ( /multipart\/form-data/ in ct || ( c$uid in form_names && |form_names[c$uid]| > 0 ) )
			{
			local fm: table[string] of string = table();
			if ( c$uid in form_names )
				{
				for ( nm in form_names[c$uid] )
					fm[nm] = "";
				delete form_names[c$uid];
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
	if ( c$uid in bs )
		delete bs[c$uid];
	if ( c$uid in form_names )
		delete form_names[c$uid];
	}
