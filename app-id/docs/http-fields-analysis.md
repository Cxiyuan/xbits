# xbits-zeek（Zeek 9.0.1）HTTP 解析字段盘点与欠缺分析

> 源码：`source/xbits-zeek`（Zeek 9.0.1）。
> 依据：`scripts/base/protocols/http/{main.zeek,entities.zeek,files.zeek}`、`src/analyzer/protocol/http/{HTTP.h,events.bif}`、`scripts/policy/protocols/http/*`。

## 1. 默认 `http.log` 直接输出的字段（`HTTP::Info`）
| 字段 | 含义 | 来源 |
|---|---|---|
| `ts` | 请求时间 | main |
| `uid` / `id` | 连接 uid / 4 元组 | main |
| `trans_depth` | 同一连接内请求/响应流水深度 | main |
| `method` | 请求方法 | http_request |
| `host` | Host 头 | http_header |
| `uri` | 请求 URI（含 query，未拆分） | http_request |
| `referrer` | Referer 头 | http_header |
| `version` | HTTP 版本 | main |
| `user_agent` | User-Agent 头 | http_header |
| `origin` | Origin 头 | http_header |
| `request_body_len` | 请求体**长度** | main |
| `response_body_len` | 响应体**长度** | main |
| `status_code` / `status_msg` | 响应码/短语 | http_reply |
| `info_code` / `info_msg` | 1xx 信息码/短语 | http_reply |
| `tags` | 攻击/失陷标记集合（当前仅 `EMPTY` 占位） | main |
| `username` / `password` | **仅 Basic-Auth** 解析；`password` 仅当 `capture_password=T` | main+http_header |
| `proxied` | 指示“可能经代理”的**头名集合**（非值） | main |
| `range_request` | 是否 Range 请求 | main |
| `orig_fuids/orig_filenames/orig_mime_types` | 请求方向文件实体（fuid/文件名/MIME，来自 files 框架） | entities.zeek（默认加载） |
| `resp_fuids/resp_filenames/resp_mime_types` | 响应方向文件实体（同上） | entities.zeek |

> 即：默认日志里有 **方法/URI/Host/UA/Referer/Origin/版本/状态码/体长度/文件引用**，**没有**完整的请求/响应头值、Cookie、请求/响应体内容、Content-Type、Server、Set-Cookie 等。

## 2. 事件层可直接拿到、但**默认不落日志**的字段
| 事件 | 提供字段 | 说明 |
|---|---|---|
| `http_request(c, method, original_URI, unescaped_URI, version)` | 方法、原始/未转义 URI、版本 | 逐请求 |
| `http_reply(c, version, code, reason)` | 版本、状态码、原因 | 逐响应 |
| `http_header(c, is_orig, name, value)`（另有 `original_name` 版本） | **任意单个头 name/value** | 可自行提取 Cookie/Authorization/XFF/Content-Type/Server/Set-Cookie/Location… |
| `http_all_headers(c, is_orig, hlist: mime_header_list)` | **全部头的 name/value（按线上顺序）** | 一次性拿全头（最有价值） |
| `http_begin_entity` / `http_end_entity` | 实体边界 | |
| `http_entity_data(c, is_orig, length, data)` | **实体体数据块**（默认每次最多 `http_entity_data_delivery_size=1500` 字节） | 可看请求/响应体内容 |
| `http_content_type(c, is_orig, ty, subty)` | Content-Type 主/子类型 | |
| `http_message_done(c, is_orig, stat: http_message_stat)` | `start/interrupted/finish_msg/body_length/content_gap_length/header_length` | 逐消息统计 |
| `http_event(c, event_type, detail)` | 解析事件/异常 | |
| `http_stats(c, stats: http_stats_rec)` | `num_requests/num_replies/request_version/reply_version` | 连接级统计 |
| `http_connection_upgrade(c, protocol)` | 协议升级（如 WebSocket） | |
| `mime_header_list` / `mime_event` | MIME 头/事件 | 多部分实体 |

> 结论：**字段其实大多“解析到了”，但默认只把少量落了 `http.log`**；其余需订阅上述事件自行落库。

## 3. 可选策略脚本可补的字段（非默认加载）
| 脚本 | 增加的 `HTTP::Info` 字段 | 内容 |
|---|---|---|
| `policy/protocols/http/header-names.zeek` | `client_header_names` / `server_header_names` | 仅**请求/响应头名称**（无值） |
| `policy/protocols/http/var-extraction-cookies.zeek` | `cookie_vars` | **Cookie 的变量名**（无值） |
| `policy/protocols/http/var-extraction-uri.zeek` | `uri_vars` | **Query 参数名**（无值） |
| `policy/protocols/http/software.zeek`（site/local 默认加载） | 无（写入 `software.log`） | 从 UA/Server/X-Powered-By 提取软件版本 |
| `policy/protocols/http/add-geodata.zeek` 等 | 地理位置等 | 可选 |

> 注意：即便是这些策略，也**只给“名称/版本”，不给头/参数的“值”**。

## 4. 源码内部已解析但未结构化暴露（C++ 层）
`src/analyzer/protocol/http/HTTP.h`：
- `HTTP_Message`：`body_length`、`header_length`、`content_gap_length`；
- `HTTP_Entity`：`content_length`、`range_length`、`encoding`(IDENTITY/GZIP/COMPRESS/DEFLATE)、`chunked_transfer_state`、`is_partial_content`、`offset`、`instance_length`、`filename`；
- `HTTP_Analyzer`：`request_method`、`original_URI`、`unescaped_URI`、`reply_code`、`reply_reason_phrase`、`request_version`/`reply_version`、`keep_alive`、`connection_close`、`upgrade_protocol`、`connect_request`。
这些多数**没有**映射进 `HTTP::Info` 日志（部分通过事件暴露）。

## 5. 真正“欠缺/不支持”的（源码级）
| 欠缺项 | 说明 |
|---|---|
| **HTTP/2** | **本源码没有 HTTP/2 分析器**（`src/analyzer/protocol/` 下无 `http2`；仅 `src/analyzer/protocol/ssl/events.bif` 提到 ALPN `h2`）。**HTTP/2 流量不会产生 http.log / HTTP 事件，HPACK 头也无法解析**。需外部包/插件或交由 Suricata 解析。 |
| **HTTP/3（QUIC）** | 有 QUIC 分析器，但**未映射为 `HTTP::Info`**，无 HTTP/3 请求字段。 |
| **请求/响应头“值”默认不落库** | 仅 host/UA/referrer/origin/proxied 名/username/password；Cookie、Authorization、XFF、Accept*、Content-Type、Content-Length、Server、Set-Cookie、Location、Cache-Control 值均需自订阅 `http_header/http_all_headers`。 |
| **请求/响应体内容不落库** | 仅 `request_body_len`/`response_body_len`；正文需 `http_entity_data`（默认每次 1500B）或 files 框架（`files.log` 的 `md5/sha1/sha256/mime_type/filename/total_bytes`，经 `resp_fuids` 关联）。 |
| **Cookie / Set-Cookie 值** | 不解析；可选脚本仅给 `cookie_vars` 名称。 |
| **认证** | 仅解析 **Basic**（username/password）；Bearer/JWT/Digest/NTLM 等不解析。 |
| **Query 参数“值”** | 默认只有完整 `uri`；可选 `uri_vars` 仅参数名。 |
| **表单（multipart）字段** | 仅作为 MIME 实体/文件，不解析字段名值对。 |
| **JSON/XML 正文语义** | 不解析。 |
| **响应重定向链 / Location** | Location 头不落库（需自取），无跳转链。 |
| **逐事务时延** | `http.log` 无每事务耗时；`http_message_stat` 有部分时间/长度。 |
| **Content-Encoding / Transfer-Encoding** | 内部解压/分块处理，但不在日志记录 encoding/transfer 字段。 |
| **Header 顺序** | 仅 `http_all_headers` 事件可保留顺序，未落库。 |
| **TLS 层字段（SNI/JA3/ALPN/证书）** | 在 `ssl.log`/`x509.log`，需按 `uid` 关联，非 http.log。 |

## 6. 与 Suricata HTTP 字段对比（Zeek `http.log` 缺项）
Suricata 的 `http.*` 关键字覆盖更广；Zeek `http.log` **缺**以下（但多数可由 Zeek 事件补）：
`http.accept`、`http.accept_enc`、`http.accept_lang`、`http.connection`、`http.content_len`、`http.content_type`、`http.cookie`、`http.header`/`http.header.raw`（全头原文）、`http.location`、`http.server`、`http.set_cookie`、`http.xff`、`http.request_line`、`http.response_line`、`http.protocol`。

## 7. 对本项目（威胁识别/app-id）的建议
1. **补一个 `xbits_http_detail` 日志/事件**：订阅 `http_all_headers`（一次性拿全部头值）+ `http_content_type`，落关键字段：
   `cookie`、`set_cookie`、`authorization`、`x_forwarded_for`、`content_type`、`content_length`、`server`、`location`、`accept`、`accept_language`、`connection`、`header_names(count)`。
2. **请求体/上传检测**：订阅 `http_entity_data`（按需 `redef http_entity_data_delivery_size` 增大）或直接用 `files.log`（`resp_fuids` 关联 md5/sha256/mime/filename，做落地/木马下载/webshell 上传识别）。
3. **Query/表单**：自行解析 `uri` query（值），POST `application/x-www-form-urlencoded` 解析体；用于注入/扫描特征。
4. **HTTP/2/HTTP/3 必须靠外部**：Zeek 9.0.1 无 HTTP/2 分析器；**当前 `scan.zeek` 中“HTTP/2 经 HPACK 仍可得 UA”的说法不成立**（需更正）。建议由 Suricata HTTP/2 解析或引入 Zeek 外部 HTTP/2 插件，再桥接本库。
5. **TLS 关联**：威胁判定时按 `uid` 关联 `ssl.log` 的 `server_name`/`ja3`/`ja3s`/`validation_status`，与 HTTP 字段合并。

## 8. 结论速览
- **默认 `http.log` 字段**：方法/Host/URI/UA/Referer/Origin/版本/状态码/体长度/文件引用（+Basic 用户名密码/代理头名/Range）。
- **事件层可得但未落库**：全部头值、请求/响应体、Content-Type、逐消息统计、升级事件等。
- **源码级真欠缺**：**HTTP/2 完全未解析**、HTTP/3 未映射、Header/Body/Cookie/参数值默认不落库、非 Basic 认证不解析、表单/JSON 不解析。
- 补齐优先级：`http_all_headers`（头值）> `http_entity_data`/files（体/文件）> query/body 解析 > HTTP/2 外部支持。

## 9. 已实现的源码级补齐（直接改 HTTP 解析脚本 `main.zeek`）
已**直接修改** `source/xbits-zeek/scripts/base/protocols/http/main.zeek`（HTTP 协议基础解析脚本）：
- 在 `HTTP::Info` 中**新增字段**（全部落 **`http.log`**，不新建任何日志/脚本文件）；
- 在 `main.zeek` 末尾**内置**采集逻辑（`XbitsBState` 状态 + `http_all_headers/http_header/http_content_type/http_begin_entity/http_entity_data/http_end_entity` 处理器）。
> 不再使用独立的 `xbits-ext.zeek`（该临时文件已删除）。CI 通过把该 `main.zeek` 覆盖到 stock Zeek 9.0.1 镜像的 `base/protocols/http/main.zeek` 来验证。

新增 `HTTP::Info` 字段：
- **完整头**：`request_headers`、`response_headers`（JSON 对象，头名[大写]→值；重复头以 `", "` 合并）；
- **Cookie**：`cookie`（请求原值）；`set_cookie`（响应所有 Set-Cookie 值，vector）；
- **完整认证**：`authorization`、`authorization_scheme`、`authorization_credentials`（Basic 自动 base64 解码为 `user:pass`）、`proxy_authorization`；
- **Query/表单**：`query_params`（JSON 名→值，URL 解码）、`form_fields`（urlencoded 全量 / multipart 尽力提取 name，JSON）；
- **Content-Type**：`req_content_type`、`resp_content_type`；
- **JSON/XML**：`json_body`、`xml_body`（请求正文原文，限长）；
- **安全相关 Body 片段**：`req_body_excerpt`、`resp_body_excerpt`（限长）+ `req_body_truncated`、`resp_body_truncated`。

**Body 过大处理（重点）**：
- 仅采集**安全相关类型**：`application/x-www-form-urlencoded`、`multipart/form-data`、`application/json(+json)`、`application/xml(+xml)/text/xml`、`application/graphql`、`text/plain`，响应侧额外 `text/html`、`javascript`；
- **每方向每实体最多 `xbits_max_body_bytes = 4096` 字节**（`&redef` 可调），超出置 `*_body_truncated=T`；
- 二进制/媒体（图片/音视频/字体/octet-stream/zip/pdf 等）**不采集正文**（仅长度；完整哈希/类型见 `files.log` 经 `resp_fuids` 关联）。
- 大型/分块正文：通过 `http_entity_data` 累积分片并截断；`http_entity_data_delivery_size` 可再调。

**验证**：`app-id/tests/run_http_fields.py` 用 `pcaps/http_fields.pcap`（urlencoded/JSON/XML/multipart+Set-Cookie）回放，断言上述字段全部落库；已加入 CI（`.github/workflows/app-id-scan.yml`）。**CI 实测（提交 `06bfd8b`，run 43810668088，success）：14/14 字段检查通过；扫描检测仍 DET=50/50、FPR=0/5。**

**仍不支持**：HTTP/2（Zeek 9.0.1 无分析器）、HTTP/3；需外部解析。
