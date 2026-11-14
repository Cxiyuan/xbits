# Web 漏洞利用（Suricata 8.0.8）

本场景检测外部入站 HTTP 请求中的 Web 漏洞利用载荷：

- SQL 注入；
- 路径穿越 / 本地文件包含；
- Log4Shell / JNDI；
- 命令注入；
- Java 反序列化 / Fastjson / OGNL / ThinkPHP / Java 序列化；
- SSRF；
- XXE；
- SSTI；
- WebShell 上传。

## 文件

- 规则：`Web漏洞利用规则.rules`
- Lua：`lua/web_*.lua`
- 质量分析：`规则质量与误报分析.md`
- 测试：`../test/generate_web_pcaps.py`、`../test/web_cases.json`

## 1. 检测分层

| tier | 规则 | 说明 |
|---|---|---|
| `tier alert` | 9103001 SQLi | UNION/报错/时间/布尔/元数据上下文 |
| `tier alert` | 9103008 Traversal/LFI | 敏感文件、协议包装器、文件参数 |
| `tier alert` | 9103013 Log4Shell | URI/Header/Body/Cookie + 嵌套解混淆 |
| `tier alert` | 9103015 CMDi | 元字符 + 系统命令 |
| `tier alert` | 9103018 Deser | Fastjson/OGNL/ThinkPHP/Java/PHP |
| `tier alert` | 9103102 XXE | `<!ENTITY SYSTEM/PUBLIC>` |
| `tier triage` | 9103101 SSRF | 内网/云元数据/危险协议 |
| `tier triage` | 9103103 SSTI | 模板表达式 + 危险对象 |
| `tier triage` | 9103104 Upload | 脚本扩展名 + 代码标记 |

## 2. 方向

```text
$EXTERNAL_NET -> $HOME_NET
```

不使用 `any any -> any any`。上线前需定义：

```yaml
HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
EXTERNAL_NET: "!$HOME_NET"
CLIENT_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
```

## 3. 检测源

每条规则使用 `http.uri.raw; bsize:>0; lua:web_*.lua;` 触发，
Lua 再读取：

- `request_uri_raw()` / `request_uri_normalized()`；
- `request_body()`（最多 16 KiB）；
- `request_headers_raw()`；
- `request_header("Cookie")`；
- `Content-Type`（上传/XML/JSON）。

## 4. 关键判断

- **SQLi**：不因 `information_schema` 单独出现告警；需要 SQL 语法上下文。
- **Traversal/LFI**：单级 `../` 必须叠加敏感文件；两级以上独立成立；
  支持 `%2f`、`%5c`、双重编码、反斜杠、点段、协议包装器。
- **Log4Shell**：检查 URI、所有请求头、Body、Cookie；
  解 `${lower:j}`、`${upper:j}`、`${::-j}` 等嵌套。
- **CMDi**：要求 Shell 元字符后跟系统命令；`&id=2`、`&cat=3` 不算。
- **Deser**：Fastjson 需要 `@type/autoType` + 危险类；
  OGNL 需要 `%{` + Runtime/ProcessBuilder；ThinkPHP 需要 `invokefunction` 调用链；
  支持 `rO0AB`/`aced0005` Java 序列化 magic。
- **SSRF**：URL/跳转/代理/抓取参数 + 内网/云元数据/危险协议；外链不告警。
- **XXE**：`<!ENTITY` + `SYSTEM/PUBLIC`；普通 `<!DOCTYPE html>` 不告警。
- **SSTI**：模板定界符 + 算术/危险对象访问；普通 `{{name}}` 不告警。
- **Upload**：脚本扩展名 + 代码标记；只有文件名/普通文件不告警。

## 5. 限频与日志

- 每条规则 `threshold: type limit, track by_src, count 1, seconds 60`；
- 不使用 `detection_filter`；
- `tier alert` 进告警队列；`tier triage` 进调查队列。

## 6. 能力边界

1. **HTTPS 未解密**：看不到 URI/Body/Header。
2. **HTTP/2/HTTP/3**：`suricata.http` Lua API 以 HTTP/1 事务为主；
   HTTP/3/QUIC 加密流量不可见。
3. **请求体只读前 16 KiB**；超长 payload 可能漏报。
4. **不做响应侧成功确认**。
5. **JSON/multipart 是字符串搜索，不是结构化解析**。
6. **Shiro rememberMe** 加密 payload 与正常会话不可仅靠长度区分，未单独告警。
7. **SSRF/SSTI/Upload** 业务白名单误报较高，使用 `tier triage`。
8. **性能**：9 条 Lua 规则每请求执行并可能读取 Body，需 shadow 压测。

## 7. 验证

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_web_pcaps.py --out test/web_pcap
suricata -T -c test/suricata-web-ci.yaml
for pcap in test/web_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-web-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/web_cases.json
```

最终验证只认 `.github/workflows/suricata-web-exploit.yml`。
当前已验证：commit `b933f57`，run `42377078821`，34/34 用例通过：
<https://github.com/Cxiyuan/xbits/actions/runs/42377078821>。

## 8. Zeek 关联分析

- 脚本：`zeek/web_exploit_chain.zeek`；
- 关联请求 URI/Header/Body 与响应状态，输出 `web_correlation.log`；
- 含 `community_id`、`related_sids`，与 Suricata EVE 的 `community_id` 对齐；
- 覆盖 Suricata 单请求规则之外的响应关联；
- CI：web workflow 内运行 Zeek 9.0.1 + community-id 断言。
