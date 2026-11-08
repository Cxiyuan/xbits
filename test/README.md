# test · 测试与流量模拟

本目录只用于 CI 与本地预检，不属于检测逻辑。当前场景：

- `DNS隧道与带外检测/`（Suricata 8.0.8）
- `侦察与攻击工具指纹/`（Suricata 8.0.8）
- `Web漏洞利用/`（Suricata 8.0.8）
- `后门通信/`（Suricata 8.0.8，WebShell + C2 信标）

若后续某个场景使用 Zeek，`.zeek` 脚本放在该场景目录内（如 `<场景>/zeek/`），
不创建仓库根级 `zeek/`。

## 1. 测试数据来源调研

在编写自有 PCAP 前，检查了以下高可靠来源：

| 来源 | 可靠性 | 是否直接采用 | 原因 |
|---|---|---|---|
| [OISF suricata-verify](https://github.com/OISF/suricata-verify) | 官方、MIT、按 Suricata 版本维护 | 否 | 面向上游规则/引擎测试；SID、Lua、dataset 与本案不同，且需要固定 commit 才能稳定 |
| [Zeek btest](https://github.com/zeek/zeek/tree/master/testing/btest) | 官方、随 Zeek 版本维护 | 否 | 面向 Zeek 引擎/解析器；不含本案 Suricata 规则与自定义检测脚本的断言 |
| [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) | 广为人知 | 否 | 通用 DNS 样本，缺少 DNS 隧道/OOB 的成对正反例 |
| malware-traffic-analysis.net 等恶意流量集 | 真实 | 否 | 许可、下载稳定性、可重复性不适合作为 CI 固定输入；且难以覆盖本案每一条规则的负例 |
| 公开 DNS tunneling 数据集 | 参差 | 否 | 缺少与本案 SID/Lua 对应的标签；体量大、许可不清 |

**结论**：没有一个可直接采用、许可清晰、与本案 SID/Lua 精确对应的公开测试集。
因此使用 **Scapy 2.6.1 生成确定性合成 PCAP**，覆盖每条规则/Lua 的正例与反例。
如果后续需要真实恶意流量，建议单独放在 `test/realworld/` 并明确许可与来源，不进入默认 CI。

## 2. 生成测试流量

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_pcaps.py --out test/pcap
```

生成的文件（CI 每次重新生成，不提交到仓库）：

| PCAP | 场景 | 期望 |
|---|---|---|
| `tunnel_32hex.pcap` | 32hex + TXT base64url 载荷 | 9109002/9109201/9109202/9109203 |
| `tunnel_base32_normal_a.pcap` | 20 字符 base32 + 正常 A 响应 | 9109201；不命中 9109203 |
| `spf_txt.pcap` | SPF TXT 大文本 | 不命中 9109202/9109203 |
| `verify_txt.pcap` | 域名验证 TXT | 不命中 9109202/9109203 |
| `dmarc_txt.pcap` | `_dmarc` TXT | 不命中 9109202/9109203 |
| `cname_tunnel.pcap` | 32hex 查询 + 高熵 CNAME target | 9109202/9109203 |
| `uuid_valid.pcap` / `uuid_invalid.pcap` | 合法/非法 UUID | 命中/不命中 9109003 |
| `compact_positive.pcap` / `compact_negative.pcap` | 随机十六进制单字符流 / `a.b.c.d.e.f.g` | 命中/不命中 9109001 |
| `long_positive.pcap` / `long_negative.pcap` | 61 字符随机字母数字 / 高连字符 | 命中/不命中 9109006 |
| `long_multilevel.pcap` | 61 字符标签 + `.abc.def.co.uk` | 命中 9109006/9109201 |
| `oob_positive.pcap` / `oob_negative.pcap` | `abc123.oast.pro` / 根域+短 token+MX | 命中/不命中 9109004 |
| `oob_other_positive.pcap` | `abc123.interact.sh` | 命中 9109005 |
| `txt_burst_positive.pcap` / `txt_burst_negative.pcap` | 50 条子域 TXT / 50 条 `_dmarc` TXT | 命中/不命中 9109103 |
| `dot_positive.pcap` / `dot_negative.pcap` | TLS 853 + ALPN `dot` + DNS SNI / 无 ALPN + 非 DNS SNI | 命中/不命中 9109101 |
| `doh_positive.pcap` / `doh_negative.pcap` | POST `/dns-query` / POST `/api` + DoH Content-Type | 命中/不命中 9109102 |

## 3. 侦察与攻击工具指纹场景

生成命令：

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_recon_pcaps.py --out test/recon_pcap
```

| PCAP | 场景 | 期望 |
|---|---|---|
| `recon_tools_positive.pcap` | 26 个保留工具的默认 UA，路径 `/` | 命中 9101001-9101027（不含已删除的 9101017） |
| `recon_sqlmap_sensitive.pcap` | sqlmap + `/.git/config` + HTTP 200 | 9101004/9101101/9101102 |
| `recon_nuclei_sensitive_403.pcap` | Nuclei + `/.env` + HTTP 403 | 9101005/9101101/9101107 |
| `recon_generic_path_rate.pcap` | python-requests 25 次 `/.env` | 9101103/9101104 |
| `recon_path_no_ua_rate.pcap` | 无 UA、25 次 `/.git/config` | 9101103/9101104 |
| `recon_curl_rate.pcap` | 外部 curl 60 次 `/api` | 9101028/9101109 |
| `recon_outbound_curl_rate.pcap` | 内网主机外联 curl 60 次 `/api` | 9101029 |
| `recon_outbound_tool.pcap` | 内网主机 → 外部，sqlmap UA | 9101105；不命中 9101004 |
| `recon_internal_tool.pcap` | 内网主机 → 内网，gobuster UA | 9101106；不命中 9101002 |
| `recon_httpx_python_negative.pcap` | `python-httpx/0.27.0` | 不命中 9101019 |
| `recon_browser_negative.pcap` | 正常 Chrome UA | 不命中任何工具 SID |
| `recon_empty_ua_negative.pcap` | 空 User-Agent | 不命中 9101028/9101101/9101103 |
| `recon_no_ua_negative.pcap` | 无 User-Agent | 不命中 9101028/9101101/9101103 |
| `recon_healthcheck_negative.pcap` | `kube-probe` + `/healthz` | 不命中 9101106/9101103 |
| `recon_body_confirmed.pcap` | sqlmap + `/.git/config` + 200 + `[core]` | 9101004/9101101/9101102/9101108 |
| `recon_soft404_negative.pcap` | sqlmap + `/.git/config` + 200 + HTML 软 404 | 9101004/9101101；不命中 9101102/9101108 |
| `recon_404_burst.pcap` | 浏览器 UA + 60 个非敏感路径 404 | 9101109 |
| `recon_404_static_negative.pcap` | 60 个 `.png` 404 | 不命中 9101109 |
| `recon_acunetix_header.pcap` | 浏览器 UA + `Acunetix-Aspect` | 9101110；不命中 9101007 |
| `recon_path_double_encoded.pcap` | 25 次 `/%252e%2567%2569%2574/config` | 9101103/9101104 |
| `recon_path_dot_segment.pcap` | 25 次 `/foo/%2e%2e/.git/config` | 9101103/9101104 |
| `recon_path_backslash.pcap` | 25 次 `/.git%5cconfig` | 9101103/9101104 |
| `recon_wrapped_ua.pcap` | `Mozilla/5.0 (compatible; sqlmap/1.8.8)` | 9101112；不命中 9101004 |
| `recon_outbound_scanner_ua.pcap` | 内网 → 外部，Shodan UA | 9101111；不命中 9101105 |
| `recon_method_trace.pcap` | 外部 TRACE + 敏感路径 | 9101113 |
| `recon_method_put_benign_negative.pcap` | 外部 PUT `/api` + 正常 Host | 不命中 9101113 |
| `recon_context_double_encoded.pcap` | sqlmap + 双重编码 `/.git/config` | 9101004/9101101 |
| `recon_nuclei_403_html.pcap` | Nuclei + `/.env` + HTML 403 登录页 | 9101005/9101101/9101107 |
| `recon_body_201.pcap` | sqlmap + `/.git/config` + 201 + `[core]` | 9101004/9101101/9101102/9101108 |

断言文件为 `recon_cases.json`，当前共 29 个 PCAP；检测规则/Lua 在 `侦察与攻击工具指纹/`。

## 4. Web 漏洞利用场景

生成命令：

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_web_pcaps.py --out test/web_pcap
```

| PCAP 组 | 场景 | 期望 |
|---|---|---|
| `web_sqli_*` | URI/Body 的 UNION、时间、布尔、元数据、报错注入 | 9103001 |
| `web_traversal_*` / `web_lfi_wrapper` | 路径穿越、编码穿越、Body 穿越、PHP 包装器 | 9103008 |
| `web_log4shell_*` | Header、嵌套 Header、Body 的 JNDI | 9103013 |
| `web_cmdi_*` | URI/Body 的命令注入 | 9103015 |
| `web_deser_*` | Fastjson、OGNL、ThinkPHP、Java 序列化 | 9103018 |
| `web_ssrf_metadata` | 云元数据 SSRF | 9103101 |
| `web_xxe` | XML 外部实体 | 9103102 |
| `web_ssti` | 模板危险对象访问 | 9103103 |
| `web_upload_webshell` | 脚本扩展名 + PHP 代码 | 9103104 |
| `web_*_negative` | 正常 SQL 元数据词、相对路径、`${env:}`、`&id=2`、安全 `@type`、外链 URL、普通 XML、`{{name}}`、PDF 上传 | 不命中对应规则 |

断言文件为 `web_cases.json`，共 34 个 PCAP；检测规则/Lua 在 `Web漏洞利用/`。
正例同时 forbid 其他类别 SID，避免跨类别误报；反例 forbid 全部 9 个 SID。

## 5. 后门通信 / C2 信标场景

生成命令：

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_backdoor_pcaps.py --out test/backdoor_pcap
```

| PCAP 组 | 场景 | 期望 |
|---|---|---|
| `ws_path_only` | 已知 WebShell 文件名，无命令参数 | 9104001 |
| `ws_cmd_query` | `/shell.php?cmd=id` + 命令输出 | 9104001/9104002/9104003 |
| `ws_cmd_post` | POST `cmd=whoami` + `www-data` 响应 | 9104001/9104002/9104003 |
| `ws_z0_base64` | `z0=<base64 id>` + `uid=` 响应 | 9104002/9104003 |
| `ws_cookie` | Cookie `pass=<base64 id>` + `uid=` | 9104001/9104002/9104003 |
| `ws_tool_ua` | `antSword` UA | 9104004 |
| `ws_negative_param` | `?cmd=config` 正常值 | 不命中 9104001-4 |
| `ws_negative_browser` | 正常浏览器访问 index.php | 不命中 9104001-4 |
| `c2_sample` | 实证 a/f/t/p + 固定 UA | 9110001/9110002 |
| `c2_variant` | a/f/t/p 参数顺序变化 | 9110002 |
| `c2_header_anomaly` | 信标 URI + 缺 Accept/Accept-Language/Referer | 9110004 |
| `c2_panel` | `/api/beacon/task/list` | 9110005 |
| `c2_singleletter` | `/?a=&b=&c=` + 头异常 | 9110006 |
| `c2_response` | 响应 `{"task":"exec","command":"whoami"}` | 9110007 |
| `c2_old_ua` | Win7 + Firefox 48 UA | 9110003（telemetry） |
| `c2_negative_analytics` | 正常 `?a=1&b=2&c=3` | 不命中 9110001-7 |
| `c2_negative_panel` | 正常 `/api/file/upload` | 不命中 9110001-7 |

断言文件为 `backdoor_cases.json`，共 17 个 PCAP；规则/Lua 在 `后门通信/`。

## 6. Zeek 关联分析

每个场景的 Zeek 脚本与对应 Suricata CI 运行在同一个 PCAP 上：

| 场景 | Zeek 脚本 | 关联日志 |
|---|---|---|
| DNS | `DNS隧道与带外检测/zeek/dns_tunnel_score.zeek` | `dns_correlation.log` |
| 侦察 | `侦察与攻击工具指纹/zeek/recon_score.zeek` | `recon_correlation.log` |
| Web | `Web漏洞利用/zeek/web_exploit_chain.zeek` | `web_correlation.log` |
| 后门/C2 | `后门通信/zeek/backdoor_c2_score.zeek` | `backdoor_correlation.log` |

联动机制：

- Suricata EVE 开启 `community-id: true`；
- Zeek 日志字段 `community_id` 由 `community_id_v1(c$id)` 生成；
- Zeek 日志字段 `related_sids` 记录对应场景 Suricata SID；
- `test/assert_zeek.py` 断言 Zeek 事件，并与同一 PCAP 的 Suricata EVE
  `community_id` 求交集；交集为空即失败；
- Zeek 9.0.1 使用固定 Docker digest，
  `zeek -b -Cr <pcap> <script>` 加载运行。

本地运行示例：

```bash
mkdir -p test/zeek_out/dns
docker run --rm -v "$PWD:/work" -w /work/test/zeek_out/dns \
  zeek/zeek:9.0.1@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0 \
  zeek -b -Cr /work/test/pcap/txt_burst_positive.pcap \
  /work/DNS隧道与带外检测/zeek/dns_tunnel_score.zeek LogAscii::use_json=T
python test/assert_zeek.py \
  --log test/zeek_out/dns/dns_correlation.log \
  --scenario dns-tunnel \
  --eve-root test/out/suricata --case txt_burst_positive
```

注意：Zeek `-b` 模式不会自动加载 base 脚本，脚本内已显式
`@load base/frameworks/logging` / `base/protocols/conn` / `base/protocols/dns|http`。

## 7. CI 断言

- `cases.json`：DNS 场景每个 PCAP 的 `require` / `forbid` SID。
- `recon_cases.json`：侦察场景每个 PCAP 的 `require` / `forbid` SID。
- `web_cases.json`：Web 漏洞利用场景每个 PCAP 的 `require` / `forbid` SID。
- `backdoor_cases.json`：后门通信/C2 信标场景每个 PCAP 的 `require` / `forbid` SID。
- `assert_zeek.py`：断言 Zeek `*_correlation.log`，并校验 Suricata EVE `community_id` 交集。
- `assert_suricata.py`：解析 `eve.json`，断言 `alert.signature_id`。

当前没有 Zeek 内容，因此没有 Zeek 断言文件。后续某场景加入 Zeek 时，
在该场景的测试目录中增加 `zeek_cases.json` 与 `assert_zeek.py`（或等价断言）。

## 8. 本地运行（预检，不作为最终验证）

本地预检需要精确版本：

```bash
# Suricata 8.0.8 + 完整规则/dataset/Lua
suricata -T -c test/suricata-ci.yaml
for pcap in test/pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/cases.json

# 侦察场景
suricata -T -c test/suricata-recon-ci.yaml
for pcap in test/recon_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-recon-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/recon_cases.json

# Web 漏洞利用场景
suricata -T -c test/suricata-web-ci.yaml
for pcap in test/web_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-web-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/web_cases.json

# 后门通信 / C2 信标场景
suricata -T -c test/suricata-backdoor-ci.yaml
for pcap in test/backdoor_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-backdoor-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/backdoor_cases.json
```

**最终验证只认 GitHub Actions**：

- `.github/workflows/suricata-dns-tunnel.yml`：DNS 场景规则/Lua/dataset/测试断言变更时运行。
- `.github/workflows/suricata-recon-tools.yml`：侦察场景规则/Lua/测试断言变更时运行。
- `.github/workflows/suricata-web-exploit.yml`：Web 漏洞利用场景规则/Lua/测试断言变更时运行。
- `.github/workflows/suricata-backdoor-c2.yml`：后门通信/C2 信标场景规则/Lua/测试断言变更时运行。
- 上述四个 Suricata workflow 内均包含 Zeek 关联与 community-id 断言；
  没有独立根级 Zeek CI。
- 后续场景若使用 Suricata，新增该场景的 Suricata workflow；若使用 Zeek，
  在该场景目录加入 `.zeek` 并新增该场景的 Zeek workflow；两种都用就都跑。
- 不创建仓库根级 `zeek/` 目录，也不为“未来可能用到”的 Zeek 预建空 CI。

本地结果仅作提交前预检；CI 未通过不得声称已验证。

## 9. 许可与安全

- 生成的 PCAP 只包含 RFC 5737/1918 地址与虚构域名，不含真实客户数据。
- 测试脚本不参与检测；检测逻辑只在规则/Lua（以及场景内 Zeek）中。

## 10. xbits 跨引擎事件联动

`xbits/` 是自研 Rust 组件，用于把 Suricata 8.0.8 的 EVE `unix_stream`
告警直接推入 Zeek 9.0.1 Input 事件循环，而不是读取 `eve.json` 做日志
join。测试入口：

- `.github/workflows/xbits-ci.yml`
  - Rust：`cargo fmt --check`、`cargo test --locked`、release build；
  - Zeek stdin：`xbits --stdin` + `xbits_test.zeek`；
  - 真实链路：Suricata 8.0.8 `filetype: unix_stream` + `xbits_live.zeek`
    分别回放 DNS `txt_burst_positive`、侦察 `recon_404_burst`、
    Web `web_sqli_uri_union`、后门 `ws_cmd_query` 四个场景 PCAP。
- 断言：`xbits/test/assert_xbits.py` 检查 `xbits_correlation.log` 的
  `signature_id`、`community_id`、`reason`、`scenario`、`related_sids`。
- Suricata 是 Unix socket 的 `connect()` 客户端；xbits 是 `UnixListener`
  监听端。测试 socket 权限设为 `0666`，生产必须用父目录权限限制访问。
