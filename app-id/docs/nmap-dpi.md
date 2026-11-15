# Nmap 特征与 DPI 调研（用于 app-id 识别）

> 目的：为 `app-id/`（基于 Zeek 的应用识别引擎库）开发 **Nmap 识别**提供依据。
> 数据来源：Nmap 官方源码 `nmap-service-probes`（master）、`nselib/http.lua`（master）及 Nmap 文档。本文所列探针载荷为**官方原始字节**。
> 状态：调研文档；实现见后续 `app-id/signatures/nmap.sig` 与 `app-id/scripts/appid/nmap.zeek`（待开发）。

## 0. 结论速览
Nmap 的可识别面很强，主要来自三类"主动指纹"：
1. **服务/版本探测探针**（`-sV`）：固定的畸形/半成品请求，如 `GET / HTTP/1.0\r\n\r\n`（无 Host/UA）、`\r\n\r\n`、`OPTIONS / HTTP/1.0\r\n\r\n`、`/nice%20ports%2C/Tri%6Eity.txt%2ebak` 等，**特异性很高**。
2. **NSE 脚本流量**：默认 `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`。
3. **TLS 主动探测**：版本探测用固定 ClientHello，可算出**确定性 JA3**；`ssl-enum-ciphers` 会发起大量不同套件的 ClientHello（行为特征）。
配合**行为特征**（端口顺序扫描、半开连接、同连接多次不同探针）可高置信判定 Nmap。

---

## 1. Nmap 工作方式（决定检测点）
- **扫描阶段**：`-sS` SYN 半开扫描 / `-sT` 连接扫描 / `-sU` UDP；大量目标端口、按序/随机推进，多数连接短命。
- **版本探测阶段（-sV）**：对开放端口依次发送 `nmap-service-probes` 中的探针（先 `NULL` 等 banner，再 `GetRequest`/`HTTPOptions`/`RTSPRequest`/`FourOhFourRequest` 等），根据响应匹配指纹。
- **NSE 脚本阶段**：`--script` 触发 Lua 脚本，走 HTTP/DNS/SSL 等协议栈，带默认 UA 与特定路径。
- **OS 探测（-O）**：TCP/UDP/ICMP 组合探针（网络层特征，非本库主攻方向）。

---

## 2. 版本探测探针（官方原文，强 DPI 特征）

| 探针名 | 协议 | 载荷（原始字节，`\r\n` 为回车换行） |
|---|---|---|
| NULL | TCP | （空载荷，连接后直接等待 banner） |
| GenericLines | TCP | `\r\n\r\n` |
| GetRequest | TCP | `GET / HTTP/1.0\r\n\r\n` |
| HTTPOptions | TCP | `OPTIONS / HTTP/1.0\r\n\r\n` |
| RTSPRequest | TCP | `OPTIONS / RTSP/1.0\r\n\r\n` |
| FourOhFourRequest | TCP | `GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n` |
| Help | TCP | `HELP\r\n` |
| Hello | TCP | `EHLO\r\n` |
| DNSVersionBindReq | UDP | DNS 查询 `version.bind` TXT/CH（见下字节） |
| DNSVersionBindReqTCP | TCP | 同上，TCP 长度前缀 |
| DNSStatusRequest | UDP/TCP | DNS 状态请求（`\0\0\x10\0...`） |
| TerminalServerCookie | TCP | `\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=nmap\r\n\x01\0\x08\0\x03\0\0\0` |
| SIPOptions | TCP/UDP | `OPTIONS sip:nm SIP/2.0\r\n...`（含 `sip:nm`、`Call-ID: 50000` 等固定串） |
| Socks5 | TCP | 含 `\x05\x04\0\x01\x02\x80\x05...google.com\x00\x50GET / HTTP/1.0\r\n\r\n` |

DNS version.bind 载荷（UDP）：
```
\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03
```

**判读**：
- `GET / HTTP/1.0\r\n\r\n`（**无 Host、无 User-Agent**）——老式 HTTP/1.0 客户端也会有，但正常浏览器/curl 会带 Host/UA；作为**中-高**置信。
- `\r\n\r\n`（GenericLines，连接后立即两对 CRLF）——**中**置信，需结合扫描行为。
- `GET /nice%20ports%2C/Tri%6Eity.txt%2ebak ...`——**极高**置信，几乎 Nmap 专属。
- `Cookie: mstshash=nmap`——**极高**置信（Nmap RDP 探测自带该串）。
- `sip:nm`、`HELP\r\n`、`EHLO\r\n` 等——中置信，需去重正常协议客户端。

---

## 3. NSE（脚本引擎）HTTP 指纹
- 默认 **User-Agent**（`nselib/http.lua` 原文）：
  ```
  Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
  ```
- 默认 **Host** 头：`stdnse.get_hostname()`（目标主机名/IP），非空。
- 常见脚本会带 `Connection: close`，请求多为 `HTTP/1.1`，路径如 `/`、`/robots.txt`、`/.git/HEAD`、`/HNAP1/`、`/server-status` 等（具体随脚本）。
- 注意：UA 可被 `--script-args http.useragent=...` 覆盖，或置空禁用 → UA 只作**中**置信，需结合其它信号。

---

## 4. TLS / JA3 指纹（确定性）
Nmap 版本探测使用固定 ClientHello（`nmap-service-probes` 中 `SSLSessionReq`/`TLSSessionReq`）。按其字节计算 JA3：

| 探针 | JA3 字符串 | JA3 MD5 |
|---|---|---|
| SSLSessionReq（SSLv3 records, no extensions） | `768,22-19-10-102-5-4-101-100-99-98-97-96-21-18-9-20-17-8-6-3,,,` | `ee0799c323d74129b75b633dcfd41593` |
| TLSSessionReq（TLS1.2, ext 13） | `771,47-10-19-57-4-255,13,,` | `16ee84a07b55074cb2751329bf1c8811` |

> `SSLv23SessionReq` 为 SSLv2 记录格式，不适用标准 JA3。
> NSE `ssl-enum-ciphers`/`ssl-cert` 使用 OpenSSL 发起多个 ClientHello（JA3 随 OpenSSL 版本变化）——可用"**同一源对同一目标短时间大量不同 ClientHello**"的行为特征识别。

---

## 5. DNS 特征
- `version.bind` / `hostname.bind`（CH 类 TXT）查询——Nmap `dns-*` 脚本与版本探测使用；`dig`/`nslookup` 也可能用，需看频率/组合。
- DNSStatusRequest 的固定载荷（见 §2）。

---

## 6. 网络层/行为特征（辅助置信）
- **端口扫描**：单源在窗口期内访问大量不同目的端口（增量明显），多为 SYN 未完成/极短连接。
- **半开扫描**：SYN 后收到 SYN/ACK 立即 RST（`-sS`）。
- **同连接多探针**：NULL→GetRequest→HTTPOptions 等在短时内对同一 `host:port` 连续发送不同畸形请求。
- **TCP 指纹**：Nmap 默认 SYN 选项/窗口有相对固定组合（MSS/SACK/Timestamp/NOP/WS、窗口 1024 等），可作弱特征（易被 `--randomize-hosts`/`-D`/`--data-length` 规避）。

---

## 7. 误报与对抗
- **可伪造/可关闭**：UA 可覆盖（`http.useragent`）、探针可改（自定义 `nmap-service-probes`）、可加 `--data-length` 填充、`--decoy` 诱饵、`--spoof-mac`、`-D`。
- **近似流量**：老式 HTTP/1.0 客户端、健康检查、某些协议探测/资产测绘也会发 `GET / HTTP/1.0`、`OPTIONS`、`\r\n\r\n`。
- **结论**：单一信号只给低/中置信；应做**多信号打分**（探针命中 + UA + JA3 + 扫描行为）再定 `Nmap`。

---

## 8. 在 app-id（Zeek）中的实现建议
Zeek 具备两层载体，正好覆盖上面的 DPI：
1. **Zeek Signature 框架（`signatures/*.sig`）**：对 TCP/UDP 原始载荷做正则/二进制匹配，命中触发 `signature` 事件 → 适合 `NULL/GenericLines/GetRequest/HTTPOptions/RTSP/FourOhFour/Help/mstshash/version.bind` 等固定探针。
2. **协议事件 + 行为**：`http_request`（UA/Host/URI）、`ssl`（JA3）、`dns_request`、`conn`/SumStats（端口扫描）。

建议落点：
```
app-id/
├── signatures/nmap.sig        # 固定探针载荷签名（二进制/正则）
├── scripts/appid/nmap.zeek    # 命中聚合、打分、note_app(c,"Nmap","scanner",...)
└── mapping/nmap.map           # 证据/置信度映射（可选）
```
- `nmap.zeek`：
  - `event signature(s: signature)`：按 `s$sig_id` 归类证据并累计评分；
  - `event http_request(c, info)`：UA 命中 "Nmap Scripting Engine" → 加分；`HTTP/1.0` 且无 Host + 探针路径 → 加分；
  - TLS：从 ssl 记录/事件取 `ja3`，命中上表 MD5 → 高置信（字段名按 Zeek 9.0.1 核验）；
  - DNS：`version.bind`/`hostname.bind` CH TXT → 加分；
  - 行为：单源多端口短时扫描（SumStats）→ 加分；
  - 汇总 ≥ 阈值 → `XbitsAppId::note_app(c, "Nmap", "scanner", evidence, confidence)`，落 `app_identity.log`。
- 置信度示例：FourOhFour/mstshash/JA3 命中=高(0.9+)；GetRequest 无Host+扫描行为=中高(0.7)；仅 GenericLines/OPTIONS=低(0.4)。

### 建议的 Zeek 签名样例（草案，待 9.0.1 验证语法）
```
signature nmap_get_request {
  ip-proto == tcp
  payload /^GET \/ HTTP\/1\.0\r\n\r\n/
  event "nmap probe: GetRequest"
}
signature nmap_four_oh_four {
  ip-proto == tcp
  payload /GET \/nice%20ports%2C\/Tri%6Eity\.txt%2ebak HTTP\/1\.0/
  event "nmap probe: FourOhFourRequest"
}
signature nmap_http_options {
  ip-proto == tcp
  payload /^OPTIONS \/ HTTP\/1\.0\r\n\r\n/
  event "nmap probe: HTTPOptions"
}
signature nmap_generic_lines {
  ip-proto == tcp
  payload /^\r\n\r\n/
  event "nmap probe: GenericLines"
}
signature nmap_mstshash {
  ip-proto == tcp
  payload /Cookie: mstshash=nmap/
  event "nmap probe: TerminalServerCookie"
}
```

---

## 9. 测试与回归计划
- 在受控环境（本地靶场/容器）运行并抓包：
  - `nmap -sS <target>`（扫描行为）
  - `nmap -sV <target>`（版本探测探针）
  - `nmap -sV --script http-title,http-headers <target>`（NSE UA）
  - `nmap -A <target>`（综合）
- 用 Zeek 9.0.1 回放 PCAP，断言 `app-id` 输出 `app=Nmap`、`evidence` 含命中探针、`confidence` 分级正确；同时用正常浏览器/curl/健康检查流量做**反例**，确保不误判。

## 10. 局限/待验证
- Zeek `signature` 对二进制/NUL 字节与 TLS 二进制探针的支持、以及 `ja3` 字段在 9.0.1 的脚本可见性，需按 9.0.1 文档验证。
- Nmap 可定制探针/UA/填充，DPI 只能覆盖默认与常见配置；需与行为特征互补。
- 加密：若流量为 TLS，探针内容不可见，只能靠 JA3/证书/行为。

## 参考
- nmap-service-probes: https://github.com/nmap/nmap/blob/master/nmap-service-probes
- nselib/http.lua: https://github.com/nmap/nmap/blob/master/nselib/http.lua
- Nmap 版本探测: https://nmap.org/book/vscan.html
