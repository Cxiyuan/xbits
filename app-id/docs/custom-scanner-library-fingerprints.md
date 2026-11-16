# 自研扫描工具（Python / Go / C-C++ / Rust）的库指纹与 DPI

> 问题：自研扫描工具（用 Python/Go/C/C++/Rust 自己写的）有没有特征或 DPI？比如都用了同一类扫描/HTTP 库，能否据此识别？
> 结论：**有，而且很强。** 自研工具通常不会自己实现 HTTP/TLS 栈，而是复用成熟库；这些库会把**默认 UA、默认请求头、头部顺序/大小写、TLS ClientHello(JА3/JА4)、HTTP/2 SETTINGS 指纹**固化进流量。即便作者改了 UA，**TLS/HTTP2 指纹和行为仍可区分**。但要注意：库指纹只能说明"这是脚本/某客户端库"，**不等于"扫描器"**，需叠加扫描行为才可精确判定。

## 1. 五层指纹（从弱到强）
| 层 | 指纹 | 稳定性/抗伪造 | 说明 |
|---|---|---|---|
| L1 | 默认 User-Agent | 弱（可改） | 见 §2 各库默认 UA |
| L2 | 默认请求头 + **头部顺序/大小写** | 中 | 各库默认 `Accept/Accept-Encoding/Connection` 与写头顺序不同 |
| L3 | **TLS ClientHello → JA3/JA4** | **强** | Go crypto/tls、Rust rustls、OpenSSL、libcurl 各不相同，改 UA 无效 |
| L4 | **HTTP/2 指纹（Akamai：SETTINGS/WINDOW_UPDATE/Priority/伪头顺序）** | **强** | Go net/http2 vs nghttp2(C/curl) vs hyper(Rust) vs Python h2 差异明显 |
| L5 | 行为（扫描模式） | 强 | 高频、多 URI/多端口、404/403 突发、缺浏览器头、短连接 |

## 2. 各语言/库的默认指纹（UA 为可验证的已知值；JA3/JA4/H2 需实测）
### Python
| 库 | 默认 User-Agent | 备注 |
|---|---|---|
| `requests`（urllib3） | `python-requests/<ver>` | 最常见自研扫描器底座；默认 `Accept-Encoding: gzip, deflate`、`Accept: */*`、`Connection: keep-alive` |
| `urllib3` 直接用 | `python-urllib3/<ver>` | |
| 标准库 `urllib` | `Python-urllib/3.x` | |
| `aiohttp` | `Python/3.x aiohttp/<ver>` | 异步高并发扫描常见 |
| `httpx` | `python-httpx/<ver>` | |
| `pycurl` | `curl/<ver>` | 实际是 libcurl |
| `scapy` | 无（原始包） | 自造 SYN/UDP 探针，靠 TCP/协议异常判定 |

### Go
| 库 | 默认 User-Agent | 备注 |
|---|---|---|
| `net/http`（HTTP/1.1） | `Go-http-client/1.1` | 大量 Go 扫描器（nuclei/httpx/katana 等）默认或曾默认 |
| `net/http`（HTTP/2） | `Go-http-client/2.0` | |
| ProjectDiscovery `httpx`/`retryablehttp` | 常为自定义或 `httpx/<ver>` | 与 Go TLS 指纹叠加 |
- Go 的 **请求头写入顺序**较固定（Host、User-Agent，再按 key 排序），是 L2 强特征。
- Go `crypto/tls` 的 ClientHello（套件/扩展/曲线/ALPN）在版本内**高度稳定**，JA3/JA4 强可辨（需按 Go 版本实测）。

### Rust
| 库 | 默认 User-Agent | 备注 |
|---|---|---|
| `reqwest` | **通常不设 UA（空）**（待验证） | rustls 或 native-tls 后端 |
| `hyper` / `ureq` / `surf` | 常不设默认 UA | |
- Rust `rustls` 的 ClientHello 很独特（套件/扩展顺序），**JA3/JA4 强特征**；hyper 的 **HTTP/2 SETTINGS/伪头顺序**亦独特。

### C / C++
| 库 | 默认 User-Agent | 备注 |
|---|---|---|
| `libcurl` | `curl/<ver>` | 极常见；头顺序 Host/User-Agent/Accept… |
| `libcurl` + OpenSSL | — | JA3/JA4 随 OpenSSL 版本；与 Requests 同源 OpenSSL 可能接近 |
| 原始 socket / libnet / libpcap | 无 | 伪造任意包；靠 TCP/协议异常、无正常客户端特征 |

## 3. 常见自研扫描技术栈 → 可检测点
- **Python `requests` 批量探测**：UA `python-requests/*` + 缺浏览器头 + 高频多 URI → 高置信"脚本扫描"。
- **Go 自研（net/http 或 PD 库）**：`Go-http-client/*` 或 `httpx/*` + Go TLS JA3 + Go H2 指纹 → 强。
- **Rust reqwest/rustls**：无 UA/rustls JA3 + hyper H2 → 强（但对正常 Rust 服务也会命中，需行为佐证）。
- **libcurl 自研**：`curl/*` + 头顺序 → 中（正常运维脚本也用 curl）。
- **scapy/gopacket 原始扫描**：无 L7；靠 SYN 半开、端口序列、异常 TCP 选项 → 行为判定。

## 4. 在 app-id(Zeek) 中的落地
1. **建"客户端库指纹库"**（数据驱动，需实测）：
   - 记录每个库/版本的：默认 UA、默认头集合、头部顺序、JA3/JA4、HTTP2 指纹。
   - 用受控样本采集（见 §6）。
2. **Zeek 观测点**：
   - L1：`http_request` 的 `user_agent`（`http.log`）。
   - L2：签名层对原始请求头做顺序/大小写匹配（`signatures/*.sig`；或脚本读 headers）。
   - L3：`ssl` 的 **JA3/JA3S**（Zeek 有；JA4 是否内置需按 9.0.1 核验）。
   - L4：HTTP/2 指纹（**Zeek 9.0.1 无 HTTP/2 分析器**，无法获取 SETTINGS/伪头顺序；需 Suricata/外部插件）。
   - L5：`conn`/`SumStats`（多端口扫描、404/403 突发、URI 广度）。
3. **判定**：`库指纹(脚本客户端) + 扫描行为` → `app=CustomScanner`/`category=scanner`；再叠加具体工具 UA 才能定到具体工具。

## 5. 零误报策略（关键）
- **库指纹 ≠ 扫描器**：`python-requests`、`Go-http-client`、`curl` 也是大量**正常业务/运维**在用。单独命中只能标 `client_lib`（线索），**不能**标"扫描器"。
- 精确判定需满足 **库指纹 + 行为** 之一组：
  - 短时高频请求（同源） + 多 URI/多目录（404/403 比例高）；
  - 多端口短命连接（扫描）；
  - 缺浏览器常规头（`Accept-Language`/`sec-ch-ua`/Cookie）且 UA 为库默认；
  - 请求路径呈字典/枚举特征。
- 维护**白名单/基线**：已知业务服务、监控/健康检查、CI、CDN 回源等。
- 明确区分输出：`client_lib=<requests|go|curl|rustls…>` 与 `scan_verdict=true/false`，避免把"客户端库"误报成"扫描器"。

## 6. 采集/实验方法（保证指纹可信）
- 对每个库/版本各写一个最小客户端/扫描样例，在受控环境跑并抓包：
  - Python: requests / urllib / aiohttp / httpx / pycurl / scapy
  - Go: net/http(1.1/2) / PD retryablehttp；记录 Go 版本
  - Rust: reqwest(rustls/native-tls) / hyper / ureq
  - C: libcurl(各 OpenSSL 版本) / 原始 socket
- 用 Zeek 9.0.1 提取 `http.user_agent`、头部顺序、`ssl.ja3/ja3s`、H2 指纹，生成**版本化指纹表**（库→指纹）。
- 回归：把正常业务流量作为负样本，验证 FPR≈0。

## 7. 局限/对抗
- **UA 可伪造**；`curl-impersonate`、Go `utls`、`ja3` 伪装等可模仿浏览器 TLS/H2 → 库指纹可被规避。
- 同一库被正常业务与扫描器共用 → 库指纹天然有假阳；**必须靠行为收敛**。
- 因此：**无法保证 0 漏报**；对"精确识别"只能做到"库指纹+行为"的**近零误报**，并接受定向伪装导致的漏报。

## 8. 待验证（Zeek 9.0.1）
- Zeek 9.0.1 的 JA3/JA4 字段可得性（`ssl.log`/脚本字段名）。
- HTTP/2：Zeek 9.0.1 **无 HTTP/2 分析器**，SETTINGS/伪头顺序不可得（需 Suricata/外部插件）。
- 各库各版本的 JA3/JA4/H2 具体值（须实测，不做臆测）。
