# 扫描工具签名（Zeek Signature）

本目录存放各类扫描工具的 Zeek 签名（`.sig`），由 `__load__.zeek` 统一 `@load-sigs`，被 `app-id/scripts/appid/scan.zeek` 消费。

## 分层
- **Tier A（品牌/确定字面 UA 或探针）**：可“字面自证”（B+ 模型下单发也可判）。
- **Tier B（弱线索）**：仅旁证，不单独判定（如 nmap 通用 HTTP/1.0 探针）。
- 无独特 UA 的工具（masscan/zmap/naabu/rustscan 等）主要靠 `scan.zeek` 的**行为**（端口扫描/目录爆破）识别。

> 重要限制（实测）：Zeek `.sig` 的 `payload` 正则**隐式锚定 payload 首字节**，对位于**请求头中段**的 `User-Agent:` **不触发**（即使加前导字符类）。因此 **UA 工具识别以 `scan.zeek` 的 `http_header`→`ua_to_tool()` 为准**（覆盖 HTTP/1.x/2）；本目录 `.sig` 主要用于**流首探针**（nmap FourOhFour/TierB 等）及其它引擎/场景。

## 当前覆盖（44 个 .sig）
- 目录/参数爆破：ffuf、gobuster、feroxbuster、dirbuster、arjun、wfuzz、kiterunner
- 漏洞/WEB 扫描：sqlmap、nuclei、nikto、wpscan、w3af、wapiti、arachni、skipfish、dalfox、xsstrike、commix、wafw00f
- 商业/综合漏扫：acunetix、nessus、openvas、netsparker、appscan、webinspect、qualys、nexpose、appspider
- CMS：wpscan、joomscan、droopescan、cmseek
- 指纹/探测：whatweb、httpx、arjun
- 测绘：shodan、censys、expanse、l9explore、zgrab
- 端口：nmap、masscan（masscan 默认不发 UA，主要靠行为）
- TLS 扫描：testssl、sslscan
- 老式脚本：zmeu、morfeus
- 其它：nmap 探针 DPI

> 完整覆盖分析与缺口（含无 UA 工具的 TLS/行为层）见 `docs/sig-coverage-analysis.md`。

## 新增签名
1. 在 `签名` 中用 `payload` 锚定 `User-Agent:` 品牌字面（词边界防子串误报）或探针 payload；
2. `event "scanner_ua_<tool>"`（UA）或 `nmap_tierA_*` / `nmap_tierB_*`（探针）；
3. 运行 `__load__.zeek` 自动加载；同步在 `scan.zeek` 的 `ua_to_tool()` 添加同一品牌 token（覆盖 HTTP/2）。
