# app-id/扫描工具 —— 扫描工具识别（DPI 签名）

本目录存放各扫描工具的 Zeek 签名（`.sig`），按 `@load-sigs` 加载。
统一由后续的 `scripts/appid/scan.zeek` 聚合判定（当前尚未实现）。

## 文件
- `nmap.sig`：Nmap 探针签名（Tier A 直判 + Tier B 组合线索）。
- `ffuf.sig`：ffuf（dirbrute，来源 SID 9101001；UA 特征 `Fuzz Faster U Fool`）
- `gobuster.sig`：gobuster（dirbrute，来源 SID 9101002；UA 特征 `gobuster/`）
- `feroxbuster.sig`：feroxbuster（dirbrute，来源 SID 9101003；UA 特征 `feroxbuster/`）
- `dirbuster.sig`：dirbuster（dirbrute，来源 SID 9101008；UA 特征 `DirBuster`）
- `sqlmap.sig`：sqlmap（vulnscan，来源 SID 9101004；UA 特征 `sqlmap/`）
- `nuclei.sig`：nuclei（vulnscan，来源 SID 9101005；UA 特征 `Nuclei`）
- `nikto.sig`：nikto（vulnscan，来源 SID 9101009；UA 特征 `Nikto/`）
- `wpscan.sig`：wpscan（vulnscan，来源 SID 9101010；UA 特征 `WPScan`）
- `acunetix.sig`：acunetix（commercial，来源 SID 9101007；UA 特征 `Acunetix`）（含 Acunetix 专用请求头签名）
- `nessus.sig`：nessus（commercial，来源 SID 9101015；UA 特征 `Nessus`）
- `openvas.sig`：openvas（commercial，来源 SID 9101016；UA 特征 `OpenVAS`）
- `whatweb.sig`：whatweb（fingerprint，来源 SID 9101018；UA 特征 `WhatWeb/`）
- `httpx.sig`：httpx（fingerprint，来源 SID 9101019；UA 特征 `httpx/`）
- `arjun.sig`：arjun（param，来源 SID 9101020；UA 特征 `Arjun/`）
- `wafw00f.sig`：wafw00f（waf，来源 SID 9101021；UA 特征 `wafw00f`）
- `commix.sig`：commix（cmdi，来源 SID 9101022；UA 特征 `commix`）
- `xsstrike.sig`：xsstrike（xss，来源 SID 9101023；UA 特征 `XSStrike`）
- `shodan.sig`：shodan（measurement，来源 SID 9101024；UA 特征 `Shodan/`）
- `censys.sig`：censys（measurement，来源 SID 9101025；UA 特征 `CensysInspect/`）
- `expanse.sig`：expanse（measurement，来源 SID 9101026；UA 特征 `Expanse/`）
- `l9explore.sig`：l9explore（measurement，来源 SID 9101027；UA 特征 `l9explore`）
- `zgrab.sig`：zgrab（measurement，来源 SID 9101014；UA 特征 `zgrab/`）
- `masscan.sig`：masscan（masscan，来源 SID 9101011；UA 特征 `masscan/`）
- `zmeu.sig`：zmeu（legacy，来源 SID 9101012；UA 特征 `ZmEu`）
- `morfeus.sig`：morfeus（legacy，来源 SID 9101013；UA 特征 `Morfeus`）
- `__load__.zeek`：加载目录内全部 `.sig`。

## 精度/零误报约定
- 所有签名均**限定在 `User-Agent:` 之后**匹配工具独有字面，避免子串泛滥（如 `httpx/` 前缀排除 `python-httpx`）。
- 这些属 **Tier A（工具独有 UA）**；后续 `scan.zeek` 再做统一打分/上下文校验，目标零误报。
- 通用脚本客户端（curl/wget/python-requests 等）**不**在扫描工具范围内，避免把正常开发流量误判为扫描器。
- 目标 Zeek 9.0.1；regex/加载需在 9.0.1 容器验证。
