# app-id/扫描工具 —— 扫描工具识别（DPI 签名/规则）

当前内容：
- `nmap.sig`：Nmap 探针的 Zeek 签名（Tier A 直判 + Tier B 组合线索）。
- `__load__.zeek`：`@load-sigs ./nmap.sig`，供包加载。

分层约定（详见 `../docs/nmap-dpi.md`）：
- **Tier A**（`nmap_tierA_*`）：Nmap 固有字面/指纹，命中即可判定 `Nmap`。
- **Tier B**（`nmap_tierB_*`）：强线索，需在 `scripts/appid/nmap.zeek` 中结合
  "无 Host/UA""多探针""扫描行为"等组合后再判 `Nmap`。
- **Tier C**（`nmap_tierC_*`，后续补）：仅作证据，禁止单独判定。

后续：
1. `app-id/scripts/appid/nmap.zeek`：消费 `signature` 事件（按 `s$event` 归类），
   叠加 HTTP UA/无 Host、TLS JA3、DNS version.bind、扫描行为打分，达阈值调用
   `XbitsAppId::note_app(c, "Nmap", "scanner", evidence, confidence)`。
2. 用 Nmap 真实流量（`-sS`/`-sV`/NSE）抓 PCAP，在 Zeek 9.0.1 做正/负样本回归。
3. 校验 Zeek 9.0.1 对 `payload` 正则中 `\r\n` / `\x00` 的支持，再补 Tier C 与二进制探针。
