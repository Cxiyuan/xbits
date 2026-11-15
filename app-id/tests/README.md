# 扫描工具识别 · 测试与回归

在 **Zeek 9.0.1** 下回放自造 PCAP，验证 `app-id/扫描工具/*.sig` + `scan.zeek` 的**检出率 / 误报率**。

## 组成
- `gen_pcaps.py`：用 scapy 生成正/负样本 PCAP 到 `pcaps/`，并写 `manifest.json`（每条用例的期望 verdict/tool）。
- `run_tests.py`：逐条 PCAP 用 `zeek -C -r <pcap> app-id/scripts/__load__.zeek` 回放，解析 `scan_report.log`，统计检出率/FPR；有漏报或误报则退出码 1。
- `pcaps/`、`manifest.json`：生成产物（不入库时可在 CI 现生成）。

## 本地/容器运行
```bash
pip install scapy
python3 app-id/tests/gen_pcaps.py
python3 app-id/tests/run_tests.py
# => 正样本检出率 x/x；负样本误报率 y/y；全部通过则 PASS
```

## 用例设计
- **正样本**：各品牌 UA 工具单请求（B+ 字面自证）、nmap NSE UA、nmap FourOhFour 探针、nmap 探针序列(≥2 TierB)、目录爆破(25 个 404 URI)、端口扫描(SYN 12 端口)。
- **负样本**：浏览器多 URI、curl、python-requests 正常、健康检查(无 UA)、Go 客户端。

## CI
`.github/workflows/app-id-scan.yml`：`zeek/zeek:9.0.1` 容器内装 scapy → 生成 PCAP → 回放断言；用于持续验证识别能力与误报率（目标 FPR≈0）。

## 最近实测结果（CI）
- 正样本检出率：**47/47 = 100%**
- 负样本误报率：**0/5 = 0%**
- 覆盖：44 个 UA 工具单请求 + nmap(NSE UA/FourOhFour/探针序列) + 目录爆破 + 端口扫描；负样本：浏览器/curl/python-requests/健康检查/Go。
