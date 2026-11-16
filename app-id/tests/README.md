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
- **正样本**：各品牌 UA 工具单请求（B+ 字面自证）、nmap NSE UA、nmap FourOhFour 探针、nmap 探针序列(≥2 TierB)、目录爆破(25 个 404 URI)、端口扫描(SYN 12 端口)、**DNS PTR 反查(25)**、**低速慢扫(100 URI 跨 50 分钟)**、**TLS ClientHello 指纹(JA3-lite)**。
- **负样本**：浏览器多 URI、curl、python-requests 正常、健康检查(无 UA)、Go 客户端。
- 每条 PCAP 会校验并输出 `sig-hit`：**UA 用例中由明文 `.sig` 触发的数量**。经实测 Zeek `.sig` 的 `payload` 正则隐式锚定首字节，对请求头中段的 `User-Agent:` **不触发**（sig-hit=0/42，属已知限制）；UA 识别实际由脚本层 `http_header`/`ua_to_tool` 覆盖，sig-hit 仅作持续观测指标。

## 近期新增
- `run_http_fields.py`：验证 HTTP 扩展字段（完整头/Cookie/Auth/Query/表单/JSON/XML/Body 片段）落 `http.log`。扩展逻辑**直接内置在 `source/xbits-zeek/scripts/base/protocols/http/main.zeek`**（不新建脚本/日志）；CI 通过把该 `main.zeek` 覆盖到 stock Zeek 9.0.1 镜像进行验证。
- `gen_pcaps.py` 额外生成 `pcaps/http_fields.pcap`（urlencoded/JSON/XML/multipart 请求 + Set-Cookie/JSON/XML 响应）。

## CI
`.github/workflows/app-id-scan.yml`：`zeek/zeek:9.0.1` 容器内装 scapy → 生成 PCAP → 回放断言；用于持续验证识别能力与误报率（目标 FPR≈0）。

> 告警通道校验：每次回放断言 **notice/signatures/weird/intel 默认告警日志必须为空**（已被 `xbits_alert.zeek` 禁用），且告警只能出现在 **`xbits_alert.log`**（测试注入 `redefs/xbits_alert_reg.zeek` 注册 `scanner` 类别）。

## 最近实测结果（CI）
- 正样本检出率：**47/47 = 100%**
- 负样本误报率：**0/5 = 0%**
- 覆盖：44 个 UA 工具单请求 + nmap(NSE UA/FourOhFour/探针序列) + 目录爆破 + 端口扫描；负样本：浏览器/curl/python-requests/健康检查/Go。
