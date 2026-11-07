# test · 测试与流量模拟

本目录只用于 CI 与本地预检，不属于检测逻辑。检测逻辑在
`DNS隧道与带外检测/`（Suricata 8.0.8）与 `zeek/`（Zeek 9.0.1）。

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
| `oob_positive.pcap` / `oob_negative.pcap` | `abc123.oast.pro` / 根域+短 token+MX | 命中/不命中 9109004 |
| `txt_burst_positive.pcap` / `txt_burst_negative.pcap` | 50 条子域 TXT / 50 条 `_dmarc` TXT | 命中/不命中 9109103 |
| `dot_positive.pcap` / `dot_negative.pcap` | TLS 853 + ALPN `dot` + DNS SNI / 无 ALPN + 非 DNS SNI | 命中/不命中 9109101 |
| `doh_positive.pcap` / `doh_negative.pcap` | POST `/dns-query` / POST `/api` + DoH Content-Type | 命中/不命中 9109102 |

## 3. CI 断言

- `cases.json`：Suricata 每个 PCAP 的 `require` / `forbid` SID。
- `assert_suricata.py`：解析 `eve.json`，断言 `alert.signature_id`。
- `zeek_cases.json`：Zeek 每个 PCAP 的 `require` / `forbid` notice 类型。
- `assert_zeek.py`：解析 `notice.log`，断言 `note` 字段。

## 4. 本地运行（预检，不作为最终验证）

本地预检需要精确版本：

```bash
# Suricata 8.0.8 + 完整规则/dataset/Lua
suricata -T -c test/suricata-ci.yaml
for pcap in test/pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/cases.json

# Zeek 9.0.1
for pcap in test/pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  mkdir -p "test/out/zeek/$name"
  (cd "test/out/zeek/$name" && zeek -b -Cr "$OLDPWD/$pcap" "$OLDPWD/zeek/dns_tunnel_detect.zeek")
done
python3 test/assert_zeek.py --log-root test/out/zeek --cases test/zeek_cases.json
```

**最终验证只认 GitHub Actions**：
- `.github/workflows/suricata-8.0.8.yml`
- `.github/workflows/zeek-9.0.1.yml`

本地结果仅作提交前预检；CI 未通过不得声称已验证。

## 5. 许可与安全

- 生成的 PCAP 只包含 RFC 5737/1918 地址与虚构域名，不含真实客户数据。
- 测试脚本不参与检测；检测逻辑只在规则/Lua/Zeek 内。
