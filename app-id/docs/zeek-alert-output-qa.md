# 深度 QA：Zeek 告警输出是否已全部清除 + 唯一出口 XbitsAlert

> 目标：证明 `xbits-zeek` 的**所有告警输出**已被禁用，且现网告警**只能**通过 `XbitsAlert`（注册制）输出。

## 1. 全量日志流清单（Zeek 9.0.1 `Log::create_stream` 全枚举）
对 `scripts/base` + `scripts/policy` 全量抽取 `$path=` 共 **66 个日志流**，按性质分类：

| 分类 | 日志流 | 是否“告警” | 处理 |
|---|---|---|---|
| **告警型（必须禁用）** | `notice`、`notice_alarm`、`signatures`、`weird` | 是 | **已 `Log::disable_stream`** |
| **情报命中** | `intel` | 是（情报命中告警） | **已禁用** |
| 动作日志（非告警） | `packet_filter`、`netcontrol`、`netcontrol_drop`、`netcontrol_shunt`、`netcontrol_catch_release`、`openflow` | 否（是执行动作记录） | 保留；且已清 `ACTION_DROP` |
| 诊断/运行指标 | `reporter`、`capture_loss`、`stats`、`loaded_scripts`、`analyzer`、`analyzer_debug`、`broker`、`cluster`、`config`、`telemetry`、`telemetry_histogram` | 否 | 保留（排障用） |
| 资产/软件 | `software`、`known_hosts`、`known_services`、`known_certs`、`known_modbus` | 否 | 保留 |
| 协议/内容日志 | `conn`、`dns`、`http`、`ssl`、`x509`、`files`、`ftp`、`smtp`、`ssh`、`smb_*`、`dce_rpc`、`ldap*`、`mqtt_*`、`mysql`、`postgresql`、`quic`、`radius`、`rdp`、`redis`、`rfb`、`sip`、`snmp`、`socks`、`syslog`、`traceroute`、`tunnel`、`unknown_protocols`、`websocket` 等 | 否（原始协议日志） | 保留 |

> 结论：**真正“告警型”的只有 `notice / notice_alarm / signatures / weird / intel` 五类**，均已禁用；其余为动作/诊断/协议日志，不属于告警。

## 2. 禁用实现（不改 vendor 源码）
`app-id/scripts/appid/xbits_alert.zeek`：
- `zeek_init &priority=-100`（晚于 base 建流）执行
  `Log::disable_stream(Notice::LOG / Notice::ALARM_LOG / Signatures::LOG / Weird::LOG / Intel::LOG)`；
- 兜底 `hook Notice::policy(n)` 删除 `ACTION_LOG/ACTION_EMAIL/ACTION_ALARM/ACTION_DROP/ACTION_PAGE`，即使流被重新开启也不外发、不投递、不丢包；
- 说明：`Signatures::actions` 默认 `SIG_ALARM` 会写 `signatures.log` 并产生 NOTICE —— 因两类输出均被禁用而静默。

## 3. 唯一告警出口：XbitsAlert（注册制）
```zeek
redef XbitsAlert::registered += { "scanner" };   # 注册允许输出的告警类别
XbitsAlert::emit(kind, name, severity, src, evidence);  # 唯一出口 → xbits_alert.log + event alert
event XbitsAlert::alert(info: XbitsAlert::Info) { ... }  # 下游订阅
```
- 仅 `kind in registered`（或 `allow_all=T`）才输出；`scan.zeek` 已改为 `XbitsAlert::emit("scanner", ...)`。
- **未注册则不输出**（已由 CI 门控测试验证）。

## 4. 防漏验证设计（CI）
`app-id/tests/run_tests.py` 每条 PCAP 回放后断言：
1. **文件级黑名单**：工作目录中任何匹配 `^(notice|signatures?|weird|intel|alarm)` 且非空的文件 → `ALERT-LEAK` 失败；
2. **主动 Notice 探针**：`redefs/notice_leak_probe.zeek` 在每个连接 `connection_state_remove` 主动 `NOTICE(...)`；若禁用失效，`notice.log/notice_alarm.log` 必有内容 → 失败；
3. **签名泄漏控制**：测试含 nmap 探针（会命中 `.sig`、默认 `SIG_ALARM`），要求 `signatures.log` 必须为空；
4. **注册门控**：对同一 PCAP 在**不注册** `scanner` 的情况下运行，断言 **不产生 `xbits_alert`**；注册后才输出；
5. 正样本必须出现 `xbits_alert.log` 记录（告警只经该接口）。

## 5. 残余“非告警”输出（保留，需知悉）
- `reporter.log`：脚本错误/警告诊断（非业务告警）；如需彻底静默可再加 `Log::disable_stream(Reporter::LOG)`。
- `capture_loss.log`、`stats.log`：运行指标。
- `packet_filter.log`/`netcontrol*.log`/`openflow.log`：动作日志；`ACTION_DROP` 已清除，默认不会产生。
- `stdout`：仅 supervisor 启动失败等系统级错误（`boot.zeek` 的 `print`），非业务告警。

## 7. CI 实测（提交 `d02bae7`，run 43806240246，success）
- `DET=50/50`、`FPR=0/5`；
- **无 `ALERT-LEAK`**：每条 PCAP 都有**主动 Notice 探针**触发 NOTICE，但 `notice*/signatures*/weird*/intel*/alarm*` 文件均未产生；nmap 探针命中签名也未产生 `signatures.log`；
- **无 `NO-ALERT`**：正样本告警均出现在 `xbits_alert.log`；
- **`REG-GATE` 通过**：未注册 `scanner` 时不产生 `xbits_alert`，注册后才输出——证明“告警只经 XbitsAlert 注册接口”。

## 8. 结论
- **告警型输出（notice/notice_alarm/signatures/weird/intel）已全部清除**；
- **告警唯一出口为 `XbitsAlert`（注册制，写 `xbits_alert.log` 并触发 `XbitsAlert::alert` 事件）**；
- 动作/诊断/协议日志保留（非告警），符合“告警只经 XbitsAlert”的要求。
