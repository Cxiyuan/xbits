# xbits-zeek 默认告警输出禁用 + 统一告警接口

> 目标：分析 `xbits-zeek`（Zeek 9.0.1）**当前会默认输出“告警”的所有事件/日志**，全部禁用；之后**告警只经一个特定接口注册并输出匹配的告警事件**。

## 1. Zeek 默认“告警类”输出来源（分析结论）
| 输出文件 | 框架/脚本 | 产生方式 | 默认行为 | 关闭方式 |
|---|---|---|---|---|
| `notice.log` | `base/frameworks/notice/main.zeek` | 各脚本 `NOTICE(...)`（全库 **70 处**调用） | 默认动作含 `ACTION_LOG` → 写 notice.log | `Log::disable_stream(Notice::LOG)` + 清 `ACTION_LOG/EMAIL/ALARM` |
| `notice_alarm.log` | Notice 框架 | `ACTION_ALARM` 类型 | 未默认开启（`alarmed_types` 为空） | `Log::disable_stream(Notice::ALARM_LOG)` |
| `signatures.log` | `base/frameworks/signatures/main.zeek` | 签名命中（含本项目 `扫描工具/*.sig`） | `Signatures::actions` 默认 **SIG_ALARM** → 写 signatures.log + NOTICE | `Log::disable_stream(Signatures::LOG)`（+ Notice 抑制） |
| `weird.log` | `base/frameworks/notice/weird.zeek` | 协议异常（weird，默认动作表大量 `ACTION_LOG`） | 写 weird.log | `Log::disable_stream(Weird::LOG)` |
| `intel.log` | `base/frameworks/intel/main.zeek` | Intel 情报命中 | 写 intel.log | `Log::disable_stream(Intel::LOG)` |
| `reporter.log` | `base/frameworks/reporter/main.zeek` | 脚本错误/警告诊断 | 写 reporter.log（**非告警**，保留用于排障） | （保留） |

### 默认加载关系
- `base/init-default.zeek` 默认加载 `base/frameworks/{notice,signatures,reporter,intel,sumstats,...}`，因此上述 notice/signatures/weird/intel 框架**开箱即用并会输出**。
- `site/local.zeek` 默认 `@load` 了一批会产生 **notice** 的策略脚本，例如：
  `misc/capture-loss`、`frameworks/software/vulnerable`、`frameworks/software/version-changes`、`protocols/dns/detect-external-names`、`protocols/ftp/detect`、`protocols/ssl/validate-certs`、`protocols/ssh/detect-bruteforcing`、`protocols/http/detect-sql-injection`、`frameworks/files/detect-MHR`、`misc/stats` 等。
- `NOTICE()` 调用最多的脚本（Top）：`policy/protocols/ssl/heartbleed.zeek(10)`、`policy/frameworks/analyzer/detect-protocols.zeek(6)`、`base/frameworks/signatures/main.zeek(5)`、`policy/protocols/ssl/weak-keys.zeek(5)`、`base/frameworks/notice/main.zeek(4)`、`policy/frameworks/packet-filter/main.zeek(3)`、`policy/protocols/ssl/expiring-certs.zeek(3)` 等。

> 结论：**默认“会告警输出”的日志是 notice.log / notice_alarm.log / signatures.log / weird.log / intel.log 共 5 类**（reporter.log 属诊断，不在此列）。

## 2. 已实现的禁用方案（只改脚本，不动 vendor 源码）
新增 `app-id/scripts/appid/xbits_alert.zeek`，在 `zeek_init &priority=-100`（晚于 base 建流）执行：
```zeek
Log::disable_stream(Notice::LOG);
Log::disable_stream(Notice::ALARM_LOG);
Log::disable_stream(Signatures::LOG);
Log::disable_stream(Weird::LOG);
Log::disable_stream(Intel::LOG);
```
并加兜底 `hook Notice::policy(n: Notice::Info)` 删除 `ACTION_LOG/ACTION_EMAIL/ACTION_ALARM`，即使流被重新开启也不外发。
这样：**所有默认告警日志不再产生**；`Signatures::actions` 的默认 SIG_ALARM 也因 signatures.log/notice 均被抑制而无输出。

## 3. 统一告警接口（唯一出口）
`module XbitsAlert` 提供：
```zeek
global registered: set[string] &redef;      # 允许输出的告警类别（需注册）
global register: function(kind: string);
global emit: function(kind: string, name: string, severity: string, src: addr, evidence: string);
global alert: event(info: Info);            # 下游可订阅
# 输出文件：xbits_alert.log（Info: ts/kind/name/severity/src/evidence）
```
- **只有 `kind in registered`（或 `allow_all=T`）才输出**——即“只输出注册匹配的告警事件”。
- 下游注册示例：`redef XbitsAlert::registered += { "scanner" };`
- 下游订阅示例：`event XbitsAlert::alert(info: XbitsAlert::Info) { ... }`
- 本项目 `scan.zeek` 的扫描判定已改为调用 `XbitsAlert::emit("scanner", tool, sev, src, evid)`。

## 4. 验证（CI）
`app-id/tests/run_tests.py` 现断言：
1. 每次回放后 **`notice.log/notice_alarm.log/signatures.log/weird.log/intel.log` 不存在或为空**（默认告警已禁用）；
2. 正样本必须出现 **`xbits_alert.log`** 记录（告警只经该接口输出）；
3. 负样本不得出现在 `scan_report.log`；
测试统一注入 `app-id/tests/redefs/xbits_alert_reg.zeek`（注册 `scanner`）。

**CI 实测（提交 `8e7e9fb`，run 43801460476，success）**：`DET=50/50`、`FPR=0/5`；`notice.log/notice_alarm.log/signatures.log/weird.log/intel.log` **均未产生**（默认告警已禁用），正样本告警仅出现在 **`xbits_alert.log`**（注册制接口）。

## 5. 影响与注意
- 关闭 notice.log 会**同时静默** `site/local.zeek` 策略脚本（暴力破解、证书错误、SQLi、软件漏洞等）的默认告警。若仍需这些情报，应在 `XbitsAlert` 接口中**重新接线**（例如订阅 `Notice::log_notice`/`Notice::policy` 或各自事件，筛选后调用 `XbitsAlert::emit`）。
- 未改 vendor 源码，仅用 `Log::disable_stream` + `Notice::policy` hook，升级 Zeek 不受影响。
- 保留 `reporter.log` 用于排障；如需也可 `Log::disable_stream(Reporter::LOG)`。
