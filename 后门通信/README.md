# 后门通信（Suricata 8.0.8）

本场景包含两个规则文件：

- `WebShell后门通信规则.rules`：WebShell 文件访问、命令参数、响应确认、管理工具 UA；
- `命令与控制信标规则.rules`：HTTP C2 信标、C2 面板 API、请求头异常、响应任务下发。

## 文件

- Lua：`lua/webshell_*.lua`、`lua/c2_*.lua`
- 分析：
  - `规则质量与误报分析.md`
  - `命令与控制信标规则质量与误报分析.md`
- 测试：`../test/generate_backdoor_pcaps.py`、`../test/backdoor_cases.json`

## 1. 规则与分级

| SID | 内容 | tier |
|---|---|---|
| 9104001 | 已知 WebShell 文件名访问（线索） | triage |
| 9104002 | URI/Body/Cookie/Header 命令参数与值语义 | alert |
| 9104003 | 响应确认命令输出/文件管理/错误回显 | alert |
| 9104004 | WebShell 管理工具 UA | telemetry |
| 9110001 | 实证 C2 GET 样本 + 固定 UA | alert |
| 9110002 | a/f/t/p URI 结构变体 | triage |
| 9110003 | 旧浏览器 UA（Win7 + Firefox 48） | telemetry |
| 9110004 | 信标 URI + 多个请求头异常 | triage |
| 9110005 | C2 面板 API 多语义 token | triage |
| 9110006 | 单字母参数 + 空值/头异常 | triage |
| 9110007 | 响应 task/payload/command 下发 | triage |

## 2. 方向

```text
WebShell 请求  : $EXTERNAL_NET -> $HOME_NET
WebShell 响应  : $HOME_NET     -> $EXTERNAL_NET
C2 信标/面板   : $CLIENT_NET   -> $EXTERNAL_NET
C2 响应        : $EXTERNAL_NET -> $HOME_NET
```

不使用 `any any -> any any`。

## 3. WebShell 关键逻辑

- 9104001 只做已知文件名线索，不再直接 Critical；
- 9104002 修复原规则“参数名/值写反”的问题：
  - 检查 `cmd/exec/command/pass/z0/z1/z2` 等参数名；
  - 检查参数值中的命令/代码语义；
  - 支持 POST Body、Cookie、请求头；
  - `z0/pass` 等 base64 参数用纯 Lua 解码；
- 9104003 在响应侧检查：
  - `uid=`、`gid=`、`root:x:0:0`、`www-data`；
  - `Index of /`、`file manager`、`chmod`；
  - `eval()'d code`、`Fatal error`、`java.lang.Runtime`；
- 9104004 只是 UA 遥测，不单独告警。

## 4. C2 关键逻辑

- 9110001 保留实证样本，但方向改为出站；
- 9110002 允许 a/f/t/p 参数顺序变化，要求至少两个空值、p 为数字；
- 9110003 旧 UA 仅 telemetry；
- 9110004 要求信标式 URI + 至少两个请求头异常；
- 9110005 要求 C2 主体 token（client/beacon/panel/...）+ 动作 token；
- 9110006 要求单字母参数 + 空值/请求头异常；
- 9110007 响应侧要求至少两个 task/payload/command 语义标记。

## 5. 验证

```bash
python3 -m pip install scapy==2.6.1
python3 test/generate_backdoor_pcaps.py --out test/backdoor_pcap
suricata -T -c test/suricata-backdoor-ci.yaml
for pcap in test/backdoor_pcap/*.pcap; do
  name=$(basename "$pcap" .pcap)
  suricata -c test/suricata-backdoor-ci.yaml -r "$pcap" -l "test/out/suricata/$name" -k none
done
python3 test/assert_suricata.py --eve-root test/out/suricata --cases test/backdoor_cases.json
```

最终验证只认 `.github/workflows/suricata-backdoor-c2.yml`。
当前已验证：commit `d621e7f`，run `42384924560`，17/17 用例通过：
<https://github.com/Cxiyuan/ips/actions/runs/42384924560>。

## 6. 能力边界

1. **HTTPS 未解密**：看不到 URI/Body/Header；
2. **HTTP/2/HTTP/3**：`suricata.http` Lua API 以 HTTP/1 事务为主；
3. **加密 WebShell/C2**（Behinder/Godzilla AES）：无法解密，只能依赖参数名/响应/行为线索；
4. **Shiro rememberMe**：仅凭 Cookie 长度/熵不能可靠区分正常会话与加密 payload；
5. **信标周期/抖动**：规则内不做跨流聚合，交给 SIEM/NDR；
6. **SSRF/SSTI/Upload** 不在此场景；
7. 不承诺生产“零误报”，不虚构检出率/误报率。

## 7. Zeek 关联分析

- 脚本：`zeek/backdoor_c2_score.zeek`；
- WebShell 命令参数 + 响应确认、重复 C2 HTTP 信标；
- 输出 `backdoor_correlation.log`，含 `community_id` 与 `related_sids`；
- 与 Suricata EVE 的 `community_id` 关联；
- CI：backdoor workflow 内运行 Zeek 9.0.1 + community-id 断言，
  另跑 `c2_periodic.pcap` 验证周期聚合。
