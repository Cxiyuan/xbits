# 桌面「应用识别」库 · 威胁识别可用性分析

> 来源：`C:\Users\sona\Desktop\应用识别`（深信服 AF 应用识别库，已解密/解包）。
> 目的：评估其中**哪些规则可用于本项目的“威胁识别”**。
> 结论先行：**这是一个“应用识别（app-id）”库，不是 IPS/威胁特征库**。绝大多数是应用分类（游戏/视频/IM/OA…），**用于威胁识别的高价值部分是少数“威胁相关类别”子集**，尤其是 **木马控制(RAT/C2) 73 条、代理工具(VPN/翻墙/隧道) 186+58 条、远程登录(远控) 144 条**。

## 1. 目录与文件清单（可用性分级）
| 路径 | 内容/格式 | 规模 | 威胁识别可用性 | 建议 |
|---|---|---|---|---|
| `00_原始库/app/contchkprivate.inf` | 应用识别规则块（`[N]` 键值：App/Type/Proto/DstPort/Range/Ct0..Ct9 字节指纹 等），**明文元数据 + FRC4 密文模式** | 9,226 规则 | **中（仅威胁类别子集高）** | 只抽 `Type=木马控制/代理工具/远程登录` 子集转签名 |
| `01_解密后/app/contchkprivate.inf` | 同上，**Ct/端口/范围已解密** | 9,226 规则 | **中（同上，且可直接取指纹）** | 威胁子集首选数据源 |
| `00_原始库/app/contchkspec.inf` | 应用类型/应用元数据（TypeName/App/Desc） | 73k 行 | 低（元数据） | 用于名称/类别映射 |
| `00_原始库/app/dfa_reg.ini` / `04_Zeek迁移/af_dfa_regex.csv` | DFA 正则（`app_ua`/`app_host`/`extern_key`） | 296 条 | 低-中（app-id；少量风险应用） | 并入 app-id 的 UA/Host 匹配 |
| `00_原始库/app/https_app.conf` / `04_Zeek迁移/af_https_apps.csv` / `af_sni.zeek` | HTTPS/SNI 域名→应用（376 域名/51 应用） | 376 | 低（app-id，非威胁） | 并入 app-id 的 SNI 表 |
| `00_原始库/app/proxytoolrules.json` | **代理/VPN/翻墙工具**规则（窗口标题/签名/appId） | 58 工具 | **高（代理/翻墙/隧道）** | 转“代理工具名单/特征”，网络侧结合 SNI/行为 |
| `00_原始库/app/proxycheck.ini` | 代理检测（IP/URL/DFA/UDP 特征） | 475 行 | 中（代理检测） | 参考其 URL/DFA 特征思路 |
| `00_原始库/app/l7protocol.ini` / `af_l7_map.csv` | L7 协议 id→名 | 102 种 | 低（协议识别） | app-id/协议标注 |
| `00_原始库/app/howto.rule(.11x)` | 类别/应用“升级/迁移”映射（old→new） | 22k 行 | **无** | 版本升级用，忽略 |
| `00_原始库/app/wireless_ua_rule_*.ini`、`wireless_url_rule_*.ini`、`c_reg.ini`、`model_file.inf`、`urltype_to_apptype.conf`、`packapprule.ini`、`rulesorder.inf` | **终端型号/设备识别、UI 分组、型号命名** | — | **无** | 与本项目威胁识别无关 |
| `02_清单与统计/*.csv` | 清单/类别统计 | 9,226/39 类 | 低 | 索引/统计参考 |
| `04_Zeek迁移/` | **整库已迁移到 Zeek**：`af_appid.sig`(22,133 签名)、`af_sni.zeek`(376)、`af_dfa_regex.csv`(296)、`af_app_meta.csv`(9,226)、`af_l7_map.csv` | 大 | **中（app-id 可直接复用；威胁仅取子集）** | 作为 app-id 数据源；威胁只取类别子集，避免 22k 签名性能/误报 |
| `03_应用库升级包_解密/` | 升级包解包（与上重复） | — | 低 | 忽略（重复） |

## 2. 可直接用于“威胁识别”的子集（核心结论）
从 `01_解密后/app/contchkprivate.inf`（9,226 条）按 `Type` 统计，**威胁/规避相关类别**如下：

| 类别 | 规则数 | 应用数 | Ct 字节指纹数 | 威胁价值 | 说明 |
|---|---|---|---|---|---|
| **木马控制（RAT/C2）** | **73** | 67 | **92** | **高** | Gh0st、BackOrifice、NetBus、ProRat、XtremeRAT、Schwarzesonne、ZXshell、上兴远控、波尔远程、暗组远控、FreeRat… 典型远控木马协议 |
| **代理工具（VPN/翻墙/隧道）** | **186** | 114 | **364** | **高** | ngrok、frp、NATAPP、NPS、Psiphon、Tor、ShadowsocksR、ExpressVPN、OpenVPN、WireGuard 类等 |
| **远程登录（远控，双用）** | **144** | 52 | **283** | **中** | TeamViewer、AnyDesk、ToDesk、RustDesk、VNC、Radmin、Ammyy、LogMeIn… 合法运维/也可被滥用 |
| P2P / P2P流媒体 | 71 / 196 | 26/58 | 135/492 | 低（策略） | 非威胁，合规/带宽策略用 |
| 网络协议 | 162 | 103 | 205 | 低 | 协议识别 |

**附：proxytoolrules.json（58 个翻墙/代理工具）**
Psiphon、Freegate(自由门)、Ultrasurf(无界)、Tor Browser、ShadowsocksR、OpenVPN、ExpressVPN、ProtonVPN、TunnelBear、Surfshark、Windscribe、Nord?、SoftEther、WireGuard(部分)、ngrok? 等（含 appId/窗口标题/厂商签名）。窗口标题/进程签名属**终端侧**特征；网络侧可用其 appId 对应的流量/SNI/行为。

## 3. 数据格式与转换要点（落到本项目的可行性）
`contchkprivate.inf` 每条规则形如：
```
[N]
App = 暗组远控        Type = 木马控制      Proto = 6
DstPort = 0          Range = 10 256
CtCnt = 1
Ct0 = 1 Z 0 0 4D41494E494E464F7C      ; 形如 <启用> <方向Z/D/S> <offset> <len?> <hex 字节>
```
- **Ct = 应用层字节指纹（offset + hex）**，可按 `offset/depth` 转 **Suricata content** 或 **Zeek payload 签名**；与 TCP/UDP/端口/Range 组合使用。
- 我们的 Zeek `.sig` `payload` 正则**隐式锚定 payload 首字节**（见 `sig-coverage-analysis.md`）：Ct `offset=0` 可直接 `payload /^<hex转义>/`；`offset>0` 需前置字节类或改用分析器脚本读 payload；**协议起始类（RAT 自定义协议）多从 offset 0 开始，最易转**。
- 加密流量（TLS/H2）看不到明文 Ct → 需 SNI/JA3/行为（本库的 SNI/UA/DFA 可辅助）。

## 4. 建议的落地方式（本项目）
1. **抽取“木马控制”子集**（73 规则/92 指纹）→ 生成 `app-id/威胁规则/rat.sig`（Zeek）与可选 Suricata 规则；配合 CI 正/负样本回归（优先，最高价值）。
2. **抽取“代理工具”子集**（186 规则/364 指纹）+ `proxytoolrules.json`(58) → 生成 `app-id/威胁规则/proxy_tools.sig` / 名单表，用于翻墙/代理/隧道检测（结合 SNI/ja3/行为）。
3. **“远程登录”子集**（144/283）→ 生成“远控工具识别”表，用于**异常/非授权远控**告警（双用，需白名单运维工具）。
4. **app-id 增强**：把 `af_https_apps.csv`(376 SNI)、`af_dfa_regex.csv`(296)、`af_l7_map.csv` 并入 `app-id/mapping/`（非威胁，但为“P2P/代理/远控”类上下文判定提供依据）。
5. **不要直接整包加载 `04_Zeek迁移` 的 22,133 条签名**：体积大、短指纹误报高、且多为普通应用；**只取威胁类别子集**。

## 5. 风险与注意事项
- **这是 app-id 库，不是攻击/漏洞/样本库**：`木马控制` 是“远控协议识别”，对**新变种/加密远控**可能漏报；不含 CVE/exploit/malware hash。
- **Ct 指纹偏短（2–16 字节）**：必须叠加 `offset/方向/端口/Range` 约束 + 白名单，否则误报高（例如正常流量恰含短字节）。
- **加密流量不可见**：需 SNI/JA3/行为补足。
- **合规**：数据来自设备解密库，使用/分发需确认授权与许可。

## 6. 规模速查
- 应用规则：**9,226 条 / 4,057 应用 / 39 类**；Zeek 迁移签名 **22,133 条**；SNI **376**；DFA **296**；L7 协议 **102**。
- 威胁相关可直接提取：**木马控制 73（92 指纹）＋ 代理工具 186（364 指纹，另 58 工具名单）＋ 远程登录 144（283 指纹）**。
