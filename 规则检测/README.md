# 规则检测 · 消费源归档总览

规则按“哪个引擎消费 + 攻击类别”归档，不设厂商目录：

- `suricata/`：**签名命中规则 + 自研 Lua 增强**（`.rules`、场景 `lua/`、数据集 `.lst`）。
  自研 Lua 用于签名匹配/解码/结构判定，减少误报、提高精确度；每条 `lua:` 规则
  **必须已有 sticky buffer**（`lua:` 之前存在 buffer 关键词，V-13 前置；无 buffer 的规则
  不注入 lua，明细见 `docs/Lua强化拒绝.json`）。转换规则不注入 flowbits、depend/scope
  状态链——相关语义缺口在 `xbits/规则库元数据/semantic_gaps.json` 的 `ownership` 区
  声明接管方（suricata-rule / xbits-feature / dropped-document）与 CI 覆盖断言。
  - 自研场景：`DNS隧道与带外检测/`、`Web漏洞利用/`、`侦察与攻击工具指纹/`、`后门通信/`；
  - 外部探针转换规则按攻击类别归档，例如：
    - `Web攻击/SQL注入/`、`Web攻击/XSS/`、`Web攻击/WebShell/`、`Web攻击/命令注入/`、
      `Web攻击/文件上传/`、`Web攻击/信息泄露/`、`Web攻击/扫描器/`；
    - `恶意软件/木马/`、`恶意软件/后门/`、`恶意软件/C2与远控/`、`恶意URL/`；
    - `网络服务漏洞/`、`主机系统漏洞/`、`应用软件漏洞/`、`网络设备漏洞/`。
  - PVS 请求→响应成功确认、flowbits 状态链不进 active 转换规则；
    `success_rules.json` 已由 `xbits --success-rules FILE` 真实消费——请求侧命中登记等待、
    响应侧同 community_id 命中配对成功后带 `correlated=<请求侧 SID>` 与 confidence+15
    （见 `xbits/README.md` success_rules 章节；CI 断言 `qa_xbits_success_rules.py`）。
- `zeek/`：**只做行为分析**（`.zeek`）：DNS 突发、侦察 404/unique URI、C2 重复 URI；
  `威胁情报/` 为白域名、公共 DNS、僵尸网络元数据。不再包含 content/UA 签名匹配。
- `xbits/规则库元数据/`：xbits 中央分析引擎消费的数据（由转换器生成，勿手改）：
  - `rules_meta.json`：每条规则元数据（depend/scope/holetype/tier/category）；
  - `success_rules.json`：PVS 成功确认依赖（996 条响应→请求映射；active 规则未消费，
    由 `xbits --success-rules FILE` 消费，CI 断言见 `xbits/test/qa_xbits_success_rules.py`）；
  - `semantic_gaps.json`：剔除的 SID 与原因（含语义、状态链、依赖关联），每个 reason
    带 `owner`（谁接管）与 `tested_by`（CI 哪个断言覆盖该缺口，null＝显式承认无覆盖；
    owner=xbits-feature 的 reason 必须有 tested_by），由 `qa_semantic_gaps_gate.py` 做
    逐 reason diff 白名单 + 归属表校验；
  - `dead_rules.json`：**已删除**（flowbits 清理链路输入恒空、产物恒为 `[]`，属空转假治理；
    flowbits 依赖接管见 `semantic_gaps.json ownership.flowbits-correlation`）；
  - `audit_rules.json`：云审计规则；
  - `sid_library.json`：SID → 名称/类别/危险等级映射；
  - `exceptions.json`：例外/强 SID 列表；
  - `conversion_report.json`：to_client 方向翻转与端口方向静态断言计数（V-16）。
- `docs/`：各场景规则设计、误报分析与清理报告。
- `convert_probe_rules.py`：外部探针 Suricata 规则转换器（语义树归约：
  Snort 的「content 在前、buffer 修饰其后」顺序统一转成 Suricata 前置
  sticky buffer；`status_code` 段带静态容量断言），按类别归档并生成：
  - `docker/probe-rules-production.yaml`：生产强规则加载集（不含 weak）；
  - `docker/probe-rules-weak.yaml`：weak 规则单独加载集；
  - `docker/probe-rules-validate.yaml`：全量加载验证集；
- `convert_probe_zeek.py`：外部探针 Zeek 行为/情报转换器；
  两者输入均为桌面 `流量检测规则` 目录。

详见 [docs/规则归档与转换方案.md](docs/规则归档与转换方案.md)、
[docs/转换规则清理报告.md](docs/转换规则清理报告.md)、
[docs/规则质量QA报告.md](docs/规则质量QA报告.md)、
[docs/Lua强化方案.md](docs/Lua强化方案.md)。

重新生成转换规则：

```bash
python 规则检测/convert_probe_rules.py --src "C:/Users/sona/Desktop/流量检测规则"
python 规则检测/convert_probe_zeek.py   --src "C:/Users/sona/Desktop/流量检测规则"
```