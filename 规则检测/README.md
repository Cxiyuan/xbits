# 规则检测 · 消费源归档总览

规则按“哪个引擎消费 + 攻击类别”归档，不设厂商目录：

- `suricata/`：**签名命中规则 + 自研 Lua 增强**（`.rules`、场景 `lua/`、数据集 `.lst`）。
  自研 Lua 用于签名匹配/解码/结构判定，减少误报、提高精确度；转换规则不注入
  flowbits、depend/scope 状态链，相关依赖交 xbits 关联。
  - 自研场景：`DNS隧道与带外检测/`、`Web漏洞利用/`、`侦察与攻击工具指纹/`、`后门通信/`；
  - 外部探针转换规则按攻击类别归档，例如：
    - `Web攻击/SQL注入/`、`Web攻击/XSS/`、`Web攻击/WebShell/`、`Web攻击/命令注入/`、
      `Web攻击/文件上传/`、`Web攻击/信息泄露/`、`Web攻击/扫描器/`；
    - `恶意软件/木马/`、`恶意软件/后门/`、`恶意软件/C2与远控/`、`恶意URL/`；
    - `网络服务漏洞/`、`主机系统漏洞/`、`应用软件漏洞/`、`网络设备漏洞/`。
  - PVS 请求→响应成功确认、flowbits 状态链只保留在 xbits 元数据，不进 active 转换规则。
- `zeek/`：**只做行为分析**（`.zeek`）：DNS 突发、侦察 404/unique URI、C2 重复 URI；
  `威胁情报/` 为白域名、公共 DNS、僵尸网络元数据。不再包含 content/UA 签名匹配。
- `xbits/规则库元数据/`：xbits 中央分析引擎消费的数据（由转换器生成，勿手改）：
  - `rules_meta.json`：每条规则元数据（depend/scope/holetype/tier/category）；
  - `success_rules.json`：PVS 成功确认依赖（供 xbits 做请求→响应关联）；
  - `dead_rules.json`：已清理的失效规则；
  - `semantic_gaps.json`：剔除的 SID 与原因（含语义、状态链、依赖关联）；
  - `audit_rules.json`：云审计规则；
  - `sid_library.json`：SID → 名称/类别/危险等级映射；
  - `exceptions.json`：例外/强 SID 列表。
- `docs/`：各场景规则设计、误报分析与清理报告。
- `convert_probe_rules.py`：外部探针 Suricata 规则转换器（按类别归档），生成：
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