# 规则检测 · 消费源归档总览

规则按“哪个引擎消费”归档：

- `suricata/`：Suricata 规则（`.rules`）、Lua 检测脚本、数据集（`.lst`）。
  - 自研场景：DNS隧道与带外检测、Web漏洞利用、侦察与攻击工具指纹、后门通信；
  - `sangfor/`：深信服探针规则转换产物（`convert_sangfor.py` 生成）：
    - 根目录：强规则；
    - `weak/`：弱/泛化规则（低置信度，由 xbits 收敛）；
    - `success/`：PVS 成功确认规则（flowbits 门控）。
- `zeek/`：Zeek 场景脚本（`.zeek`），按同名场景子目录组织。
- `xbits/`：xbits 中央分析引擎消费的数据。
  - `sangfor/`：转换产出的元数据（rules_meta / success_rules / audit_rules /
    sid_library / exceptions），由转换器生成，请勿手改；
  - 中央引擎规则文件本体在 `xbits/rules/`（analysis.json 等）。
- `docs/`：各场景规则设计与误报分析文档。
- `convert_sangfor.py`：Sangfor 导出转换器（输入桌面 `流量检测规则` 目录）。

详见 [docs/规则归档与转换方案.md](docs/规则归档与转换方案.md)。

重新生成 sangfor 规则：

```bash
python 规则检测/convert_sangfor.py --src "C:/Users/sona/Desktop/流量检测规则"
```

（会重建 `规则检测/suricata/sangfor/`、`规则检测/xbits/sangfor/` 与
`docker/sangfor-validate.yaml`。）
