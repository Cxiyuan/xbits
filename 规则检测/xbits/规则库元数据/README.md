# xbits 规则库元数据

由 `规则检测/convert_probe_rules.py` 生成，按 SID 与外部探针规则库对齐。

| 文件 | 用途 |
|---|---|
| `rules_meta.json` | 每条规则元数据：`depend`/`scope`/`holetype`/`tier`/`category`/源文件 |
| `success_rules.json` | PVS 请求→响应成功确认依赖（元数据，不进入 Suricata；供 xbits 关联） |
| `dead_rules.json` | 已清理的失效规则（orphan flowbits / 无检测原语） |
| `semantic_gaps.json` | 无法等价转换而剔除的 SID 与原因（仅保留元数据） |
| `audit_rules.json` | 云审计规则（仅元数据，不进入 Suricata 告警） |
| `sid_library.json` | SID → 规则名/危险等级/类别/子类别/所属类目 |
| `exceptions.json` | 例外列表与强 SID 名单 |

## 消费方式

1. **告警归一化**：Suricata 告警进入 xbits 后，用 `sid_library.json` 补全
   `name` / `category` / `subcategory` / `danger_class`；
2. **弱规则收敛**：`rules_meta.json` 中 `tier=weak` 的 SID 默认低置信度，
   需要 Zeek 上下文或成功确认才输出；
3. **攻击成功确认**：`success_rules.json` 描述“响应侧 SID ← 请求侧 SID”依赖，
   配合 Suricata `flowbits` 门控与 5-tuple 关联，确认成功后才输出高置信度告警；
4. **误报与例外**：`exceptions.json` 的强 SID / 例外表用于抑制与提权；
5. **清理审计**：`dead_rules.json` 记录已剔除的 orphan/no-primitive 规则。

数据由转换器覆盖生成，**不要手工编辑**。