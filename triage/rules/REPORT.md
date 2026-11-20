# triage/rules 规则来源与覆盖报告

> 自动抽取自 `流量检测规则`（设备逆向导出的**已解密明文规则**）。
> 生成器：`triage/tools/build_rules_from_traffic_rules.py`。仅收录**文件内容型**且**不与既有 Suricata/Zeek 重复**的规则。

## 一、规则库版本（来源 README）
- IPS 特征库 ips_feature：`20250224/11:35:07`
- WAF 规则库 waf：`20250217/10:33:32`
- UTM 规则库 utm：`20240625/11:00:00`
- 全库合计 43,465 规则行 / 34,167 不同 SID（含 etc_fw 现网 + lib_* 基线重复）。

## 二、抽取口径（三原则）
1. **triage 能用**：仅保留"文件内容/字节特征"规则——`file_data`/`only_stream` 或纯字节 `content:"|..|"`；
   且能无损转成可编译 YARA（含可用 content；**pcre-only 丢弃**，避免 YARA 正则方言不兼容）。
2. **不与 Suricata/Zeek 重复检测**：
   - 先按 **SID** 排除仓库 `规则检测/suricata` 已转译的（17,477 SID）；
   - 再按 **内容签名**排除内容已存在的（例：`ml_webshell` 与已转译的 `webshell_detect` 内容相同、SID 不同 → 跳过）；
   - Zeek 侧为评分/情报脚本，无文件内容签名，无需按内容排除。
3. **按检测内容分类**输出到 `triage/rules/<category>/`。

质量门：所有 content 字节数之和 ≥ 8 且最长 content ≥ 6；同内容去重。

## 三、结果（本次生成）
| 类别目录 | YARA 规则数 | 主要来源文件 |
|---|---|---|
| `rules/webshell/` | **85** | pvs/success/ml_webshell、commonwebshell 等（去重后） |
| `rules/trojan/` | **81** | sf_snort/trojan、lib_ips_feature/trojan（剩余非重复字节特征） |
| `rules/backdoor/` | **58** | sf_snort/backdoor、lib_ips_feature/backdoor |
| `rules/binary/` | 手工 3 | curated（注入/下载执行/UPX 等通用字节特征） |
| `rules/document/` | 手工 2 | curated（PDF JS/Launch、嵌入可执行） |
| **合计自动** | **224** | —— |

跳过原因（全库统计口径）：`overlap_sid`(已转译) / `overlap_content_repo`(内容重复，如 ml_webshell→webshell_detect 2316 条) / `not_file`(事务/协议型，非文件内容) / `weak`(过短，易误报) / `dup_sid`(etc 与 lib 重复) / `repeat`(同内容)。

> 说明：shellcode / spyware / worm / file(文档) 家族虽为字节型，但**已全部被 Suricata 转译覆盖**（SID 或内容重合），按原则2不重复收录。

## 四、如何增量/重新生成
```bash
python3 triage/tools/build_rules_from_traffic_rules.py \
  --src-dir "C:/Users/sona/Desktop/流量检测规则" \
  --repo-rules 规则检测/suricata \
  --out triage/rules
```
生成 `triage/rules/<cat>/<cat>.yar` 与 `triage/rules/manifest.json`（rule→sid/msg/source 映射，便于溯源）。

## 五、可用性
- 所有生成规则经 `yara.compile()` 校验通过；
- `triage.py` 递归加载 `triage/rules/**/*.yar`；
- xbits 默认 triage 类别 `binary,script,document,archive` 覆盖这些规则的目标文件：
  - webshell 规则作用于**脚本**文件（.php/.jsp/.asp）；
  - trojan/backdoor 规则作用于**二进制**文件。
