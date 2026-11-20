# triage/rules/ —— 静态 triage 的 YARA 规则（按检测内容分类）

```
rules/
├─ webshell/   恶意脚本/WebShell 内容特征（webshell.yar 自动生成 + curated_webshell.yar 手工）
├─ trojan/     木马/勒索字节特征（trojan.yar 自动生成）
├─ backdoor/   后门/C2 字节特征（backdoor.yar 自动生成）
├─ binary/     通用二进制可疑特征（curated_binary.yar 手工：注入/下载执行/加壳等）
├─ document/   PDF/文档利用特征（curated_document.yar 手工）
├─ manifest.json  自动生成规则 → (sid/msg/source) 溯源映射
├─ REPORT.md      抽取来源、口径与覆盖报告
└─ fetch_community_rules.sh  可选：拉取社区规则到 vendor/（不内置第三方语料）
```

- `triage.py` **递归加载** 本目录下所有 `*.yar` / `*.yara`（含子目录），装了 `yara-python` 即自动生效。
- 规则命中只作为证据之一（`findings` 里的 `yara.<规则名>`），不单独放宽 xbits 抑制门槛。

## 自动生成规则（来自流量检测规则库，三原则约束）
- 仅收录 **文件内容型**（`file_data`/`only_stream`/纯字节 `content`），保证 triage 可用；
- **不与既有 Suricata/Zeek 重复检测**（按 SID + 内容签名双重去重）；
- **按检测内容分类**到 `webshell/ trojan/ backdoor/` 子目录。
- 详见 [`REPORT.md`](REPORT.md)；生成器 [`../tools/build_rules_from_traffic_rules.py`](../tools/build_rules_from_traffic_rules.py)。

重新生成：
```bash
python3 triage/tools/build_rules_from_traffic_rules.py \
  --src-dir "C:/Users/sona/Desktop/流量检测规则" \
  --repo-rules 规则检测/suricata --out triage/rules
```

## 自写规则注意事项
1. 用 `python3 -c "import yara;yara.compile(filepath='...')"` 或 `yara -r rules/ <file>` 先编译验证。
2. meta 建议含 `description/author/severity/category`（`severity` 会影响命中权重）。
3. 二进制特征结合 `uint16(0)==0x5A4D`(MZ) / `{7F 45 4C 46}`(ELF) 收窄，降低误报。

## 使用社区规则（可选，不内置）
```bash
bash triage/rules/fetch_community_rules.sh
python3 triage/triage.py --file sample --rules-dir triage/rules/vendor/signature-base/yara
```
> 第三方规则各有 LICENSE，商用/分发需自行确认，且可能大量误报，建议裁剪后使用。
