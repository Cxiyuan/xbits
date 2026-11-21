# threat-intel/ —— 统一威胁情报子模块

项目根目录下的独立子模块：**可维护、可更新、统一查询**，对 Suricata / triage / xbits 按各自场景提供所需情报类型（ip / domain / md5 / sha1 / sha256）。

## 结构
```
threat-intel/
├─ sources.json              # 情报源声明（增删源改这里 + collect.py 加解析器 + options.min_fetched 阈值）
├─ tools/
│  ├─ collect.py             # 采集器：拉源 → 规范化/校验/阈值 → 原子写 data/ + exports/
│  └─ query.py               # 统一查询（CLI + Python API：--ip/--domain/--hash/--stats）
├─ tests/test_collect.py     # V-21 自测（mock getter，不联网：HTTP500/阈值/原子回滚/unimplemented/to_ids）
├─ local/                    # 自有情报（采集不覆盖，始终合并；*.example.txt 不合并）
├─ data/                     # 规范化数据（生成物；仅在全部源成功时整体替换）
│  ├─ md5.txt / sha1.txt / sha256.txt / ip.txt / domain.txt
│  ├─ file_hash.txt          # 三种哈希合并（triage 默认加载）
│  └─ meta.json              # 最近一次**成功**采集的元数据（含 last_success_utc）
├─ collect_last_attempt.json # 最近一次尝试记录（成功/失败都写；失败时 sources[name].status=failed+error）
└─ exports/                  # 引擎消费物（生成物）
   └─ suricata/              # iprep.list + iprep-categories.txt + datasets/*.txt + 接入README
```

## 消费方式（各取所需）
| 消费方 | 情报类型 | 接入点 |
|---|---|---|
| **triage**（文件静态分析） | md5/sha1/sha256（整文件哈希） | 默认读 `data/file_hash.txt`；可用 `--hash-intel FILE` 覆盖 |
| **Suricata**（流量侧） | IP（iprep 信誉）、文件哈希与域名（datasets） | `exports/suricata/`，配置与示例规则见其 [README](exports/suricata/README.md) |
| **xbits**（编排，已落地） | 全类型（ip/domain/md5/sha1/sha256） | `--threat-intel-dir data/`：命中参与评分（`score +20` / `confidence +15`，`intel_decision=threat-hit`）；域名**精确匹配**，加载期拒绝公共后缀条目。情报已真正进入决策链（不是只标注），xbits 侧 `analysis.rs`/`engine.rs` 消费；请求→响应关联另由 `--success-rules` 提供（V-14，见 `xbits/README.md` §8.2），两者互不替代。 |
| 人工排查 | 全类型 | `tools/query.py` CLI |

## 统一查询
```bash
python3 threat-intel/tools/query.py --stats
python3 threat-intel/tools/query.py --ip 50.16.16.211
python3 threat-intel/tools/query.py --domain example.com
python3 threat-intel/tools/query.py --hash <32|40|64位hex>   # 自动判 md5/sha1/sha256
```
Python API：见 `tools/query.py` 的 `IntelStore`（集合精确匹配，万级数据 O(1)）。

> **非法输入的处置（已知限制，R15-6）**：query.py 的 `lookup_ip` / `lookup_domain` / `lookup_hash`
> 对非法输入（无法解析的 IP、非 hex 的 hash、空值）直接返回未命中（`None` / `matched=false`）——
> **静默跳过且不计数**，与 xbits 引擎侧（`intel.rs` 加载期拒绝 + `invalid_ip_warnings` 计数）不同；
> 采集侧（`collect.py`）对源数据做强校验，查询侧不重复校验。人工排查时若怀疑命中应为真，
> 先确认输入本身合法。

## 更新（可维护 SOP）
```bash
python3 threat-intel/tools/collect.py                     # 全量刷新（仅全部源达标才原子替换 data/ 与 exports/）
python3 threat-intel/tools/collect.py --since 2025-06-01  # 只取较新事件
python3 threat-intel/tools/collect.py --domain-max 20000  # 域名上限（DGA 噪声大，默认 5 万）
python3 -m unittest discover -s threat-intel/tests -v    # V-21 自测（本地、mock、不联网）
```
- 需联网环境执行；**CI 不自动跑**（时效由部署方负责，建议每周/每月刷新，git 提交可 diff 审计）。
- 自有情报放 `local/*.txt`（正式文件名），每次刷新自动合并、永不覆盖。
- 新增公开源：`sources.json` 加条目（含 `options.min_fetched`）+ `collect.py` 注册解析器（见 `COLLECT_SOURCES` 与 `KNOWN_OPTIONS`）；options 未知键会直接失败。

## 失败可见与原子写（V-21）
- 每个 enabled 源返回 `SourceResult{ok, fetched, http_code, error, last_success_utc}`，写入
  `collect_last_attempt.json` 的 `sources[name]`（`status=ok|failed` + `ok/fetched/http_code/error`）。
- **任一源失败**（HTTP 错误 / 超时 / 产出低于阈值 / enabled 但 type 无解析器 / options 未知键）
  → **非零退出**，`data/` 与 `exports/` **完全不触碰**（旧快照与 `meta.last_success_utc` 保留），
  失败详情写入 `collect_last_attempt.json`（`status=failed`、`failed_sources`、`error`）。
- 全部源成功：先写同盘临时目录 → 校验逐文件行数与 `meta.counts` 一致 → 逐文件 `os.replace`；
  替换阶段中途失败则从备份回滚，目标目录保持原样（自测 `test_replace_failure_rolls_back` 覆盖）。
- 阈值（`sources.json` 每源 `options.min_fetched`，缺省见 `collect.py MIN_FETCHED_BY_TYPE`）：
  CIRCL **1000**（现网 2408 md5 / 3204 sha256 / 30 万+ IP+域名）、Feodo **10**（推荐阻断列表正常几十条，
  旧快照仅 1 条被 QA 判为假成功）。低于阈值即视为该源失败。
- `to_ids` 从 `sources.json options.to_ids` 读取并校验布尔类型，不再硬编码；`abusech-api`
  未实现但 enabled=true 时写 `status=failed` + `unimplemented` 并非零退出（不再静默 `[SKIP]`）。

## 数据规范与质量
- 采集即校验：哈希按算法校验长度与十六进制；IP 用标准解析；域名归一化为小写去前导点。
- CIRCL 源仅取 *malware 相关事件*（`malware_only`，可在 sources.json 关闭）；属性是否要求 `to_ids=true`
  由 `options.to_ids` 控制（当前为 true，避免非 IOC 引用混入）。
- 当前源（见 `sources.json`）：CIRCL MISP OSINT（TLP:WHITE，多经 VT 交叉核验）、abuse.ch Feodo Tracker（C2 IP）。
  abuse.ch 的 MalwareBazaar/ThreatFox/URLhaus 批量导出已需 Auth-Key（无鉴权 410），需要时在 sources.json 启用并补解析器。
- 仅采集 IOC 元数据：不下载样本、不上传数据；请遵守各源 License/ToU。

## 边界
- 网络 IOC（IP/域名）的**流量层**消费归 Suricata/Zeek/xbits；triage 只消费文件哈希（未来可加“文件内嵌 IOC”用 domain/ip 数据）。
- 情报会过时：请定期刷新，并结合规则/行为特征综合判定。
