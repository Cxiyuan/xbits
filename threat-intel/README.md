# threat-intel/ —— 统一威胁情报子模块

项目根目录下的独立子模块：**可维护、可更新、统一查询**，对 Suricata / triage / xbits 按各自场景提供所需情报类型（ip / domain / md5 / sha1 / sha256）。

## 结构
```
threat-intel/
├─ sources.json              # 情报源声明（增删源改这里 + collect.py 加解析器）
├─ tools/
│  ├─ collect.py             # 采集器：拉源 → 规范化/校验/去重 → data/ + exports/
│  └─ query.py               # 统一查询（CLI + Python API：--ip/--domain/--hash/--stats）
├─ local/                    # 自有情报（采集不覆盖，始终合并；*.example.txt 不合并）
├─ data/                     # 规范化数据（生成物）
│  ├─ md5.txt / sha1.txt / sha256.txt / ip.txt / domain.txt
│  ├─ file_hash.txt          # 三种哈希合并（triage 默认加载）
│  └─ meta.json              # 采集时间/计数/来源统计（溯源）
└─ exports/                  # 引擎消费物（生成物）
   └─ suricata/              # iprep.list + iprep-categories.txt + datasets/*.txt + 接入README
```

## 消费方式（各取所需）
| 消费方 | 情报类型 | 接入点 |
|---|---|---|
| **triage**（文件静态分析） | md5/sha1/sha256（整文件哈希） | 默认读 `data/file_hash.txt`；可用 `--hash-intel FILE` 覆盖 |
| **Suricata**（流量侧） | IP（iprep 信誉）、文件哈希与域名（datasets） | `exports/suricata/`，配置与示例规则见其 [README](exports/suricata/README.md) |
| **xbits**（编排） | 全类型（ip/domain/md5/sha1/sha256） | `--threat-intel-dir data/`：命中参与评分（`score +20` / `confidence +15`，`intel_decision=threat-hit`）；域名**精确匹配**，加载期拒绝公共后缀条目 |
| 人工排查 | 全类型 | `tools/query.py` CLI |

## 统一查询
```bash
python3 threat-intel/tools/query.py --stats
python3 threat-intel/tools/query.py --ip 50.16.16.211
python3 threat-intel/tools/query.py --domain example.com
python3 threat-intel/tools/query.py --hash <32|40|64位hex>   # 自动判 md5/sha1/sha256
```
Python API：见 `tools/query.py` 的 `IntelStore`（集合精确匹配，万级数据 O(1)）。

## 更新（可维护 SOP）
```bash
python3 threat-intel/tools/collect.py                     # 全量刷新（覆盖 data/ 与 exports/，不动 local/）
python3 threat-intel/tools/collect.py --since 2025-06-01  # 只取较新事件
python3 threat-intel/tools/collect.py --domain-max 20000  # 域名上限（DGA 噪声大，默认 5 万）
```
- 需联网环境执行；**CI 不自动跑**（时效由部署方负责，建议每周/每月刷新，git 提交可 diff 审计）。
- 自有情报放 `local/*.txt`（正式文件名），每次刷新自动合并、永不覆盖。
- 新增公开源：`sources.json` 加条目 + `collect.py` 注册解析器（见 `COLLECT_SOURCES`）。

## 数据规范与质量
- 采集即校验：哈希按算法校验长度与十六进制；IP 用标准解析；域名归一化为小写去前导点。
- CIRCL 源仅取 *malware 相关事件* 且属性 `to_ids=true`（可用于 IDS 检测），避免非 IOC 引用混入。
- 当前源（见 `sources.json`）：CIRCL MISP OSINT（TLP:WHITE，多经 VT 交叉核验）、abuse.ch Feodo Tracker（C2 IP）。
  abuse.ch 的 MalwareBazaar/ThreatFox/URLhaus 批量导出已需 Auth-Key（无鉴权 410），需要时在 sources.json 启用并补解析器。
- 仅采集 IOC 元数据：不下载样本、不上传数据；请遵守各源 License/ToU。

## 边界
- 网络 IOC（IP/域名）的**流量层**消费归 Suricata/Zeek/xbits；triage 只消费文件哈希（未来可加“文件内嵌 IOC”用 domain/ip 数据）。
- 情报会过时：请定期刷新，并结合规则/行为特征综合判定。
