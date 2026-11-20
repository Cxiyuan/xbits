# triage/ — 静态 Triage（xbits 文件分析）

本项目对"流量中被 Suricata 检测到并转存的文件（二进制可执行文件、脚本、文档、压缩包等）"
做**不运行的静态 Triage**，作为 xbits 中央分析平台的文件分析一环。

整体链路：

```
Suricata 解包/文件追踪
  ├─ 命中文件 -> file-store 落盘（<spool>/<sha[0:2]>/<sha256>）
  └─ eve-log `files`(fileinfo) 事件 -> xbits 薄 hook
        xbits 编排（--triage-cmd 调 triage/triage.py）
          -> 静态 triage 返回 {verdict,score,category,findings,evidence}
          -> xbits 全程跟踪：file_triage 文档按 received/analyzing/completed|failed|skipped 逐阶段输出
```

## 1) 静态 triage 模块

- **纯标准库必跑**：自写魔数嗅探、MD5/SHA1/SHA256、Shannon 熵、strings、脚本危险函数扫描、
  PDF/Office 关键字、双扩展名伪装等；任何环境可直接运行、结果确定可复现。
- **可选开源组件软接入（有则增强，无则降级，绝不因缺库崩溃）**：

| 组件 | 类型 | 能力 | 开关 |
|---|---|---|---|
| python-magic | py 库(自动) | 权威 MIME/魔数 | 装了即用 |
| **pefile** | py 库(自动) | PE 结构：导入/导出、节区熵、编译时间、**imphash/authentihash**、证书表存在性探测（不做信任校验，见签名语义）、危险导入映射（注入/反调试/下载/持久化/加解密） | 装了即用 |
| **pyelftools** | py 库(自动) | ELF 结构：机器/类型/入口、NEEDED 依赖、静态链接判定 | 装了即用 |
| yara-python | py 库(自动) | 家族/行为规则 | `--rules-dir DIR` |
| oletools | py 库(自动) | Office 宏深度解析 | 装了即用 |
| ssdeep / tlsh | py 库(自动) | 模糊哈希（相似样本归并） | 装了即用 |
| **capa** | 外部命令 | 能力语义（C2/注入/持久化等） | `--capa-cmd` / `--all-engines` |
| **ClamAV** | 外部命令 | 病毒库签名扫描 | `--clamscan-cmd` / `--all-engines` |
| semgrep | 外部命令 | 脚本 AST 级规则 | `--semgrep-config` + `--semgrep-cmd` |
| binwalk | 外部命令 | 内嵌/压缩容器拆解 | `--binwalk-cmd` / `--all-engines` |
| 本地 hash 情报 | 离线 | 命中已知恶意 hash（不联网） | **仅独立 CLI**：默认 `threat-intel/data/file_hash.txt`，或 `--hash-intel FILE`；xbits 以 `--stdin` 调用时以 payload 的 `intel` 标注为准、不读本地名单 |

可选依赖清单见 [`triage/requirements-optional.txt`](requirements-optional.txt)：
`python3 -m pip install -r triage/requirements-optional.txt`。外部命令不在 PATH 时自动跳过。
- **绝不执行样本、不落盘、不联网**（hash 情报走本地名单或调用方传入值）；只读文件做判断。
- **hash 情报单一判定来源**：xbits 调起（`--stdin`）时只认 payload `intel`（不读盘、不另判、不重复计分）；
  独立 CLI（`--file`/位置参数）保留本地名单查询；显式 `--hash-intel` 仅独立 CLI 生效（`--stdin` 下忽略）。

命令行：

```bash
python3 triage/triage.py --file /path/to/sample        # 直接分析（Python 库增强自动生效）
python3 triage/triage.py /path/to/sample
python3 triage/triage.py --stdin                       # 从 stdin 读 {"path": "...", "intel": {...}}（xbits 用）
# 显式开启外部引擎：
python3 triage/triage.py --stdin --all-engines --rules-dir triage/rules --semgrep-config auto
```

输出 JSON（节选，新增 `info` 承载 pe/elf/fuzzy/capa 等结构化证据）：

```json
{
  "ok": true,
  "file": {"path","name","size","sha256","sha1","md5"},
  "type": {"category":"binary","magic":"PE executable (MZ)","ext":"exe","mime":"..."},
  "verdict": "malicious|suspicious|clean|unknown",
  "score": 0,
  "degraded": false,
  "engine_errors": {},
  "findings": [{"id":"pe.inject_write","severity":"critical","weight":40,"detail":"..."}],
  "evidence": ["pe.inject_write[critical]","sha256=...","category=binary","imphash=..."],
  "info": {"pe": {"machine","sections","imports","imphash","authentihash",
                  "signed_present","signature_verified",...},
           "elf": {"machine","type","entry","needed","statically_linked"},
           "fuzzy": {"ssdeep","tlsh"}},
  "engines": {"pefile":true,"pyelftools":true,"yara":false,"capa":false,...},
  "engine_status": {"pefile":{"present":true,"ok":true,"error":null}, ...}
}
```

**引擎状态 schema（V-20）**：`engines[tool]=bool` 只是向后兼容摘要（= `present and ok`）；
结构化三态在 `engine_status[tool] = {present, ok, error}`：
- `present=false`：组件未安装/未启用/对该类别不适用（可选缺失，不算失败）；
- `present=true, ok=true`：本次真实执行成功（含"执行了且未检出"）；
- `present=true, ok=false`：执行失败（rc!=0 / 超时 / 解析失败 / 目录或规则缺失）→ 计入顶层
  `degraded=true` 与 `engine_errors`。**"执行失败"与"扫描通过未检出"严格不同形**。

**YARA 部分失败语义（R8-3）**：三类失败分开报告，任何一类出现都 `engine_status["yara"].ok=false`
且顶层 `degraded=true`——但**已编译成功的规则照常匹配**（可用部分生效，不会被跳过）：
- `error` 字段：`compile-failed: <文件名,...>` / `unreadable: <原因>` / `match-errors: <n>` 组合；
- `engine_status["yara"].failed_files`：编译失败的规则文件名列表；
- `engine_status["yara"].unreadable_errors`：目录/文件不可读原因（最多 5 条）；
- `info.yara_rules.failed` / `info.yara_rules.loaded`：失败与成功加载的文件计数；
- `info.yara_rules_failed`（= failed_files）、`info.yara_unreadable_errors`、`info.yara_match_errors`
  供程序化消费。全部规则文件编译失败时 `error` 以 `no-rules-compiled` 开头。
- 单测：`test_yara_partial_compile_failure_is_degraded_and_valid_rules_still_hit`（合法规则仍命中、
  ok=False、degraded=True、error 含坏文件名）、`test_yara_unreadable_rules_dir_is_reported`。

**签名语义（V-22）**：`info.pe.signed_present` 仅表示 Authenticode 证书表非空（存在性探测，
可被伪造）；`info.pe.signature_verified` 才表示可信验证——本工具不做证书链/信任校验，
`signature_verified` 恒为 `false`，因此**证书表存在绝不触发 verdict 降级**（旧 `signed` 字段
保留仅为兼容，值 = `signed_present`，旧"已签名判 clean"的洗白路径已移除）。

**hash 情报**：`info.intel_source` ∈ `xbits-payload | xbits-payload(none) | local-file | none`、
`info.intel_hit`、`engines.hash_intel{source,hit}`，见上文"单一判定来源"。

类别 `category`：`binary | script | document | archive | text | other`。
xbits 默认只对 `binary,script,document,archive` 做 triage（文本/图片等常见噪声跳过）。

作为库：

```python
from triage.triage import analyze
r = analyze("/path/to/sample")
```

## 2) xbits 侧编排与全程跟踪

xbits 新增 CLI（配合 `--hook-socket`）：

```bash
xbits --hook-socket /var/run/xbits/hook.sock \
      --rules xbits/rules/analysis.json \
      --analysis-file /var/log/xbits/file_triage.jsonl \
      --file-spool-dir /opt/xbits/filestore \
      --triage-cmd "python3 /opt/xbits/triage/triage.py --stdin" \
      --triage-timeout-ms 30000 \
      --triage-categories binary,script,document,archive \
      --triage-cache-ttl-sec 3600
```

行为：
- 收到 `file_stored`（EVE `fileinfo` 归一）事件后，按 `file_spool_dir/<sha[0:2]>/<sha256>` 定位文件；
- 命中 `--triage-cache-ttl-sec` 缓存则直接复用结果（同一 sha256 不重复分析）；
- 逐阶段输出 `file_triage` 跟踪文档（`event.status`）：`received` → `analyzing` → `completed`/`failed`/`skipped`；
- `completed` 且 verdict 为 `malicious`/`suspicious` 才推送 ES，其余阶段只写分析文件用于全程跟踪；
- 文件缺失或 `stored=false` → `failed`（fail-closed，不猜测）。

### 2.1 阶段语义（失败形态不再合并）

`failed` 阶段由 `event.xbits.note` 明确区分，`xbits` 不再把不同故障压成同一句话：

| 场景 | 阶段 | note |
|---|---|---|
| 超出 `--triage-timeout-ms` | `failed` | `triage-timeout: after <N>ms (process group killed)`；进程组清理失败时附 `process-group kill failed: …`，并计入 `triage_timeouts` |
| 命令正常退出但退出码非 0 | `failed` | `triage-failed: non-zero exit code=<N> stderr=<截断后的 stderr>` |
| 无法启动命令 / 等待失败 | `failed` | `triage-failed: spawn error: …` |
| stdout 非 UTF-8 | `failed` | `triage-failed: stdout is not UTF-8: …` |
| 退出码 0 但输出不是 JSON | `failed` | `bad-triage-json: …` |
| triage 返回 `{"ok": false, ...}` | `failed` | `triage-returned-error` |
| `file_stored=false` | `failed` | `stored=false (Suricata did not persist this file; refusing to guess a spool path)` |
| 非法 `file_sha256`（非 32/40/64 hex） | `failed` | `bad-file-sha256: …` |
| spool 里找不到该 sha | `failed` | `file-not-found: spool dir 中不存在 sha=… 的文件` |
| 未配置 `--file-spool-dir` 且无有效 `file_path` | `failed` | `file-not-locatable: --file-spool-dir 未配置且事件没有可用的 file_path` |
| triage 队列满（worker 忙） | `failed` | `triage-queue-full (dropped; triage worker busy)`，计入 `triage_dropped` |
| triage worker 已退出 | `failed` | `triage-worker-unavailable (dropped)`，流水线标记不可用（进程随后非零退出） |

### 2.2 执行模型

- 外部 triage 命令只在独立的 `xbits-triage` worker 线程执行（有界队列深度 64），
  分析线程只做准入判定与投递：默认 30s 的 triage 不会阻塞告警判定与 pending 超时；
- 队列满时**丢弃并计数**（`triage_dropped`）+ 落一条 `failed` 阶段文档，绝不阻塞决策线程；
- 超时杀的是**整个进程组**：spawn 时 `process_group(0)`，超时对 `-pgid` 发 SIGKILL（含孙进程）；
  只杀 `sh -c` 本体、放任孙进程继续运行的旧行为已移除；
- 超时/非零退出/启动失败/编码失败分别有独立结果类型与计数，不再"超时返回空串 → 当成坏 JSON"。
- **情报由 xbits 经 stdin 传入**：请求里的 `intel: {threat: [{type,value}...], allowlist: [...]}`
  来自 xbits 引擎（`engine.intel_annotations`，与告警共用同一数据源）；`--stdin` 下 triage
  以本次 payload 情报为准、不读本地名单（见 §1 与 `_payload_threat_hashes`）。只有独立 CLI
  才会读 `--hash-intel` / `threat-intel/data/file_hash.txt`。
- **命中一定进 ES**：`completed` 阶段即使 triage 判 `clean`，只要 xbits 情报命中文件哈希就推 ES，
  文档标 `xbits.intel_conflict=true`（`xbits.verdict` 以情报为准为 `malicious`，原始结论保留在
  `xbits.triage_verdict`，`xbits.note` 追加 `intel-conflict: ...`）；`failed`/`skipped` 阶段命中同样推，
  避免超时/类别跳过把已知恶意文件静默丢掉。

## 3) Suricata 侧：转存 + 通知

参考运行配置见 [`docker/suricata-test.yaml`](../docker/suricata-test.yaml)：启用 `file-store`
（v2，按 SHA256 分桶落盘）与 eve-log 的 `files`(fileinfo) 事件。生产部署要点：

```yaml
outputs:
  - file-store:
      version: 2
      enabled: yes
      dir: /opt/xbits/filestore      # 与 xbits --file-spool-dir 指向同一目录
      force-filestore: yes           # 全量转存；如需只转存命中文件，去掉此项并给规则加 filestore 关键字
      stream-depth: 0
      write-fileinfo: yes
      force-hash: [sha256]
  - eve-log:
      filetype: xbits-hook          # 薄 hook 转发到 xbits
      types:
        - files:
            force-magic: yes
            force-hash: [sha256]
```

> 磁盘：`force-filestore: yes` 会转存 Suricata 追踪到的所有文件，可用空间与保留策略需规划；
> 只关心"命中文件"时，改为在二进制/脚本检测规则中加 `filestore` 关键字，去掉 `force-filestore`。

## 3.5) 规则库（`triage/rules/`，按检测内容分类）
- 目录：`webshell/ trojan/ backdoor/ binary/ document/`（每类一个/多个 `.yar`），`triage.py` **递归加载**。
- 来源与口径见 [`rules/REPORT.md`](rules/REPORT.md)：从流量检测规则库（明文规则）抽取，**仅文件内容型** 且
  **不与既有 Suricata/Zeek 重复**（SID + 内容签名双重去重），共自动生成 **224 条** YARA
  （webshell 85 / trojan 81 / backdoor 58）＋手工 curated。
- 生成器：[`tools/build_rules_from_traffic_rules.py`](tools/build_rules_from_traffic_rules.py)。

## 4) 测试

```bash
python3 triage/tests/test_triage.py                 # 静态 triage 单元测试（14 例）
python3 xbits/test/qa_file_triage.py \
  --xbits xbits/target/release/xbits \
  --triage-cmd "python3 triage/triage.py --stdin"   # 端到端编排 + 全程跟踪（4 例）
```

CI：`xbits-cross-engine-8.0.8-9.0.1` 工作流的 `match-context` 作业已包含上述两个测试。
