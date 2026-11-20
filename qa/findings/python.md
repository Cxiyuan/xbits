# Python 子模块审计：triage / threat-intel / allowlist

- 审计员：python-auditor（team deep-qa-rootcause，任务 t2）
- 范围：`triage/`、`threat-intel/`、`allowlist/`、`xbits/test/qa_file_triage.py`，以及工作区未提交改动（`git status` 中 `?? allowlist/ threat-intel/ triage/ xbits/src/intel.rs xbits/test/qa_file_triage.py`）
- 方法：只读静态分析（read/grep/glob + git status）；未执行 pytest、未构建、未联网。所有 file:line 均可直接核对。
- 结论口径：只收“表面已完成、实际靠兜底/静默降级/配置不生效/测试假绿绕过”的问题；宁少勿滥，共 15 条。

## 摘要

| ID | 严重度 | 分类 | 问题一句话 |
|---|---|---|---|
| PY-01 | high | 兜底绕过 | collect.py 源失败只 WARN，仍无条件覆盖 data/ 并 exit 0，且销毁上一份好快照 |
| PY-02 | medium | 表面处理 | abusech-api 是打印 SKIP 的空壳却登记为已支持；options.to_ids 声明了但代码不读 |
| PY-03 | high | 兜底绕过 | 只探测“证书表非空”就把 PE 判成 clean，覆盖 high/critical 证据 |
| PY-04 | high | 未根治 | 默认 hash 情报路径依赖仓库相对布局，缺失/损坏一律静默成“无情报” |
| PY-05 | high | 表面处理 | engines.yara=true 只代表 import 成功；规则目录拼错/规则全编译失败仍是 0 命中 |
| PY-06 | medium-high | 兜底绕过 | ClamAV/capa/semgrep 的失败（rc!=0、超时、库缺失）== 未检出，verdict 照旧 clean |
| PY-07 | medium | 表面处理 | YARA 命中严重度按规则名子串猜；224 条生成规则全 critical → 弱命中直接 malicious |
| PY-08 | medium | 文档与实现不符 | curated 规则条件过宽 + 默认自动加载未在文档体现 + semgrep 示例要求联网 |
| PY-09 | medium-high | 未根治 | public_dns 被并进通用 ip.txt，两套语义合一，DNS 基线信号可被普通 IP 白名单绕过 |
| PY-10 | medium | 表面处理 | allowlist/sources.json 无任何代码读取；--check 只验 custom 语法、不比对 data/ |
| PY-11 | medium | 未根治 | 同一 IPv6 在 add/refresh/query/xbits 四处三种表示，精确比较永不命中 |
| PY-12 | medium | 测试掩盖 | 未装 yara 时 validate_rules 返回 0；CI 的 test_triage 都在无 yara 环境跑，YARA 运行路径零覆盖 |
| PY-13 | medium | 兜底绕过 | oletools 已装但解析失败被 `except: pass` 吞掉，与“无宏”无法区分 |
| PY-14 | low-medium | 测试掩盖 | qa_file_triage 用固定 `sleep(3.0)` 等异步终态，PIPE 从不排空，坏行静默丢弃 |
| PY-15 | low-medium | 文档与实现不符 | intel.rs `is_empty()` 只查 7 个集合中的 3 个，启动日志 intel=empty 会撒谎 |

对任务里 6 个怀疑点的核对结论（先说结论，细节见各条）：

1. **“public_dns 被从 ips 里错误剔除”＝证伪，实际相反**：IP 被并进 `ips`（见 PY-09）；`--check` 与写盘路径用的是同一份合并结果（这一点一致），但两者都错在“合并语义”，且 `--check` 对 data/ 漂移无感知（PY-10）。`sources.json` 声明的 `type` 确实根本没实现（PY-10，证实）。
2. **abusech-api 静默 SKIP 成立**（PY-02）；**网络失败只 WARN 后继续产出“成功”快照成立且更严重——会覆盖旧数据**（PY-01）。
3. **triage 默认情报路径硬编码仓库相对布局、静默失效成立**（PY-04）；**YARA/hash 加载失败静默降级为“无情报”成立**（PY-04/PY-05）。
4. **validate_rules 未装 yara 时 return 0 成立，但当前 CI 在该 step 前已 pip install yara-python，因此“CI 假绿”不成立；真正的假绿是 CI 两个 test_triage 步骤都在无 yara 环境跑，YARA 运行期路径从未被测试**（PY-12）。
5. **sleep/超时掩盖竞态成立**（PY-14），但方向主要是 flaky 与“管道挂死/坏行丢失”，不是稳定假通过。
6. **query.py 与 refresh.py 校验规则不一致成立**（PY-11），同一数据三套判定。

---

## PY-01 | high | 兜底绕过 | threat-intel 采集失败仍写“成功”快照并销毁旧数据

**证据**（`threat-intel/tools/collect.py`）

```python
# :145-150  （同模式见 :86-90 CIRCL manifest、:106-110 单事件抓取）
except Exception as exc:
    print(f"[WARN] {src['name']} 获取失败：{exc}")
    return

# :195-199  写入一律 "w" 截断
with open(path, "w", encoding="utf-8", newline="\n") as fh: ...

# :241-272  主流程：失败源不记 stat、不抬高退出码
for src in cfg.get("sources", []):
    ...
    fn(src, store, stat, args)
merge_local(store, stat)
write_outputs(store, stat, args, now)     # :265 无条件覆盖 data/ 与 exports/
...
return 0                                  # :272 永远 0
```

- `:142`（`stat[src["name"]] = {...}`）和 `:158` 只在成功路径写 stat；失败源在 `meta.json` 的 `sources` 里**整段缺失**，与“该源根本没配置”不可区分。
- 现存证据：`threat-intel/data/meta.json` 里 `"feodo-tracker": {"ips": 1}` —— 一个 C2 推荐阻断列表只落 1 条 IP 也照样被记录为成功，没有任何最小产出量校验。
- 每次 `collect.py` 都会整目录重写 `data/*.txt`、`data/file_hash.txt`、`exports/suricata/iprep.list`、`datasets/*`；断网/被 410/被限流时等于把最后一份可用情报清空，而 triage / Suricata / xbits 三个消费方都只看这些文件。

**为什么是绕过而非根治**：把“抓取失败”降级成一条 stderr 文本，用退出码 0 和 `[DONE]` 伪装成功；没有失败计数、没有保留旧快照、没有最小产出量阈值。消费方（`triage.py` 默认读 `file_hash.txt`、Suricata iprep、`xbits --threat-intel-dir`）会安静地失去情报，而运维看到的是绿色。

**正面修复方向**：每个源返回 `SourceResult{ok, fetched, http_code, error, last_success_utc}`；写入前先落临时目录，只有“至少一个源成功且每源产出量 ≥ 阈值”才原子替换；任一源失败则非零退出并把 `status=failed` 写进 `meta.sources`；保留 `meta.last_success_utc` 与上一份快照（如 `data/.prev/`）；给 feodo/CIRCL 加最小条数断言（例如 feodo < 10 视为失败）。

---

## PY-02 | medium | 表面处理 | abusech-api 源是空壳，却被当作“已支持”；声明过的配置项代码不读

**证据**

```python
# threat-intel/tools/collect.py:161-169
def src_abusech_api(src: dict, store: dict, stat: dict, args) -> None:
    print(f"[SKIP] {src['name']}：需要 Auth-Key（{src.get('options', {}).get('auth_key_env', '')}），尚未实现解析器")

COLLECT_SOURCES = {"circl-misp-feed": ..., "abusech-iplist": ..., "abusech-api": src_abusech_api}

# threat-intel/sources.json:21-29（notes 明确写着“设置环境变量后置 enabled=true 并在 collect.py 实现解析器”）
{"name": "malwarebazaar", "enabled": false, "type": "abusech-api", ...}

# threat-intel/tools/collect.py:127 —— to_ids 硬编码，sources.json:9 的 options.to_ids 从未读取
if a.get("deleted") or not a.get("to_ids"):
    continue
```

**为什么是绕过而非根治**：解析器注册表里有 `abusech-api` 这个 key，`main()` 的 `fn is None` 分支不会触发，于是“源未实现”表现为一条 stdout 提示；`stat` 不记录、退出码不变、`meta.json` 里也看不到。用户按 notes 设置 `ABUSECH_AUTH_KEY` 并置 `enabled=true` 后，拿到的是“缺这一源的正常快照”。同一文件里 `options.to_ids` 被声明却在代码里写死为真，是配置与实现脱钩的第二个样本。

**正面修复方向**：启动时校验 `enabled 且 type 未实现` → 直接报错退出（fail-fast），或至少在 `meta.sources` 写 `{"status": "unimplemented"}`；把 `to_ids` 从 `opts` 读取并对未知/冲突选项校验；对 `auth_key_env` 做“环境变量缺失 → 该源显式失败”的判断，而不是打印后继续。

---

## PY-03 | high | 兜底绕过 | “证书表非空”被当成“可信”，签名降级能把 high/critical 证据压成 clean

**证据**（`triage/triage.py`）

```python
# :307-312  signed 仅表示安全目录 VirtualAddress/Size 非零，不校验证书链、不校验是否被篡改
sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
info["pe"]["signed"] = bool(sec_dir.VirtualAddress and sec_dir.Size)

# :713-722
strong_prefixes = ("yara.", "clamav.", "capa.", "semgrep.", "intel.")
has_strong = any(f["id"].startswith(strong_prefixes) for f in findings)
signed = bool(info.get("pe", {}).get("signed"))
if signed and not has_strong:
    verdict = "clean"
    score = min(score, 20)
```

**为什么是绕过而非根治**：`pe.inject_write`/`pe.inject_thread`/`pe.packed_section` 等 high 权重启发式不是 `has_strong` 前缀，因此“在恶意 PE 末尾追加任意 Authenticode blob（甚至自签名证书表）”即可把 verdict 从 malicious 直接改写为 clean、score 封顶 20。代码注释承认“不校验证书链信任”，但下游仍把它当合法性凭证使用——这是把探测到的东西当成结论。

**正面修复方向**：区分 `signed_present` 与 `signature_verified`，只有后者（WinVerifyTrust/完整链校验）才允许降级；降级上限不覆盖 high/critical 证据（只降权不反转 verdict）；输出 `evidence` 时显式带 `signed_unverified=true`，让 xbits/分析师看得见降级原因。

---

## PY-04 | high | 未根治 | 默认 hash 情报路径依赖仓库布局，缺失/损坏一律静默成“无情报”

**证据**（`triage/triage.py`）

```python
# :677-686 —— 默认情报路径 = 本文件上一级目录 + threat-intel/data/file_hash.txt
intel_path = opts.get("hash_intel")
if not intel_path:
    _repo_root = os.path.dirname(_SCRIPT_DIR)
    for _p in (os.path.join(_repo_root, "threat-intel", "data", "file_hash.txt"),
               os.path.join(_SCRIPT_DIR, "intel", "known_bad.txt")):
        if os.path.isfile(_p):
            intel_path = _p
            break
intel = _load_hash_intel(intel_path)

# :496-508  不存在 → 空集；不可读 → 空集；空文件 → 空集，全部同一条路径
def _load_hash_intel(path: str | None) -> set[str]:
    if not path or not os.path.isfile(path):
        return set()
    ...
    except OSError:
        pass
    return out

# :743-757  输出里没有 hash_intel 字段；engines（:645 / :756）也没有它的状态
```

**为什么是绕过而非根治**：README §2 的部署示例只保证 `triage/triage.py` 在 `/opt/xbits/triage/`，一旦 `threat-intel/data/` 没被一起拷过去（或只部署 triage 子目录），hash 情报就永久为空：没有告警、没有退出码、输出 JSON 里也没有任何标记。于是“没配情报”“配了但路径错”“文件损坏”“文件为空”四种状态在结果里完全同形，都是“命不中 intel.known_bad”。显式 `--hash-intel /bad/path` 也同样静默成功。

**正面修复方向**：优先级改为 环境变量/显式参数 > 模块相对默认 > 无；在输出中加入 `engines.hash_intel = {"path": ..., "entries": N, "status": "loaded|missing|unreadable|empty"}`；显式 `--hash-intel` 指错或不可读要非零退出（或至少 stderr 明确告警）；空表也算状态回显，并在 README 的部署段落写清“情报目录需同步部署”。

---

## PY-05 | high | 表面处理 | engines.yara=true 只代表库能 import；规则目录/编译失败全静默

**证据**（`triage/triage.py`）

```python
# :415-423
try:
    import yara
except Exception:
    engines["yara"] = False
    return
engines["yara"] = True
if not rules_dir or not os.path.isdir(rules_dir):
    return                      # ← 目录拼错/不存在：告警为零，engines 仍是 true

# :397-411  逐文件编译失败被丢弃
try:
    r = yara_mod.compile(filepath=fp)
except Exception:
    try:
        r = yara_mod.compile(source=fh.read().decode("utf-8", "replace"))
    except Exception:
        r = None
if r is not None:
    compiled.append(r)

# :429-436  匹配异常也吞掉
except Exception:
    try:
        matches = rules.match(path)
    except Exception:
        matches = []
```

**为什么是绕过而非根治**：`engines.yara=true` 的语义是“Python 库可 import”，与“加载了 N 条规则且扫描成功”无关；`--rules-dir` 拼错、规则全部编译失败、单条规则语法坏掉、匹配抛异常，结果都是 0 条 `yara.*` finding + verdict 不受影响。默认加载路径（`:664-669`，装了 yara 就自动加载 `triage/rules`）同样没有任何“已加载规则数”回显，运维无法判断 YARA 到底有没有生效。

**正面修复方向**：输出 `engines.yara = {"import": true, "rules_dir": ..., "rules_loaded": N, "rules_failed": M, "match_errors": K}`；`rules_failed>0` 或 `rules_loaded==0` 时给 stderr 告警并允许 strict 模式非零退出；匹配异常要计数并写进 `info`，不能折叠成空列表。

---

## PY-06 | medium-high | 兜底绕过 | ClamAV/capa/semgrep 的“执行失败”与“未检出”同形，verdict 照旧 clean

**证据**（`triage/triage.py`）

```python
# :512-515  _run 不检查 rc；超时抛 TimeoutExpired
def _run(cmd_list, timeout=DEFAULT_TIMEOUT):
    proc = subprocess.run(cmd_list, ..., text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr

# :554-571  rc 被丢弃；没有 "FOUND" 就记为 signature=None（= 干净）
engines["clamav"] = True
rc, out, err = _run(args, timeout=DEFAULT_TIMEOUT)
text = (out or "") + (err or "")
if "FOUND" in text:
    ...
else:
    info["clamav"] = {"signature": None}
except Exception as exc:
    info["clamav_error"] = str(exc)[:200]   # 只进 info，不影响 engines/verdict
```

**为什么是绕过而非根治**：病毒库缺失/过期会让 clamscan 以退出码 2 结束、超时会抛异常、命令路径半坏会返回空输出——三者都被归为“无命中”，`engines.clamav` 仍然是 `True`，verdict 仍是 clean。capa（`:518-543`）、semgrep（`:574-596`）、binwalk（`:599-613`）同构：`engines[...]=True` 在真正执行前就置位，失败只写 `info.*_error`。下游（xbits `file_triage` 的 `completed`）把它当“已用 ClamAV 检查且干净”。

**正面修复方向**：`engines` 拆分 present/ok/error；`rc>1`、`TimeoutExpired`、空输出且非零退出都要记为“引擎失败”，在输出顶层加 `degraded: true / engine_errors: [...]`；xbits 侧对 `degraded` 的 completed 不要当作“干净”，至少标 `verdict_confidence: low`。

---

## PY-07 | medium | 表面处理 | YARA 命中严重度按规则名子串猜；224 条生成规则全是 critical

**证据**（`triage/triage.py`）

```python
# :437-441
name = getattr(match, "rule", str(match))
sev = "critical" if any(t in name.lower() for t in ("rat", "ransom", "webshell", "backdoor", "trojan", "malware", "shellcode")) else "high"
findings.append({"id": f"yara.{name}", "severity": sev, "detail": ..., "weight": 45})

# :724
if "critical" in severities or score >= 60:
    verdict = "malicious"
```

**为什么是绕过而非根治**：生成规则名统一是 `xb_webshell_*` / `xb_trojan_*` / `xb_backdoor_*`（`triage/rules/manifest.json` 224 条），全部命中 `webshell|trojan|backdoor` 子串 → 一律 critical → 任何一条命中（规则内容门槛最低 6 字节，见 `rules/REPORT.md:21`）都直接 `malicious`，`:711` 的权重体系被旁路。反过来，手工规则里写好的 `meta: severity = "medium"`（如 `curated_binary.yar:43`）被完全忽略；`triage/rules/README.md:33` 却写“meta 建议含 severity（会影响命中权重）”——文档与实现不符。

**正面修复方向**：优先读 `match.meta["severity"]`（yara-python 会带 meta），无 meta 时才按 category 映射；不要用规则名子串定级；对“单条弱内容命中”设上限（最多 suspicious），把“多条/家族规则命中”才升 malicious。

---

## PY-08 | medium | 文档与实现不符 | curated 规则条件过宽 + 默认自动加载未写明 + semgrep 示例破坏“不联网”

**证据**

```yara
/* triage/rules/webshell/curated_webshell.yar:22-37 —— 无 <?php 锚点，eval( 与 base64_decode 各自可出现在正常代码 */
$eval = /\beval\s*\(/   $b64 = "base64_decode" ...
condition: $eval and any of ($b64, $gz, $rot) or ($assert and any of ($b64, $gz, $rot))

/* :39-54  defineClass 单独一条即可命中 */
condition: ($exec or $pb) or ($getrt and $req) or $class
```

- `triage/triage.py:664-669`：只要装了 yara，默认就加载 `triage/rules`；而 `triage/README.md:28` 表格把 yara 的“开关”写成 `--rules-dir DIR`，读者会以为默认不启用。
- `triage/README.md:48` 唯一给出的 semgrep 示例是 `--semgrep-config auto`：semgrep 的 `auto` 会联网拉 registry 规则，与同文件 `:39`“绝不执行样本、不落盘、不联网”和 `triage.py:13` 的约束直接冲突；仓库自带的 `triage/semgrep/webshell.yml` 反而没有任何 CI/文档引用（仅该文件第 2 行自述用法）。
- `triage/rules/REPORT.md:29` 写 `binary/ 手工 3`，实际 `curated_binary.yar` 有 5 条规则；`REPORT.md:47`“所有生成规则经 yara.compile() 校验通过”是这些规则唯一的质量门（没有命中样本）。

**为什么是绕过而非根治**：规则集被默认打开后，上述宽条件会稳定把正常 PHP/JS/Java 源码判成 critical→malicious（`webshell_common_markers` 命中 `eval($_POST` 这类片段也会 critical）；文档同时给出“不联网”承诺和需要联网的示例，等于把离线保证做成了口头约定。

**正面修复方向**：宽规则加锚点与上下文（`<?php` + 至少两个独立弱信号）或降 severity/权重；把“yara 装了即默认加载 triage/rules”写进 README 表格的开关列；semgrep 示例改成 `triage/semgrep/webshell.yml`（或明确标注 `auto` 会联网、不属于默认路径）；用生成器顺带产出每条规则的命中样本，作为规则真实有效的门禁；修正 REPORT 计数。

---

## PY-09 | medium-high | 未根治 | public_dns 被并进通用 ip.txt：两套语义合一，DNS 基线可被普通 IP 白名单绕过

**证据**（`allowlist/tools/refresh.py`）

```python
# :33-38  FILES 把 public_dns_servers.txt 的输出名声明成 ("ip.txt", "ip", ...)
"public_dns_servers.txt": ("public_dns.txt", "ip", "公共 DNS 基线"),

# :78-93
for fname, (_out, kind, _desc) in FILES.items():
    ...
    elif fname == "public_dns_servers.txt":
        ips.extend(v for v in vals if v not in domains)  # 占位防重；见下归并
...
pub, _ = read_custom("public_dns_servers.txt", "ip")     # 再读一遍，单独出 public_dns.txt
```

- 实测快照：`allowlist/data/ip.txt` 与 `allowlist/data/public_dns.txt` **内容完全相同**（各 15 行、逐行一致），`data/meta.json` 也记 `ip: 15, public_dns: 15`。`allowlist/custom/ip.txt` 根本不存在，所以“通用 IP 白名单”= 公共 DNS 清单。
- 消费侧：`xbits/src/intel.rs:146-152` 的 `allowlisted_ip()` 与 `is_public_dns()` 查的是两份本来应该正交的集合；`:199-209` 的 DNS 基线判定是 `!is_public_dns(dst) && !allowlisted_ip(dst)` —— 只要某个 IP 进了通用 `ip.txt`，它就不再触发 `public_dns_off_baseline`，基线信号被“加一条普通白名单”关掉。
- `allowlist/tools/query.py:67-73`：`--ip 8.8.8.8`（默认 `kind=ip`）会命中，用户无法区分它是“通用白名单”还是“DNS 基线”。

**为什么是绕过而非根治**：`if v not in domains` 是跨类型死判断（IP 字符串永远不等于域名），注释“占位防重”掩盖了它什么也没做；实际行为是把 public_dns 反向并入通用 ip 白名单，然后又把同一批 IP 单独写一份，语义层被合并却保留了两套文件与两套查询接口。`allowlist/README.md:16` 还说 `custom/ip.txt` 是“通用白名单（初始为空）”，与快照 15 条相矛盾。

**正面修复方向**：`ip.txt` 只来自 `custom/ip.txt`，`public_dns.txt` 只从 `public_dns_servers.txt` 单向派生，禁止反向并入；`intel.rs` 的基线判定只用 `is_public_dns`，不复用 `allowlisted_ip`；`meta` 计数分别给出“来源文件 → 输出文件”映射并断言两者不相交；删掉死判断，或改成有意义的“同类型去重”。

---

## PY-10 | medium | 表面处理 | allowlist 的 sources.json 是装饰品；--check 只验语法、不验数据

**证据**

```python
# allowlist/tools/refresh.py:33-38  FILES 里第一列（输出名）被 _out 丢弃，真实输出名硬编码在 :106
for fname, (_out, kind, _desc) in FILES.items():
...
for name, lines in (("domain.txt", domains), ("ip.txt", ips), ("public_dns.txt", pub)):

# :100-102  --check 只回显计数后成功返回
if args.check:
    print(f"[OK] custom 校验通过：domain={len(domains)} ip={len(ips)} public_dns={len(pub)}")
    return 0
```

- 全仓库检索 `sources.json` 在 allowlist 内只出现在 `refresh.py:11` 的 docstring 和 `README.md:12/53`；**没有任何代码读取它**。`type`（`refresh-static-ini-domains` / `refresh-static-ini-ips`）、`enabled`、`path` 全部不生效：把 `enabled` 改成 false、改 `path`、加新源都不会改变 `refresh.py` 行为；而 README §更新 SOP 告诉用户“加条目 + 实现 fetch/parse”，前半句实际是空操作。
- `sources.json` 只声明 2 个源，`FILES` 硬编码 4 个文件；`custom/ip.txt`（README 声明存在）实际不存在，`read_custom` 对缺失文件返回空列表而不报错（`:54-57`），`--check` 因此照样 `[OK]`。
- `--check` 与写盘路径共用同一份合并结果（这点一致），但都不校验 `data/` 与 `custom/` 是否同步：`add.py` 之后忘记 `refresh.py`（README 说“CI 不自动刷新，自定义数据以 git 管理为准”）时漂移不可见，消费方（xbits/query.py）读的仍是旧快照。

**为什么是绕过而非根治**：把“源清单”做成 JSON 文件能给人一种“配置驱动”的印象，但真正的清单是 Python 字典；`--check` 叫“校验”却只做正则语法校验，不回答“消费方看到的数据是否正确”。

**正面修复方向**：让 `sources.json` 成为唯一真源（`enabled/path/type` 真正生效，未知 type 直接报错）；`FILES` 的 `out` 字段要么删掉要么真用；`--check` 增加“custom 归一化结果 == data 快照”的比对（含 meta 计数、缺失文件即失败），不一致非零退出；缺文件在 verbose 模式下明确列出。

---

## PY-11 | medium | 未根治 | 同一 IP 数据三套归一化：IPv6 在 allowlist 里永不命中

**证据**

```python
# allowlist/tools/add.py:57-64  压缩式（canonical str）
if kind in ("ip", "public_dns"):
    return str(ipaddress.ip_address(value.strip()))     # "2001:db8::1"

# allowlist/tools/refresh.py:46-51  展开式（exploded），IPv4 原样
return ipaddress.ip_address(v).exploded.lower() if ":" in v else v   # "2001:0db8:0000:...:0001"

# allowlist/tools/query.py:67-73 / xbits/src/intel.rs:19-30,146-152  不做归一化，直接小写字符串比较
v = str(value).strip().lower()
pool = self._public_dns if kind == "public_dns" else self._ips
```

**为什么是绕过而非根治**：`add.py` 把 IPv6 以压缩式写进 `custom/`，`refresh.py` 再以展开式写进 `data/`，查询端与 xbits 都用“小写原文精确比较”。结果是：用 `add.py add public_dns 2001:db8::1` 加进去的 IPv6，`query.py --ip 2001:db8::1` 与 xbits 的 `is_public_dns()/allowlisted_ip()` 永远匹配不到；事件里 Suricata 通常也是压缩式。当前数据全是 IPv4，所以这条是潜伏的、无测试覆盖的缺陷。同一问题也存在于 threat-intel（`collect.py:63-70` 只 `lower()`，`query.py:72-76` 只 `lower()`，与 allowlist 的 exploded 规则不一致），属“同一数据两套判定”。

**正面修复方向**：抽一个 `canonical_ip()`（`ipaddress.ip_address(x)` 的 `str()` + lower）在 add/refresh/query 共用，`intel.rs` 加载时同样归一（或加载成 `IpAddr` 结构比较）；`refresh --check` 增加“data 与 custom 归一化后一致”的断言，把这类不一致挡在写盘前。

---

## PY-12 | medium | 测试掩盖 | 未装 yara 时 validate_rules 返回 0；CI 的 YARA 运行路径零覆盖

**证据**

```python
# triage/tests/validate_rules.py:11-15
try:
    import yara
except Exception:
    print("yara-python not installed; skip YARA validation")
    return 0
```

```yaml
# .github/workflows/xbits-ci.yml:222-237
- name: Static triage unit tests (triage/, stdlib path)
  run: python3 triage/tests/test_triage.py
- name: Static triage unit tests (triage/, pefile+pyelftools enhanced path)
  run: |
    python3 -m pip install --quiet ... pefile pyelftools
    python3 triage/tests/test_triage.py
- name: Validate triage YARA rules compile (triage/rules)
  run: |
    python3 -m pip install --quiet ... yara-python
    python3 triage/tests/validate_rules.py
```

- `triage/tests/test_triage.py` 没有任何一条用例传 `--rules-dir`，也没有一条断言 `engines["yara"]` 为真/规则命中；900+ 行 triage 里 YARA 的加载、缓存、非 ASCII 回退、匹配、严重度分级全部没有被行为测试覆盖。
- `validate_rules.py` 的“skip → exit 0”让“未验证”和“验证通过”在退出码上等价；任何不在该 workflow、或 yara 未装/装坏的环境都会得到一个绿色的“校验”步骤。

**为什么是绕过而非根治**：CI 只证明“规则文件能被 yara 编译”，不证明“triage 会加载它们并命中”；两个 test_triage 步骤先于 yara 安装执行，所以 PY-05 里那些静默丢弃规则、匹配异常吞掉的路径在 CI 中永远不会暴露。规则生成器（`REPORT.md:47`）也只以 compile 作为质量门。

**正面修复方向**：`validate_rules.py` 未装 yara 时返回非零（或提供 `--require-yara` 供 CI 用）；增加“装了 yara 的环境”下的行为用例：已知 webshell 样本必须出现 `yara.*`，良性文本必须不出现；生成器为每条规则产出最小命中样本并在 CI 里跑；断言 `engines.yara.rules_loaded == 预期条数`。

---

## PY-13 | medium | 兜底绕过 | oletools 解析失败被吞，与“无宏”不可区分

**证据**（`triage/triage.py:445-466`）

```python
try:
    from oletools.olevba import VBA_Parser
    engines["oletools"] = True
    try:
        vba = VBA_Parser(path, data=data)
        ...
    except Exception:
        pass                                  # ← 解析失败静默
except Exception:
    engines["oletools"] = False
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        findings.append({"id": "office.macro_capable", ...})   # 只有“没装库”才留痕
```

**为什么是绕过而非根治**：oletools 已安装但文档加密、OLE 结构损坏、版本不兼容时，`VBA_Parser` 抛异常被 `pass` 吞掉；最终输出与“文档确实没有可疑宏”完全一致（无 `office.*` finding、`engines.oletools=True`）。只有“库没装”这一种情况才有低危提示，真正的解析失败反而更安静。

**正面修复方向**：解析异常写 `info["oletools_error"]` 并追加“宏分析失败（文档无法解析）”的 low finding 或 `degraded` 标志；`engines.oletools` 拆成 present/parsed；对 OLE/加密文档在解析失败时默认按“宏能力未知”而非“无宏”处理。

---

## PY-14 | low-medium | 测试掩盖 | qa_file_triage 用固定 sleep 等异步终态，管道不排空，坏行静默丢弃

**证据**（`xbits/test/qa_file_triage.py`）

```python
# :51-63  解析失败的行直接跳过
except json.JSONDecodeError:
    pass

# :108-122  固定 3 秒等待后直接 terminate；stdout/stderr 用 PIPE 却从不读取
engine = subprocess.Popen([...], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
wait_socket(work / "xbits.sock")
send_events(work / "xbits.sock", events_factory(sha_map))
time.sleep(3.0)
engine.terminate()
engine.wait(timeout=5)
```

**为什么是绕过而非根治**：用固定墙钟等待“异步管线跑完”而不是轮询到 `completed/skipped/failed` 终态，慢机器上必 flaky（多一帧延迟就少一条状态），快机器上又掩掉了“状态是否及时落盘”的问题；`PIPE` 从不排空，xbits 输出超过管道缓冲（~64KB）就会阻塞子进程、测试挂死而不是失败；`read_rows` 静默丢弃解析失败的跟踪行，而“全程跟踪文档可审计”正是这条测试要证明的东西。此外失败分支从不打印子进程 stderr，排障只能猜。

**正面修复方向**：轮询 `out.jsonl` 直到出现终态或明确 deadline（超时给出已见状态），再 `terminate`；用 `communicate(timeout=...)` 或重定向到文件来排空 stdout/stderr 并在失败时打印；解析失败计为错误（收集并断言为空），而不是跳过；对 `event.status` 断言之外再断言 `event.note`/`xbits.verdict` 来源。

---

## PY-15 | low-medium | 文档与实现不符 | intel.rs 的 `is_empty()` 只查 3/7 个集合，启动日志会撒谎

**证据**（`xbits/src/intel.rs`、`xbits/src/hook.rs`）

```rust
// intel.rs:125-129
pub fn is_empty(&self) -> bool {
    self.threat.ips.is_empty()
        && self.threat.hashes.is_empty()
        && self.allowlist.domains.is_empty()      // 漏掉 threat.domains / allowlist.ips / allowlist.public_dns
}

// hook.rs:218-222  —— 唯一的启动期情报状态信号
let intel_note = match &intel {
    Some(svc) if !svc.is_empty() => "intel=on".to_string(),
    Some(_) => "intel=empty".to_string(),
    None => "intel=off".to_string(),
};
```

**为什么是绕过而非根治**：只部署 `threat-intel/data/domain.txt`（当前 5 万条域名）或只用 allowlist 的 `ip/public_dns` 时，`is_empty()` 返回 true → 启动日志打 `intel=empty`，但注释/README（`allowlist/README.md:46-48`、`xbits/README.md:300-317`）承诺的域名与 IP 标注其实已经生效。这是 allowlist/threat-intel 数据接入后的“健康状态”唯一可见信号，它错了，运维就无法判断三个目录是否真的加载成功（与 PY-04/PY-05 是同一类“静默降级不可观测”）。

**正面修复方向**：`is_empty()` 覆盖全部 7 个集合；启动日志改成逐项计数（`threat={ip,domain,hash} allowlist={domain,ip,public_dns}`），目录存在但文件缺失时明确列出缺失文件名。

---

## 附：本批次未采用的候选（避免噪声，供 captain 取舍）

- `triage.py:732` `if verdict == "clean" and score >= 25` 是不可达死代码（前一支已覆盖）——仅代码洁癖。
- `triage.py:645` `engines["magic_lib"]` 用 `mime != application/octet-stream` 推断，`_sniff_type:209` 会把文本 mime 设为 `text/plain`，导致未装 python-magic 时也报 `magic_lib=true`——观测口径小瑕疵，未单列。
- `triage/tests/test_triage.py` 多用 `assertIn(verdict, ("malicious","suspicious"))` 的宽断言；`threat-intel/data/domain.txt` 按字母序截断 5 万（`collect.py:203`，meta 记 `domain_collected=263416`）——真实但价值低于上表。
