# 测试与 CI 假绿审计（审计员：tests-auditor / task t4）

- 范围：`triage/tests/`、`xbits/test/qa_*.py`、`xbits/testdata/`、`测试用例/`、`.github/workflows/*.yml`、`docker/`，以及工作区未提交改动（`git status` / `git diff`）。
- 方法：只读静态分析（read/grep/glob + git status/diff）。未修改任何源码、未运行测试/构建、未联网。所有 `file:line` 以当前工作区文件为准，可直接核对。
- 口径：只收「表面通过、实际没验证到关键行为」的条目；纯文档错误、纯风格问题不收。共 13 条。

## 摘要

| ID | 严重度 | 分类 | 问题一句话 |
|---|---|---|---|
| TS-01 | high | CI 假绿 | 新目录 `triage/**`、`threat-intel/**`、`allowlist/**` 不在任何 workflow `paths:`，改了被测代码/数据 CI 一次都不跑 |
| TS-02 | high | 测试掩盖 | 规则覆盖门禁自称「每个 .rules 的每个 sid 都被用例覆盖」，实际只扫 4 个目录（74/17477 个唯一 SID），其余只做 `suricata -T` 加载 |
| TS-03 | high | 测试掩盖 | YARA 规则从编译到命中没有任何一条断言；triage 还会把编译失败的规则静默丢弃 |
| TS-04 | high | 测试掩盖 | 「pefile+pyelftools enhanced path」第二个 CI 步骤是假门：断言只判 `engines` 里有 key，装不装都过 |
| TS-05 | high | 测试掩盖 | match_context / 抑制体系只在自造的 6 条 SID 夹具上验证；生产 3.7MB 元数据与生成器从不被 CI 校验 |
| TS-06 | high | 测试掩盖 | hook 矩阵文档承诺「engine SID 集合 == require，不许额外规则」，代码却只做子集/禁集，额外命中仅打印 |
| TS-07 | medium | 测试掩盖 | `c2_periodic` 用例 require 与 forbid 双空 → Suricata 断言与 hook 矩阵恒过 |
| TS-08 | medium | 测试掩盖 | `qa_xbits_context` 负例只断言 `len(got)==0` + 固定 sleep，引擎崩溃与「正确抑制」不可区分 |
| TS-09 | medium | CI 假绿 | hook 运行时断言只 `grep` 一个 rule_id 子串，配合 `sleep 1` 与 `kill ... || true`，不校验条数/字段 |
| TS-10 | medium | CI 假绿 | stdin 桥测试等于回声测试：fixture 本身含同名 SID，输出只要出现该子串即通过 |
| TS-11 | medium | 测试掩盖 | `docker/suricata-test.yaml` 新增 file-store + `files` 输出，唯一 CI 使用点却把 files 事件静默丢弃 |
| TS-12 | medium | 测试掩盖 | 规则质量 QA 数据是提交产物却无 CI 重新生成/校验，已引用到已删除文件（无告警） |
| TS-13 | low-medium | CI 假绿 | 「Zeek behavior scripts compile」只保证跑完不报错，不校验任何日志/评分输出 |

任务里 6 个怀疑点的核对结论（先给结论，细节见各条）：

1. **新增根目录 `threat-intel/`、`allowlist/` 不在任何 workflow 的 `paths:` 内 → 属实**；同问题还覆盖 `triage/**`（TS-01，含本次新增的 triage 测试步骤本身）。
2. **断言过弱（只 grep SID/只判 exit 0/只数行数）→ 属实**（TS-06、TS-09、TS-10、TS-13）。
3. **sleep/固定等待、`|| true`、过宽 skip → 部分属实**：workflow 与 QA 层有固定 `sleep` + `|| true`（TS-09、TS-08）；`validate_rules` 未装 yara 时 `return 0`（TS-03 的一环）。固定等待主要造成 flaky 与「静默丢行」，不是稳定的假通过。
4. **mock/桩数据绕开真实路径 → 属实且是最大一块**：YARA 从不真的命中（TS-03）、match_buffers 只用 6 条假 SID（TS-05）、file-store 事件无消费者（TS-11）、intel/allowlist 数据无任何 CI 校验（TS-01）。
5. **workflow 有「只验证能启动/能加载」步骤 → 属实**（TS-02、TS-13）。
6. **删除/新增文件后 workflow 路径失效 → 本次未发现仍在引用已删文件**：`xbits-images.yml` 里的 `规则检测/zeek/威胁情报/*.zeek` 引用已在工作区 diff 中移除；但**引用它们的下游产物 `规则检测/docs/规则质量QA数据.json` 已陈旧且无人校验**（TS-12）。`测试用例/zeek_cases.json`（README 承诺）实际不存在，也无任何用例消费。

---

## TS-01 | high | CI 假绿 | 被测目录不在 workflow `paths:`，改动零 CI

**证据**
- `.github/workflows/xbits-ci.yml:6-20` push/pull_request 触发路径仅：`xbits/**`、`测试用例/generate_{caps,recon_pcaps,web_pcaps,backdoor_pcaps}.py`、`.github/workflows/xbits-ci.yml`。
- 同一文件 `.github/workflows/xbits-ci.yml:222-244` 新增了 **triage** 单测 / YARA 编译校验 / `qa_file_triage.py` 三步——被测对象是 `triage/`，但 `triage/**` 不在触发路径里。
- `.github/workflows/xbits-images.yml:6-20` 触发路径仅 `docker/**`、`xbits/**`、`app-id/**`、`规则检测/**`、`测试用例/generate_web_pcaps.py`、workflow 自身；其中 `99-100` 行跑 `qa_rule_coverage.py`，而该脚本读 `测试用例/cases.json`、`recon_cases.json`、`web_cases.json`、`backdoor_cases.json`（`xbits/test/qa_rule_coverage.py:19-40`）——这些用例文件不在 paths 里。
- `.github/workflows/xbits-ci.yml:321-357` 的 `suricata-live` job 会 `cp 规则检测/suricata/**/*.rules`、`cp 测试用例/classification.config`、用 `测试用例/suricata-*-ci.yaml.in` 生成配置——`规则检测/**`、`测试用例/*.config`、`测试用例/*.yaml.in` 都不在 `xbits-ci.yml` 的 paths 里。
- 全局检索：`threat-intel`、`allowlist` 在 `.github/workflows/*.yml` 里 0 命中（只有 `xbits/test/..`、README 引用）。

**为什么掩盖了真实问题**
本次审计的核心新模块恰好是「最不会被触发」的那几个目录：改 `triage/triage.py` 或 `triage/rules/*.yar`，CI 全绿（因为根本没跑）；改 `threat-intel/data/*.txt`、`allowlist/custom/*.txt`，CI 全绿（因为没有任何 job 读它们）；改 `测试用例/cases.json` 删掉一条 require，本应让覆盖门禁变红，但门禁所在的 `xbits-images` 不会启动。等于「新增了测试，但测试的触发条件把被测对象排除在外」，是典型的结构性 CI 假绿，不靠改断言能发现。

**正面修复方向**
- 把「消费什么就监听什么」写成硬约束：`xbits-ci.yml` paths 补 `triage/**`、`threat-intel/**`、`allowlist/**`、`规则检测/**`、`测试用例/*.config`、`测试用例/*.yaml.in`、`测试用例/*.py`；`xbits-images.yml` 补 `测试用例/*.json`（cases）与 `triage/**`。
- 更稳的做法：为 triage / intel / allowlist 各开独立 workflow（各自 paths = 自身 + 共用断言脚本），避免「挂在一个大 workflow 里靠别人的路径捎带」。
- 加一条元测试（不需要 CI 环境的纯静态检查）：解析 `qa_*/test_*` 脚本里出现的仓库相对路径，断言每个路径都被至少一个 workflow 的 `paths:` 前缀覆盖，否则 fail。

---

## TS-02 | high | 测试掩盖 | 规则覆盖门禁的范围远小于自我声明

**证据**
- `xbits/test/qa_rule_coverage.py:4-6` docstring：「**Every** sid in **every** `规则检测/**/*.rules` file must be named by at least one generated case」。
- `xbits/test/qa_rule_coverage.py:17-42` 的 `CATEGORIES` 只列 4 个目录：`suricata/DNS隧道与带外检测`、`侦察与攻击工具指纹`、`Web漏洞利用`、`后门通信`。
- `.github/workflows/xbits-images.yml:99-100` 步骤名是 `Rule coverage gate (all SIDs must be exercised)`。
- 实测计数（只读 grep）：这 4 个目录共 **74** 个唯一 `sid:`；`规则检测/suricata/**` 全量共 **17,477** 个唯一 SID（另 46 个 `.rules` 文件、12 个子目录）；即 **17,403 个 SID 不在门禁范围内（约 0.4% 覆盖）**。
- 这些剩余规则的处理方式仅是 `.github/workflows/xbits-images.yml:155-169` 的 `suricata -T`（配置加载自检），从未对任何 PCAP 跑过。

**为什么掩盖了真实问题**
「规则覆盖门禁 PASS」和「所有 SID 都被演练」是两个不同事实，脚本打印的 `RULE COVERAGE: PASS (all rule sids are exercised by at least one case)`（`qa_rule_coverage.py:102`）把前者说成后者。转换来的 46 个规则文件（Web攻击/恶意软件/网络服务漏洞等）可以整体语义错乱、正则写错、`content` 永远匹配不上，门禁依然绿；CI 日志里也看不到「这 17k 条规则只有加载没有命中」这一事实。

**正面修复方向**
- 要么把 gate 改成「按目录白名单 + 显式 excluded 清单（带原因 + 计数）」，输出里必须打印 `excluded_dirs=12, excluded_sids=17403`，让缺口可见；
- 要么给每个转换目录抽 1~2 条代表性 SID，生成最小 PCAP 做命中回归（正例 + 反例），把「加载」升级成「命中」；
- 门禁的 PASS 文案不要写 all，改 `covered 74/17477 (excluded 12 dirs, see EXCLUDED.md)`，避免误读。

---

## TS-03 | high | 测试掩盖 | YARA：只有「能编译」，没有「会命中」

**证据**
- `triage/tests/validate_rules.py:24-35`：只做 `yara.compile(filepath=...)`，失败再 `source=` 重试，两者都失败才计 bad。**从未对任何样本 `match()`**。
- `triage/tests/test_triage.py` 全部用例：`analyze(path)` 没有一处传 `rules_dir`，也没有一处断言 `findings` 里出现 `yara.*`（grep `yara` 在 `triage/tests/` 仅有 `validate_rules.py`）。
- `xbits/test/qa_file_triage.py:181-194`：唯一断言是 `statuses` 序列 + `verdict == "malicious"`；而该样本 `PHP_SHELL`（:74）仅靠内置正则 `php.eval`(60) + `php.system_exec`(55) 就可判 malicious（`triage/triage.py:51-54`，:711-725），**YARA 全部规则失效、甚至一条没加载，测试依旧绿**。
- `triage/triage.py:398-412`：`_compiled_yara_rules` 对每个失败文件 `r=None` 后直接跳过，不计数、不告警、不影响 `engines["yara"]`（`:421` 在编译前就置 True）。
- `triage/triage.py:677-685`：hash 情报默认路径同样受「文件不存在即静默为空」影响（`_load_hash_intel` 无告警）。

**为什么掩盖了真实问题**
YARA 是 triage 唯一的「强证据」通道（`strong_prefixes`，`triage.py:713`），但整条路径的可见性只到「编译通过」。规则写错条件（例如 `$php and ($eval or $assert or $create)` 里某个字符串打错）→ 编译 OK → 命中永远为 0 → CI 全绿 → 线上样本被判 clean。更糟的是运行时编译失败被吞掉，`engines.yara=true` 依然报「已启用」，把「坏了」显示成「开了」。

**正面修复方向**
- 在 `triage/tests/` 加正/负样本对：`webshell_php_eval_superglobal` 必须命中 → `findings` 含 `yara.webshell_php_eval_superglobal`；良性 PHP 不得命中。manifest 里每个 `yara_rule` 至少抽 1 条做正例（或用生成器从 manifest 反查）。
- `_compiled_yara_rules` 统计 `failed` 并写入返回结构，`engines["yara"]` 改为 `true/false/partial(n)`；`bad>0` 时 `validate_rules.py` 已经在 CI 里 fail，运行时也要在 stderr 明确报错，禁止静默降级。
- 给 `qa_file_triage.py` 的 completed 文档补断言：`findings` 含 YARA 命中 id、`engines.yara` 为 True、`type.category == "script"`，避免「regex 单独过关」。

---

## TS-04 | high | 测试掩盖 | 「增强路径」CI 步骤断言的是 key 存在而非能力生效

**证据**
- `triage/tests/test_triage.py:118-127`：`self.assertIn("pefile", r["engines"])`；`:129-135`：`assertIn("pyelftools", ...)`；`:149-153`：`assertIn("ssdeep"/"tlsh", ...)`。
- `triage/triage.py:239-245`、`:333-340`：无论 import 成功与否都会写入键（`engines["pefile"]=False` 也写），因此 `assertIn` 恒真。
- `.github/workflows/xbits-ci.yml:227-231` 的步骤名是 `Static triage unit tests (triage/, pefile+pyelftools enhanced path)`，做的是 `pip install pefile pyelftools` 后再跑**同一个** `test_triage.py`。

**为什么掩盖了真实问题**
「装依赖 → 重跑同一文件 → 绿」被当成「增强路径已验证」。装不装 pefile/pyelftools，断言结果完全一样；装了但 `pefile.PE()` 抛异常、`info.pe` 完全缺失，也照样绿。CI 里因此存在一个**看起来是第二道防线、实际是同一道防线副本**的步骤。

**正面修复方向**
- 断言值而非键：`assertTrue(r["engines"]["pefile"])`，并断言 `info["pe"]` 含 `machine`/`sections`/`imphash` 等字段；ELF 同理断言 `info["elf"]["needed"]`。
- 让增强步骤有专属断言：`pefile` 未安装时该用例 `skipTest("pefile not installed")` 并在 CI 里把 skip 视为失败（或显式 `--require-enhanced` 开关）；安装后断言解析产物非空。
- 用真实 PE/ELF 夹具（现成的 `sample.exe` 是伪 MZ + 随机字节，`pefile` 必然解析失败），换成最小合法 PE 头才能测出「解析路径真的工作」。

---

## TS-05 | high | 测试掩盖 | match_context / 抑制体系只被自造夹具验证，生产元数据无人校验

**证据**
- `.github/workflows/xbits-ci.yml:213-220`：`qa_xbits_match_context.py --rules xbits/testdata/match_context_rules.json --match-buffers xbits/testdata/match_buffers.json`。
- `xbits/testdata/match_buffers.json:1-30`：仅 6 条 SID（9103001~9103006），且每条 `"source": "testdata"`——是手写夹具。
- 生产元数据是 `规则检测/xbits/规则库元数据/match_buffers.json`（3.7MB），由 `规则检测/build_match_buffers.py:24` 生成；grep 全仓 `.github/workflows/*.yml` 与 `xbits/test/*.py`，**没有任何一处引用它**，也没有任何 CI 步骤运行 `build_match_buffers.py`。
- `xbits/test/qa_xbits_match_context.py:222-267`：断言只用 `suppressed/emitted` 计数，全部基于上面 6 条 SID 的 `buffers` 声明。

**为什么掩盖了真实问题**
抑制 key 的正确性完全取决于「规则真实匹配的 buffer」（`match_buffers.json` 的 `buffers/primary/has_payload/app_tx_lua`）。测试证明的是「给定正确元数据时逻辑对」，而**元数据本身是否与 17k 条规则一致**从未被验证。生成器改错 ALIASES（`xbits/src/analysis.rs:164` 要求与 `build_match_buffers.py` 的 ALIASES 保持一致）、规则新增后元数据忘重算，都会让线上抑制静默失效，CI 依然全绿。

**正面修复方向**
- CI 里跑 `python 规则检测/build_match_build_buffers.py`（或 `--check` 模式）并把结果与提交的 `规则库元数据/match_buffers.json` 做 diff，不一致直接 fail。
- 让 `qa_xbits_match_context.py` 至少跑一遍真实元数据：对 3~5 个真实 SID（跨 buffer 类型）验证 `primary` 与规则文本声明一致（可用 `规则检测/build_match_buffers.py` 的解析结果当 oracle）。
- 断言 `xbits/src/analysis.rs:168-188` 的 `canonical_buffer_name` 与 `build_match_buffers.py` 的 ALIASES 完全同构（可在测试里两侧各导出一份映射做集合比较）。

---

## TS-06 | high | 测试掩盖 | hook 矩阵文档承诺「不许额外规则」，代码只判子集

**证据**
- `xbits/test/qa_suricata_hook_matrix.py:10-13` docstring：`engine SID set == case.require`（no unexpected extra rule）。
- `xbits/test/qa_suricata_hook_matrix.py:247-266`：实际只做 `eve != engine`（转发完整性）、`require <= set(engine)`（不缺）、`forbid & set(engine)`（禁集）；`extra = sorted(set(engine) - require)` 只拼进 OK 行文本，**不进入 failures**。

**为什么掩盖了真实问题**
**误报**（本该被 forbid 之外语义拦住的规则开始乱命中）在这套矩阵里不会被判失败：只要 EVE 与 engine 一致，多出来的 SID 就是「一致地多」。而 require 列表是按正例写的，负例 PCAP 上不该出现的规则若不在 forbid 里，就完全隐身。文档写的是最严格口径，跑出来的是宽松口径——审阅者读 docstring 会得出「有额外命中会红」的错误结论。

**正面修复方向**
- 对「精确规则集」场景把 `set(engine) == require` 作为失败条件；对确实允许多条规则命中的场景，把 `forbid` 补全成「本 PCAP 上所有已知不应命中的 SID」，或引入 `known_extra` 白名单并在用例里显式声明。
- 至少让 `extra` 输出为 `::warning::` 并以「非空 extra 计数」写进 job summary，让误报漂移在 CI 可见；否则把 docstring 改成实际口径，别留假承诺。

---

## TS-07 | medium | 测试掩盖 | 空 require + 空 forbid 的用例恒过

**证据**
- `测试用例/backdoor_cases.json:194-201`：`c2_periodic` 的 `require: []`、`forbid: []`（全量用例里唯一双空）。
- `测试用例/assert_suricata.py:48-56`：`missing = require - actual`、`unexpected = forbid & actual`，双空时两个集合都必然为空 → 该 case 无论是否命中、命中多少条都 `OK`。
- 同一 PCAP（`c2_periodic.pcap`）正是 `.github/workflows/suricata-backdoor-c2.yml:114-125` Zeek 相关性步骤的输入；Suricata 侧对该 PCAP 实际零断言。
- `xbits/test/qa_rule_coverage.py:73-76` 覆盖集合 = require ∪ forbid，该 case 对覆盖无贡献但仍计入 `cases`。

**为什么掩盖了真实问题**
「18/18 cases passed」里有 1 条是恒真式。C2 周期性信标这类最容易被改坏的时序检测，恰好被放进了唯一没有态度断言的用例；后续若有人把该 PCAP 改坏或该规则整条失效，backdoor 场景仍然全绿（Zeek 侧只统计 `scenario=="backdoor-c2"` 的事件数，不校验具体 SID/得分）。

**正面修复方向**
- 在 `assert_suricata.py` 里拒绝「require 与 forbid 同时为空」的 case（fail with `empty case spec`），或要求每条 case 至少 `min_alert_count` 之类的显式声明。
- 给 `c2_periodic` 补 require（该项应命中的信标 SID）与 forbid（该 PCAP 已知误报 SID）；Zeek 侧同样补 `reason`/`score` 断言。

---

## TS-08 | medium | 测试掩盖 | 负例只断言「没有输出」，无法区分「正确抑制」与「引擎没工作」

**证据**
- `xbits/test/qa_xbits_context.py:58-87`：`run_case` 只 `send_events` + `time.sleep(0.25)` 读 `alerts.jsonl`；`:117-123` 的 `missing-context` / `benign-context` 断言为 `len(got) == 0`。
- 同文件 `:72` 仅等待 socket 文件出现；`:77` 的 `except Exception` 只覆盖 Python 侧异常，引擎崩溃后照常返回零行。

**为什么掩盖了真实问题**
「期望 0 条」与「引擎根本没读事件 / 分析线程 panic / 规则加载失败」产生同一个观测。抑制逻辑真正坏掉（该抑制的没抑制）会被 positive 用例抓到，但**不该抑制却也没了**这类问题不会；再加上 0.25s 固定等待，慢机器上正例反而变红、负例永远绿——测试的严格度是单向的。

**正面修复方向**
- 每个负例旁边放一个「必须产出」的对照告警（不同 5-tuple，规则保证命中），断言 `len(got)==1` 且其 SID 为对照 SID，以此来证引擎在工作；
- 用「等待到条件成立或超时」替代固定 sleep（轮询文件行数），超时本身就是失败；
- 读完 `engine.err`（`:64-70` 已重定向）并断言无 `bad hook event` / panic 关键字。

---

## TS-09 | medium | CI 假绿 | hook 运行时断言 = 一个 rule_id 子串 + 固定 sleep

**证据**
- `.github/workflows/xbits-ci.yml:66-73`：跑 zeek → `sleep 1` → `grep -q 'xb-zeek-http-request' /tmp/xbits-hook.out` → `kill ... || true`。
- `.github/workflows/xbits-ci.yml:387-393`：suricata hook 版本，`sleep 1` → `grep -q 'xb-suricata-web-sqli'`。
- `.github/workflows/xbits-images.yml:236-243`：`sleep 1` → 两个 `grep -q '"rule_id":"..."'` → `kill ... || true`。
- 同样场景已有严格断言可用：`xbits/test/assert_xbits.py:45-70`（要求 `community_id/src/dst/reason/related_sids` 非空、`related_sids` 含本 SID）。

**为什么掩盖了真实问题**
`grep` 命中的是**任意一行里出现该子串**：告警缺 `community_id`、`sid` 变成 0、`score/confidence` 缺失、甚至只转发了一条而丢失另外十条，都会通过。`sleep 1` 既是假红的来源（慢机器告警还没落盘）也是假绿的来源（只等到第一条就 grep 到）。`kill ... || true` 把「没杀掉、进程还占着 socket」的失败也吞掉。

**正面修复方向**
- 这三处统一改用 `assert_xbits.py`（或 `qa_*` 里的严格断言函数）：`--min-events N`、`--require-uid`、解析 JSON 校验字段集合；
- 把 `sleep 1` 换成「轮询直到文件出现满足条件的 JSON 行，最多 N 秒，超时失败」；
- `kill` 改为「确认退出码 0 且 socket 文件被清理」，失败即红。

---

## TS-10 | medium | CI 假绿 | stdin 桥「验证」是回声测试

**证据**
- `.github/workflows/xbits-ci.yml:158-162`：`xbits --stdin < xbits/testdata/alert.jsonl | grep -q '"signature_id":9103001'`。
- `xbits/testdata/alert.jsonl:1`：输入第 1 行本身就是含 `"signature_id":9103001` 的 EVE alert。
- `xbits/src/lib.rs:115-132`：`--stdin` 路径是 `parse_eve_line` → `alert_to_json` 的行级转换。

**为什么掩盖了真实问题**
输入里已有该子串，输出只要**原样包含**就通过——`alert_to_json` 丢弃 `src/dst/proto/community_id`、或把 Zeek 事件映射整体写错，这条 grep 都发现不了。它是本仓库唯一覆盖 stdin 桥的断言，所以该路径事实上无测试。

**正面修复方向**
- 用 Python 解析输出，逐字段断言映射：`src`/`dst`/`sport`/`dport`/`proto`/`community_id`/`signature_id` 与输入对应，且行数 == 期望告警数（`alert.jsonl` 第 2 行是 flow，应被丢弃 → 断言恰好 1 行）。
- 加一条反向用例：损坏的 EVE 行不得产生输出且不得 panic。

---

## TS-11 | medium | 测试掩盖 | 新增 file-store / files 输出在 CI 中无消费者，事件被静默丢弃

**证据**
- `docker/suricata-test.yaml:24-45`（工作区未提交改动）：新增 `- file-store: version 2 / force-filestore: yes / write-fileinfo: yes` 与 `- files: force-magic / force-hash: [sha256]`。
- `.github/workflows/xbits-images.yml:215-234`：唯一加载 `docker/suricata-test.yaml` 的 CI 路径（经 `qa_xbits_concurrent.py`）启动 xbits 时只带 `--hook-socket/--rules/--alert-file`。
- `xbits/test/qa_xbits_concurrent.py:50-56`：`Popen` 参数里没有 `--file-spool-dir`、没有 `--triage-cmd`；`xbits/src/hook.rs:265-270` 对 `is_file_event` 的处理是「pipeline 为空就 `continue`」→ files 事件被丢弃且不留日志。
- 唯一的 fileinfo→triage 测试 `xbits/test/qa_file_triage.py:99-121` 自己 `mkdir` 并按 `<sha[0:2]>/<sha256>` 手写 spool，从未由 Suricata 真实落盘（rust-auditor R14 同向）。

**为什么掩盖了真实问题**
新配置看起来「已接入并跑过 image 测试」，实际是：Suricata 把文件转存进 `/opt/xbits/filestore`（容器内，随 `--rm` 销毁），`files` 事件发到 xbits 后被静默丢弃，测试只断言了「Suricata 退出码 0 且 web_sqli 告警能到」。所以 `force-filestore`、`stream-depth`、`write-fileinfo` 这些字段写错（Suricata 的 files/file-store 配置错误在部分字段上只是警告不报错）都不会被发现。

**正面修复方向**
- 加一条真正的端到端：xbits 以 `--file-spool-dir /qa/filestore --triage-cmd "python3 /opt/xbits/triage/triage.py --stdin"` 启动，同容器跑一个含文件下载的 PCAP，断言 `event.kind=="file_triage"` 且 status 走完 `received→completed`；
- 若短期不接 triage，至少在 `qa_xbits_concurrent` 里断言「收到 files 事件但 pipeline 未配置」这条 stderr 提示存在，让「配置漂移」可见，而不是静默 `continue`。

---

## TS-12 | medium | 测试掩盖 | 规则质量 QA 数据无 CI 生成/校验，已指向已删除文件

**证据**
- `规则检测/qa_rule_quality.py:332`：把结果写到 `docs/规则质量QA数据.json`（提交产物）。
- `规则检测/docs/规则质量QA数据.json:4229-4249`：仍列 `zeek/威胁情报/botnet_apps.zeek`、`public_dns_servers.zeek`、`white_domains.zeek`，而这三个文件已在本工作区删除（`git status` 显示 `D`）。
- `规则检测/README.md:16`：仍写「`威胁情报/` 为白域名、公共 DNS、僵尸网络元数据」。
- grep `.github/workflows/*.yml`：`qa_rule_quality` 0 命中；唯一相近的是 `xbits/test/qa_rule_coverage.py`。

**为什么掩盖了真实问题**
这份 JSON 是「规则质量 QA」的唯一可视化产物，却没有任何 job 重新生成或对比，所以删除文件后它原样保留旧条目，读它的人会以为 `威胁情报/` 目录仍存在、规则仍被评估。这与怀疑点 6（删文件后引用失效）同源：失效引用不在 workflow 里（那部分已修），而在「由 workflow 本应产出但从未产出」的 QA 数据里。

**正面修复方向**
- 把 `python 规则检测/qa_rule_quality.py` 接进 `xbits-images`（该 workflow 已监听 `规则检测/**`），生成后 `git diff --exit-code` 断言产物与提交一致；
- 或在测试里断言该 JSON 的 key 集合 == 实际 `.rules`/`.zeek` 文件集合（纯静态检查，成本极低）；
- 同步修正 `规则检测/README.md:16` 与 `规则检测/zeek/README.md` 已删除目录的描述。

---

## TS-13 | low-medium | CI 假绿 | 「Zeek behavior scripts compile」只保证不报错

**证据**
- `.github/workflows/xbits-images.yml:146-154`：`docker run ... zeek -b -Cr web_sqli_uri_union.pcap <三个 score 脚本> LogAscii::use_json=T`，步骤结束即判通过。
- 同一文件 `:155-169` 的 probe-rules 两步也只有 `suricata -T`（加载验证）。

**为什么掩盖了真实问题**
`zeek -Cr` 退出码 0 只说明脚本语法/加载没问题；三个 `*_score.zeek` 是否真的产出评分、评分字段是否被 Zeek 日志写出、阈值改动是否让某个场景永远不触发，全部不校验。用 `web_sqli` 这个 Web 场景 PCAP 去跑 DNS/recon/backdoor 评分脚本，本来也几乎不会产生任何可判定的输出——步骤名与输入物料就决定了它只能是「能加载」检查。

**正面修复方向**
- 给每个 score 脚本配一条本场景的正例 PCAP，跑完后断言 `*_correlation.log` 里存在期望 `reason`/`score>=阈值` 的记录（`测试用例/assert_zeek.py` 已有此能力，可直接复用）；
- 明确把「仅加载」步骤改名（如 `Zeek scripts load`），并把「行为断言」放到各场景 workflow 里作为独立必过步骤。