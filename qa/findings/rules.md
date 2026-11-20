# 规则转译与 Zeek「纯行为化」审计（审计员：rules-auditor / task t3）

- 审计对象：`规则检测/suricata/**`（.rules / lua/ / `规则检测/xbits/规则库元数据/` / 生成器）、`规则检测/zeek/**`、
  `规则检测/convert_probe_{rules,zeek}.py`、`规则检测/{build_match_buffers,apply_lua_enhancements,gen_xbits_analysis,qa_rule_quality}.py`、
  `xbits/rules/*.json`、`xbits/testdata/*`，以及工作区未提交改动（`git status` / `git diff`）。
- 方法约束：只读静态分析（read / grep / glob / git status / git diff）；未运行 suricata、zeek、docker、cargo、python；
  未联网；本轮只新增本文件。所有 `file:line` 以当前工作区为准。
- 口径：只收「表面已完成、实际靠顺序约定/文档口号/剔除/假绿掩盖」的高信号问题；纯风格与纯文档措辞不单独立项。
- 规模基准（用于量化）：`规则检测/suricata/**` 共 51 个 `.rules`、17,477 个唯一 SID（其中 4 个自研场景目录 74 个 SID，
  转译规则 17,403 条）；`规则检测/xbits/规则库元数据/match_buffers.json` 17,477 条；49 个 `.lua` 文件；3 个 Zeek 脚本。

**结论先说**：Zeek「纯行为化」这件事本身**基本成立**（`规则检测/zeek/` 只剩 3 个纯计数脚本，
`xbits-images.yml` 里的 `zeek-rules/威胁情报/*` 三行已在 diff 中删除，docker/CI 没有残留加载）。真正的坑在 Suricata 转译：
转换器把 **Snort 的「content 在前、buffer 关键词在后」语义**原样搬进 Suricata，而 Suricata 的 sticky buffer 只对其**之后**的
content/pcre 生效 —— 5,544 条规则的锚点因此落在原始 payload 而不是声明的 buffer，另有 2,073 条**正确顺序**的规则反被当成
「dangling-http-uri」整条剔除。同时 1,546 条请求→响应状态链规则被从 Suricata 删除并宣称「交 xbits 关联」，但 xbits 里
**不存在任何 flowbits/depend/success_rules 消费代码**。结果是：`suricata -T` 全绿、规则文件看着完整，而「命中语义」和「关联能力」
两条都只在纸面上。

严重度统计：blocker 0 / high 5 / medium 6 / low 1，共 12 条。

| ID | 严重度 | 分类 | 一句话 |
|----|--------|------|--------|
| R-01 | high | 语义漂移 | 5,544 条 `content:…; http_uri;` 在 Suricata 里 buffer 只作用于其后的 pcre；同时 2,073 条正确顺序被整条剔除 |
| R-02 | high | 永远不命中 | `content:"200"; http_stat_code; content:"…"` → 后续 content 被绑到 3 字节状态码缓冲，17 条规则不可能命中 |
| R-03 | high | 元数据错误 | 生成器把 `http.uri.raw` 前缀塌缩成 `http.uri`，15 条规则元数据写错 buffer，与 xbits「raw 禁止归一化兜底」直接冲突 |
| R-04 | high | 表面处理 | 1,546 条 flowbits/depend 请求→响应链被从 Suricata 删除并宣称「交 xbits」，xbits 无任何消费代码（success_rules.json 无人读） |
| R-05 | high | 永远不执行 | 1,031 条 `lua:` 规则没有 sticky buffer，与规则库自己写的「无 buffer 则 Lua 不执行」相矛盾，且无任何测试证明这些 Lua 真的跑过 |
| R-06 | medium-high | 假绿 | 语义剔除量 14,120 条只写进 `semantic_gaps.json`（xbits 不读、CI 不查、无阈值），配套能力是否补齐无人验证 |
| R-07 | medium | 空转机制 | `dead_rules.json` 恒为 `[]`：flowbits 从不注入 + 带 flowbits 的规则先被剔除，cleanup 永远删不到东西，README 仍宣传「已清理失效规则」 |
| R-08 | medium | 文档与实现不符 | `convert_probe_zeek.py` 仍保留三个会 `mkdir`+写盘的生成器，与「仅保留解析工具函数」不符；CI 同名步骤是空转 |
| R-09 | medium | 残留引用 | `规则检测/README.md:16` 仍称 `zeek/威胁情报/` 存在；`:30` 仍把 `convert_probe_zeek.py` 描述成「情报转换器」 |
| R-10 | medium | 用错标准 | 用 Python `re.compile` 预判 Suricata PCRE2 兼容性：通过的未必能载、Python 不支持的被整条丢弃 |
| R-11 | medium | 配置漂移 | 19 处 `[$HTTP_PORTS,…]` 被展开成字面端口 `[80,443,8080,8443]`，改 var 不再生效 |
| R-12 | low | 文档与实现不符 | `xbits/README.md:249` 宣称 17,477 条规则「都有可精确获取的具体 buffer」，与 R-01/R-03 的实际锚点不符 |

---

## R-01 | high | 语义漂移 | sticky buffer 顺序被整体反转，且正确顺序反被剔除

**证据**
- `规则检测/suricata/Web攻击/SQL注入/sql.rules:3`（原样引用）：
  ```
  alert tcp any any -> any $HTTP_PORTS (… content:"select"; http_uri; nocase; pcre:"/=[+\s]*select…/isU"; lua:sqli_context.lua; sid:14010001; …)
  ```
  全量统计：转译规则 17,403 条中，**5,544 条**是 `content:"…"; http_uri;` 这种「内容在前、buffer 在后」的写法
  （严格正则 `content:"…";…; http_uri` 逐行统计）；放宽到任意 sticky buffer 关键词（含 http_header/http_cookie 等）写在其
  content/pcre 之后的有 **5,776 条**，其中 **3,674 条**在 buffer 之后又出现了 content/pcre。
- 转换器把这个顺序当成「等价」：`规则检测/convert_probe_rules.py:346` `out = URICONTENT_RE.sub(lambda m: f'content:"{m.group(1)}"; http_uri;', out)`
  —— `uricontent` 被改写成 `content` 在前、`http_uri` 在后。文档同样把它写成等价转换：
  `规则检测/docs/规则归档与转换方案.md:62`「`uricontent:"X"` → `content:"X"; http_uri;`（等价）」。
- 反向的「buffer 在前、content 在后」（Suricata 正确顺序）被判为非法并整条丢弃：
  `规则检测/convert_probe_rules.py:296-299`
  ```python
  if tl == "http_uri" and not prev.lower().startswith("content:"):
      return "dangling-http-uri"
  ```
  对应 `规则检测/xbits/规则库元数据/semantic_gaps.json` 中 `"dangling-http-uri": 2073`。
- 同一仓库里两种顺序并存，说明转换链路没有统一约定：自研场景规则用**前置** buffer
  （`规则检测/suricata/后门通信/命令与控制信标规则.rules:35` `http.uri.raw; bsize:>0; lua:c2_beacon.lua;`，
  `规则检测/suricata/DNS隧道与带外检测/DNS隧道与带外检测规则.rules:49-53` `dns.query; to_lowercase; dotprefix; dataset:…`），
  转译规则用**后置** buffer（上引 sql.rules:3）。
- CI 只做加载验证，不校验命中语义：`.github/workflows/xbits-images.yml:155-161`「Converted probe rules must load in Suricata」
  跑的是 `suricata -T`。17,403 条转译规则里没有任何一条进过 PCAP 回放（`xbits/test/qa_suricata_hook_matrix.py:38-56`
  的用例只覆盖 4 个自研场景目录，`测试用例/{cases,recon_cases,web_cases,backdoor_cases}.json` 里没有 9103/9104/11xxx/13xxx 之外的转译 SID）。

**为什么是绕过而非根治**
Suricata 的 sticky buffer 是「设定之后所有 content/pcre 的匹配面」，不是 Snort 那种「修饰前面那条 content」的修饰词。
把顺序原样搬过来，等于把「在 URI 里找 select」变成「在整包 payload 里找 select，而在 URI 里跑 pcre」——
锚点变宽（误报上升）、精确约束落错字段（漏报）。`suricata -T` 只证明「能加载」，而这次审计最需要的恰恰是「命中语义没变」，
CI 对此完全没有断言，于是 5,544 条规则的语义反转被一次绿色加载掩盖。更严重的是反向处理：真正符合 Suricata 语法的
2,073 条规则被 `dangling-http-uri` 整条删掉，删除理由还是错的。

**正面修复方向**
- 转换器改成「先归约到 Suricata 语义树，再线性化」：解析出 content 列表和 buffer 归属后，按 `buffer; content:"…"; 修饰词;` 顺序
  重新生成；`uricontent` 必须产出 `http_uri; content:"X";`，绝不能 `content:"X"; http_uri;`。
- 删除 `dangling-http-uri` 这一条误判（`convert_probe_rules.py:296-299`），改为「buffer 无后继 content/pcre 时告警」。
- 加一条**语义级**回归：对每个 buffer 类型各挑 2~3 条转译规则，用「只在该 buffer 命中 / 只在该 buffer 之后的位置命中」的构造
  PCAP 断言命中与不命中，并把它接进 `xbits-images`。仅 `-T` 通过不算修复。
- 修完后把 `规则检测/docs/规则归档与转换方案.md:62` 的「等价」结论一并撤回，写明 sticky buffer 是前向作用域。

## R-02 | high | 永远不命中 | `http_stat_code` 之后的 content 被绑到 3 字节缓冲

**证据**
- `规则检测/suricata/Web攻击/文件包含/file_include.rules:26`（sid:13060038，另有 :27-:42 合计 14 条）：
  ```
  … content:"200"; http_stat_code; content:"|0d 0a 0d 0a|"; content:"|23 21 2f|bin|2f|bash"; nocase; distance:0; within:11; …
  ```
- `规则检测/suricata/恶意软件/后门/backdoor.rules:9`（sid:10020245，另有 :10-:11）：
  ```
  … content:"|3c|html|3e 3c|head|3e 3c|title…"; http_stat_code; …
  ```
- 精确统计（按「buffer 关键词之后还有 content/pcre」扫描全部转译规则）：**17 条**规则在 `http_stat_code` 之后紧跟
  content/pcre，例如上面 file_include.rules:26-42、backdoor.rules:9-11。
- 这 17 条同时被写进元数据：`规则检测/xbits/规则库元数据/match_buffers.json` 中 `13060043` 的
  `"buffers": ["http.header", "http.status"]`，`primary: "http.header"` —— 元数据说它匹配 `http.header`，
  而规则文本里 `http_header` 出现在第 4 个 content 之后，锚点实际在原始 payload。
- 这些规则在 CI 里只做 `-T`（`.github/workflows/xbits-images.yml:155-161`），从没有输入过 HTTP 响应。

**为什么是绕过而非根治**
`http_stat_code` 在 Suricata 里是 3 字节的 sticky buffer（"200"）。它一旦出现，后续所有 content 都只能在"200"这 3 个字节里找，
`|0d 0a 0d 0a|`、`|23 21 2f|bin|2f|bash` 这种多字节串**在数学上不可能命中**。这 17 条规则因此是「文件在、SID 在、CI 绿、
永远不报警」的典型死规则；它们体积小、不报错、不告警，最容易被"加载通过"掩盖。同时 `content:"200"` 落在 payload 面上，
命中条件反而变成「payload 里随便出现 200 且状态码后面还有 CRLFCRLF」——两个方向都错。

**正面修复方向**
- 转换器对 `status_code:N` 生成 `http_stat_code; content:"N";`（buffer 前置），并保证同一条规则里只允许一个状态码约束、
  且它必须是该条规则的最后一个 buffer 段；其后若要继续匹配 body/header，必须显式重置 buffer（`file_data;` / `http_header;`）。
- 加静态断言：任何规则中，某个 sticky buffer 之后若再出现 content/pcre，且该 buffer 的容量上界（状态码=3、method≤16 等）
  小于 content 长度，直接 fail 生成流程。
- 用 `file_include`/`backdoor` 这两组构造 PCAP 做「应当命中」回归，补进 hook 矩阵。

## R-03 | high | 元数据错误 | `http.uri.raw` 被生成器塌缩成 `http.uri`

**证据**
- `规则检测/build_match_buffers.py:141`：
  ```python
  if n.startswith(PREFIXES):          # 137
      if n.startswith("http.request_header") or n.startswith("http.response_header"):
          return "http.header"
      if n.startswith("http.uri"):
          return "http.uri"           # 141-142：http.uri.raw 也命中这里
  ```
  `"http.uri.raw".startswith("http.uri")` 为真，于是 dotted 写法的 raw URI 被归一到**归一化 URI**。
  只有下划线写法被正确映射：`规则检测/build_match_buffers.py:31` `"http_raw_uri": "http.uri.raw"`。
- 实际后果（生成产物可核对）：`规则检测/suricata/Web漏洞利用/Web漏洞利用规则.rules:45` 用的是 `http.uri.raw`，
  但 `规则检测/xbits/规则库元数据/match_buffers.json` 中 `"9103001": {"buffers": ["http.uri"], "primary": "http.uri"}`。
  同类还有 `9104001`、`9110002`、`9110004`（`规则检测/suricata/后门通信/命令与控制信标规则.rules:35` `http.uri.raw;`），
  合计 15 条规则使用 dotted `http.uri.raw`（Web漏洞利用 9 条、后门通信 4 条、WebShell后门通信 2 条）。
- 这与 xbits 的硬约定直接冲突：`xbits/src/analysis.rs:248-250`
  ```
  // http.uri.raw 必须来自 match_context 导出，禁止用归一化值兜底。
  "http.uri" => e.uri.clone(),
  ```
  `http.uri.raw` 被列入 `CONTEXT_ONLY_BUFFERS`（`xbits/src/analysis.rs:144-153`），本来只能走补丁导出的精确值。
  元数据却把它写成 `http.uri`，xbits 于是拿 EVE 的归一化 `http.url` 去做抑制 key。

**为什么是绕过而非根治**
这是两个组件各写一份映射表（`build_match_buffers.py` 与 `analysis.rs` 的 `canonical_buffer_name`，后者注释还写着
「必须与 规则检测/build_match_buffers.py 的 ALIASES 保持一致」，见 `xbits/src/analysis.rs:163-164`）却没有一致性测试的必然结果。
"raw vs 归一化" 是安全相关语义（`%3C`/大小写/%2e 的还原与否决定同一 URL 是否同一 key），把它静默近似掉，
等于让「精确抑制」在 15 条规则上退化回被明令禁止的兜底路径，而且不报错、不打日志、CI 也测不到（CI 只用
`xbits/testdata/match_buffers.json` 里 6 条虚构 SID，见 `.github/workflows/xbits-ci.yml:216-220`）。

**正面修复方向**
- `canonical_buffer` 精确匹配整串而不是前缀：显式列出 `http.uri` / `http.uri.raw` / `http.uri.query`，并对未知 dotted 名
  直接返回 `None` 而不是放行。补单测：`canonical_buffer("http.uri.raw") == "http.uri.raw"`。
- 加一条跨语言一致性测试：从 `build_match_buffers.py` 导出一份 `名→规范名` 映射，与
  `xbits/src/analysis.rs:168-188` 的 `canonical_buffer_name` 做集合相等断言（可放在 `xbits/test/` 里，用 Rust 侧导出一个
  JSON dump 再比）。
- `qa_xbits_match_context.py` 至少对 3 个真实 SID（含 9103001 这类 raw 规则）用**生产元数据**跑一遍，而不是只用 testdata 夹具。

## R-04 | high | 表面处理 | 1,546 条请求→响应状态链「交 xbits」，xbits 里没有消费者

**证据**
- 转换器主动剔除全部状态链规则，并把「交 xbits」写进注释与输出：
  - `规则检测/convert_probe_rules.py:676-680`：任何含 `flowbits:` 的规则 `meta["skip"]="flowbits-correlation"`，不进 Suricata；
  - `:683-687`：任何带 `depend`/`scope_id` 的规则 `meta["skip"]="dependency-correlation"`；
  - `:850-852`：被剔除的依赖规则写成 `规则检测/xbits/规则库元数据/success_rules.json`（当前 996 条）。
- 计数（`规则检测/xbits/规则库元数据/semantic_gaps.json`）：`flowbits-correlation: 670`、
  `dependency-correlation: 876`、`state-noalert: 527`、`no-dependency: 4708`。
- 文档明确承诺由 xbits 接管：`规则检测/README.md:6-7`「转换规则不注入 flowbits、depend/scope 状态链，相关依赖交 xbits 关联」；
  `规则检测/README.md:19`「`success_rules.json`：PVS 成功确认依赖（供 xbits 做请求→响应关联）」。
- xbits 侧**没有**任何对应实现：`grep -rn "success_rules\|success-rules\|depends\|dependency" xbits/` 命中 0 行；
  `xbits/src/main.rs:71-184` 的全部 CLI 参数中没有 success-rules / depend 相关开关；
  `xbits/src/analysis.rs` 的 `RuleMeta`（`:82-90`）只反序列化 `tier/category/name`，`rules_meta.json` 里的
  `depends/scopes/holetype` 全部被丢弃。

**为什么是绕过而非根治**
「把这些规则从 Suricata 删掉，交给中央引擎」只有在中央引擎真的实现了关联时才是根治。现状是：Suricata 侧删掉了
1,546 条状态链规则（不再有任何 flowbits 状态机），xbits 侧既没有 flowbits 语义、也没有 success_rules 读取、也没有
请求→响应配对代码。检测能力净减少 1,546 条，而所有可见证据（注释、README、`semantic_gaps.json` 的措辞）都指向
「已迁移」。这是典型的「删除即修复」——把一条检测链路从 A 处删掉、在 B 处写上 TODO 式的注释，然后用 `suricata -T` 绿
和 `cargo test` 绿（测试也不测这条链路）证明一切正常。

**正面修复方向**
- 二选一，必须明写：
  1) 在 xbits 里实现：`--success-rules` 加载 `success_rules.json`，按 `community_id + sid` 做请求→响应配对，产出
     `correlated=true` 与「成功确认」评分，并有端到端用例（同一条 PCAP，配对成立/不成立两种断言）；
  2) 不实现就把这 1,546 条规则**保留在 Suricata**（恢复 flowbits，或在转换时对 `depend` 规则直接合并成单条规则），
     并删除文档里「交 xbits 关联」的承诺。
- 无论选哪条，都对 `semantic_gaps.json` 的每个 reason 建立「能力归属表」：reason → 由谁接管 → 接管方是否已有测试。

## R-05 | high | 永远不执行 | 1,031 条 `lua:` 规则没有 sticky buffer

**证据**
- 规则库自己写明的约束：`规则检测/suricata/DNS隧道与带外检测/DNS隧道与带外检测规则.rules:243-244`
  ```
  #       关键：Lua 规则必须带 buffer（请求 dns.query，响应 dns.queries.rrname）；
  #       只有 hook 没有 buffer 的规则会被当作 straight match，脚本不会执行。
  ```
- 实测统计：转译规则里带 `lua:` 的共 7,024 条，其中 **1,031 条没有任何 sticky buffer**。例子：
  - `规则检测/suricata/Web攻击/SQL注入/sql.strong.rules:150`（sid:13020170）
    `content:"|0D 0A|user-agent|3A 20|pangolin"; nocase; lua:sqli_context.lua;`
  - `规则检测/suricata/Web攻击/SQL注入/sql.rules:92` 等同文件 1,031 条。
- 这些 `lua:` 是批量注入的，注入器只看 flow 方向、不看有没有 buffer：`规则检测/apply_lua_enhancements.py:101-102`
  （`elif mode == "all": use = script`）以及 `:35` `new = re.sub(r"(?=\s*sid\s*:)", f" lua:{script}; ", line, count=1)`。
- 元数据把这些规则一律当「精确 payload 规则」：`规则检测/xbits/规则库元数据/match_buffers.json` 中
  `"13020170": {"buffers": ["payload"], "primary": "payload", "has_payload": true, "app_tx_lua": false}`，
  `xbits/README.md:246-249` 也据此宣称「带 `lua:` 的规则同样是可精确抑制的 payload/sticky buffer 规则」。

**为什么是绕过而非根治**
「Lua 上下文增强」是这批规则降低误报的唯一手段（例如 `sqli_context.lua` 会重做 URL 解码、注释归一化、布尔/时间盲注判定）。
如果规则库里自己写的「无 buffer 则脚本不执行」成立，那么这 1,031 条的 Lua 门是空的：规则退化成纯 content 匹配，
误报控制完全失效，而元数据、README、CI 都把它当成「已增强」。如果该说法不成立（Suricata 对无 buffer 的 `lua:` 走 packet
hook），那说明规则库自己的关键注释是错的，同样需要修。**两种情况都没有任何测试能区分**：`qa_suricata_hook_matrix.py`
只覆盖 4 个自研场景目录，转译规则从未回放 PCAP，所以「Lua 到底跑没跑」在生产与 CI 中都是未知数。

**正面修复方向**
- 先做事实校准：写两条最小规则（同样 content、一条带 `http.uri;` 前置 buffer、一条不带），用同一 PCAP 观察 Lua 的
  `init/match` 是否被调用（可在脚本里 `print` 到 stderr），把结论写回 `DNS隧道与带外检测规则.rules:243-244`。
- 按结论二选一：给这 1,031 条补 buffer（`http.uri;`/`http.request_body;` 等，取决于脚本检查的字段），或从这些规则上撤掉
  `lua:` 并在元数据里如实标成「无增强」。
- `apply_lua_enhancements.py` 增加前置条件：目标规则必须已有 sticky buffer，否则 fail（而不是照注）。
- 补一条 CI 断言：转译规则中 `lua:` 且无 buffer 的条数必须为 0。

## R-06 | medium-high | 假绿 | 14,120 条语义剔除只留一份没人读的 JSON

**证据**
- `规则检测/xbits/规则库元数据/semantic_gaps.json` 的 `counts` 合计 14,120 条（`http-only-uri-unsupported: 2947`、
  `dangling-http-uri: 2073`、`dsl-semantic: 1634`、`no-dependency: 4708`、`dependency-correlation: 876`、
  `flowbits-correlation: 670`、`state-noalert: 527`、`convert-rule-none: 263`、`isdataat: 136`、`unsupported: 89`、
  `negated-pcre: 80`、`method-unsupported: 48`、`mixed-position: 39`、`response-direction-conflict: 14`、
  `rawbytes-unsupported: 8`、`rate-unsupported: 6`、`duplicate-position: 1`、`false-positive-quarantine: 1`）。
  即：活跃转译规则 17,403 条 + 剔除 14,120 条 = 31,523 条源规则里，**44.8%** 没进 Suricata。
- 这份 JSON 唯一的生产者/消费者是转换器自己（`规则检测/convert_probe_rules.py:832-838` 写盘）；`xbits/src/` 全文
  grep `semantic_gaps` 命中 0 行；`.github/workflows/*.yml` 里也没有任何步骤读取或校验它（唯一相关的
  `xbits-images.yml:99-100` 跑的是另一个脚本 `qa_rule_coverage.py`，只覆盖 4 个场景目录）。
- 文档把它描述成「可追溯」的治理手段：`规则检测/docs/转换规则清理报告.md:10`「语义/行为/关联隔离 14,120 → 见
  `semantic_gaps.json`，不进入 Suricata」。

**为什么是绕过而非根治**
「我们记录了每一条剔除原因」听起来是可审计的，但没有任何自动机制保证：① 剔除量不会随某次转换器改动暴涨；
② 某个 reason 对应的规则集合不会悄悄换成员；③ 被剔除的检测能力由谁补上。这三个都没人守，JSON 就只是一个事后可查的
墓碑。R-04 的 1,546 条就是这条路径的直接后果——剔除被当成"处理完成"，补齐被写成注释。加上 R-01 里 2,073 条「正确的规则
被错误地剔除」，说明这份 JSON 里的 reason 本身也可能是错的，但没有任何测试会去质疑它。

**正面修复方向**
- 把 `semantic_gaps.json` 纳入 CI 契约：每次转换后与提交版本做 diff，**每个 reason 的 SID 集合变化必须有显式白名单**，
  新增剔除直接 fail。
- 对每个 reason 建「能力归属」字段（谁接管、有无测试），像 R-04 那样二选一落地；没有归属的 reason 视为 bug。
- 剔除率设阈值（例如单 reason 环比 +5% 报警），并在 `qa_rule_coverage.py` 里把「剔除集合 ∩ 现有用例 SID」纳入检查。

## R-07 | medium | 空转机制 | `dead_rules.json` 永远是 `[]`

**证据**
- 现网产物就是空数组：`规则检测/xbits/规则库元数据/dead_rules.json` 内容为 `[]`（2 字节）。
- 机制上也不可能非空：
  - 转换器从不注入 flowbits —— `规则检测/convert_probe_rules.py:744-745` `flowbit_set = None` 然后
    `rule = convert_rule(line, flowbit_set, None)`，所以 `:360-363` 的注入分支永远不执行；
  - 带 flowbits 的源规则更早在 `:676-680` 就被整条剔除（reason=`flowbits-correlation`）；
  - 于是 `cleanup_dead_flowbits()`（`:462-505`）扫描到的 `flowbits:isset` 既没有 set 方、也没有可删对象，`removed` 恒空；
  - 两次清理（`:864`、`:887`）都是空转。
- 文档仍以它为卖点：`规则检测/README.md:20`「`dead_rules.json`：已清理的失效规则」。

**为什么是绕过而非根治**
一个「清理失效规则」的机制长期产出空集，会被读成「没有失效规则，规则库很干净」。真实情况是：失效规则的主要来源
（状态链规则）根本没进 Suricata，另一部分（永不命中的 content 顺序错误，见 R-01/R-02）不在这个机制的检测范围内。
用一个恒空的产物给规则质量背书，比不做更误导。

**正面修复方向**
- 删除无效的 flowbits 清理链路，或把它改成有实际输入的形式（若恢复 flowbits 注入，则需同时恢复配对校验）。
- 真正的「失效规则」检测应基于可命中性：静态规则（buffer 容量 vs content 长度、buffer 顺序、互斥条件）+ 动态（PCAP 覆盖）。
  这两项都应产出非空判定条件和 CI 断言，而不是一个永远为空的 JSON。

## R-08 | medium | 文档与实现不符 | `convert_probe_zeek.py` 仍留着会写盘的生成器，CI 步骤空转

**证据**
- `规则检测/convert_probe_zeek.py:8-12` 声称「这些数据脚本已全部移除……本转换器现仅保留解析工具函数供历史转译参考；
  不再向 `规则检测/zeek/` 输出任何数据脚本」，但文件里仍有三个完整生成器，每个都会 `mkdir(parents=True, exist_ok=True)`
  并 `write_text` 到 `OUT = ROOT / "zeek"`（`:26`）：
  - `write_crawler_whitelist`（`:50`，写盘 `:55`、`:138`）
  - `write_white_domains`（`:141`，写盘 `:144`、`:169`）
  - `write_public_dns`（`:172`，写盘 `:175`、`:186`）
  只是 `main()` 不再调用它们（`:189-204`）。「解析工具函数」与「数据脚本生成器」不是一回事。
- 主流程仍强制要求 `--src/etc_fw/utm` 目录存在，否则返回 2：`:193-196`。也就是说这个"什么都不生成"的脚本仍会
  因为一个它已经不读的输入路径而失败。
- CI 里同名步骤是空转：`.github/workflows/xbits-images.yml:136-142`
  ```
  - name: Convert probe rules to Zeek behavior data
    run: if [ -d "$HOME/probe-rules" ]; then python 规则检测/convert_probe_zeek.py --src "$HOME/probe-rules"
         else echo "Probe-rule export not available in CI; using committed Zeek conversion"; fi
  ```
  两种情况都不会真的"convert"：仓库里已没有任何 committed Zeek 转换产物（`规则检测/zeek/` 只剩 3 个行为脚本），
  `else` 分支的描述已失效；`then` 分支只打印一行并 exit 0。

**为什么是绕过而非根治**
「Zeek 纯行为化」如果是靠「删目录 + 在转换器里注释掉调用」完成的，那这条约束没有护栏：三个生成器仍在、`OUT` 仍指向
`规则检测/zeek`，任何人把 `main()` 里加回一行调用，`规则检测/zeek/威胁情报/` 就会在下次转换时原样重建，而 CI 不会发现
（它只判断目录存在与否，不校验 `zeek/` 下不得出现数据脚本）。

**正面修复方向**
- 物理删除三个写盘函数与 `OUT` 常量；保留的解析函数挪到独立的 `probe_parse.py`，并在文件顶部写清「本仓库不再产出 Zeek
  数据脚本」。
- CI 加一条守卫：`规则检测/zeek/**/*.zeek` 只允许出现数据脚本白名单之外的内容（禁止 `set[string] = {…}` 这类名单字面量、
  禁止 `@load` 情报文件），或直接断言目录内文件数/文件名集合等于 3。
- 把 `xbits-images.yml:136-142` 这个步骤删掉（它已无产物），或改名为「verify zeek has no data scripts」并断言非空。

## R-09 | medium | 残留引用 | 规则检测 README 仍在描述已删除的 `zeek/威胁情报/`

**证据**
- `规则检测/README.md:15-16`
  ```
  - `zeek/`：**只做行为分析**（`.zeek`）：DNS 突发、侦察 404/unique URI、C2 重复 URI；
    `威胁情报/` 为白域名、公共 DNS、僵尸网络元数据。不再包含 content/UA 签名匹配。
  ```
  而 `git status` 显示 `规则检测/zeek/威胁情报/{botnet_apps,public_dns_servers,white_domains}.zeek` 三个文件已 `D`，
  目录已不存在（`规则检测/zeek/` 现只有 3 个场景脚本 + README）。
- `规则检测/README.md:30` 与 `:42` 仍把转换器描述成会产生情报数据：「`convert_probe_zeek.py`：外部探针 Zeek 行为/情报转换器」，
  并给出「重新生成转换规则」的命令。
- 下游产物同样过期（交叉引用：tests-auditor 的 TS-12）：`规则检测/docs/规则质量QA数据.json:4229-4243` 仍收录
  `zeek/威胁情报/botnet_apps.zeek`、`public_dns_servers.zeek`、`white_domains.zeek` 三个已删文件的统计。
- 与之相对，`规则检测/zeek/README.md:23-24`、`allowlist/README.md:56` 的表述是正确（已删除、已迁移）的，
  说明删除只在部分文档里收尾。

**为什么是绕过而非根治**
「Zeek 纯行为化」是这次架构决策的核心卖点，而面向新人的入口文档第一屏仍在说 Zeek 目录里有情报数据。文档不一致本身不是
安全问题，但它让「删除是否彻底」这个判断失去可信来源——同一个仓库里三份文档三个说法时，只能靠逐个 `ls` 才能确认现实。
再叠加 R-08（生成器还在），后来者很可能按 README:42 再跑一次转换器，把目录重建回去。

**正面修复方向**
- 删掉 `规则检测/README.md:16` 的 `威胁情报/` 描述，改成「Zeek 不持有任何名单/情报（见根目录 `allowlist/`、`threat-intel/`）」。
- `:30`/`:42` 改为「历史转译工具，当前不产出任何 Zeek 数据脚本」，与 `convert_probe_zeek.py` 的实际行为一致。
- 重跑 `qa_rule_quality.py` 刷新 `规则检测/docs/规则质量QA数据.json`（或删掉 zeek 段），并把「文档里提到的路径是否存在」
  做成一条静态检查。

## R-10 | medium | 用错标准 | 用 Python `re` 预判 Suricata PCRE2 兼容性

**证据**
- `规则检测/convert_probe_rules.py:405-421`：
  ```python
  if tl.startswith("pcre:"):
      m = re.match(r'pcre\s*:\s*"(.*)"$', t, re.S)
      if m:
          s = m.group(1); last = s.rfind("/")
          if s.startswith("/") and last > 1:
              pat, flags = s[1:last], s[last + 1:]
              if any(c in flags for c in "RPB"): return None
              if sum(flags.count(c) for c in "UBP") > 1: return None
              try: re.compile(pat)
              except Exception: return None
  ```
  即：用 CPython 的 `re` 能否编译，来决定这条规则是否进入 Suricata。
- 同一逻辑在 `:289-292`（`semantic_skip_reason`）里有一份近似重复，两处判断口径不完全一致（前者只看 flags，后者看整行），
  意味着同一条规则可能在不同阶段得到不同结论。
- 产物：`semantic_gaps.json` 里 `convert-rule-none: 263`、`negated-pcre: 80` —— 这些 SID 永久离开 Suricata，
  且没有记录「原 PCRE 长什么样」（`rules_meta.json` 只保留 `classtype/references/status_code/rate/skip`）。

**为什么是绕过而非根治**
Python `re` 与 PCRE2 是两个不同的正则引擎：Python 支持的构造（如 `(?P<name>…)`、`\A`）PCRE2 未必等价，
PCRE2 支持的构造（`\K`、`(?R)`、possessive quantifier `a*+`、`\p{L}`）Python 直接编译失败。于是这套「预检」同时产生两类错误：
- **假通过**：Python 能编译、Suricata 载入时才报错 → 靠 `suricata -T` 兜底，而 `-T` 只覆盖被选中的规则集，
  且失败时人工去加 `unsupported-sids.txt`（`convert_probe_rules.py:579-586`）——这是事后打补丁，不是根治；
- **假拒绝**：合法的 PCRE2 规则被 Python 误杀 → 静默进入 `convert-rule-none`，无人复核。
把「能否加载」这种二进制判断塞进一个"尽力而为"的启发式里，等于用不可靠的标准给出确定性的删除决定。

**正面修复方向**
- 删掉 `re.compile` 预检，改为**由 Suricata 判定**：转换后跑一次 `suricata -T`，把报错 SID 与原因结构化写回
  `unsupported-sids.json`（含原始 pcre 文本），并对每次新增项要求人工确认。
- 规则元数据必须保存被剔除的原始 `pcre` 与 reason，便于复核「这条到底该不该删」。
- 若必须做静态预检，应使用与 Suricata 同源的 PCRE2 绑定（`pcre2` python 包），并把它声明为构建依赖，而不是 CPython `re`。

## R-11 | medium | 配置漂移 | `[$HTTP_PORTS,…]` 被展开成字面端口

**证据**
- `规则检测/convert_probe_rules.py:338-343`：
  ```python
  out = re.sub(r"\[\$HTTP_PORTS([^\]]*)\]",
               lambda m: "[80,443,8080,8443" + m.group(1) + "]", out)
  ```
- 生成产物里出现字面端口列表：全部转译规则中 **19 处** 含 `[80,443,8080,8443` 的硬编码端口组。
- 而三份 probe 配置自己声明的 `HTTP_PORTS` 是 `[80,8080,8000,443,8443]`（各不相同）：
  `docker/probe-rules-validate.yaml:17`、`docker/probe-rules-production.yaml:17`、`docker/probe-rules-weak.yaml:17`。
- 同一批配置还把全部网段写成 `any`：`docker/probe-rules-production.yaml:8-10`
  （`HOME_NET/EXTERNAL_NET/CLIENT_NET: "any"`），而规则文本里大量使用 `$CLIENT_NET`/`$EXTERNAL_NET`
  （如 `规则检测/suricata/后门通信/命令与控制信标规则.rules:20`）。

**为什么是绕过而非根治**
把变量"展开"成常量看起来只是语法变通，实际是把「运维可改的配置」变成「编译进规则文本的常量」：改 `HTTP_PORTS` 变量对这 19 条
规则不再生效，且没有任何地方记录「这 19 条曾经依赖变量」。加上 production profile 把网段全设为 `any`，说明这份「生产强规则
加载集」目前只是"能加载"的验证器，而不是可上线语义。这两点都在 `suricata -T` 下完全绿。

**正面修复方向**
- 保留变量：Suricata 支持 `$HTTP_PORTS` 直接用（配置里已经定义），转换时只处理真正不支持的 `[$A,$B]` 混合写法，
  并把它拆成两条规则或显式 `vars` 引用，而不是硬编码。
- production profile 的变量必须来自部署配置（`!$HOME_NET` 等），并在 CI 里对「production profile 中 any 网段数量」设上限。
- 加一条转换产物断言：生成规则中不得出现 `[80,443,8080,8443` 这类字面端口组。

## R-12 | low | 文档与实现不符 | README 把「生成器的输出」当成「规则事实」

**证据**
- `xbits/README.md:246-249`
  ```
  只有当真规则既无具体 buffer、也无 content/pcre、仅挂 lua 时，才标记 app_tx_lua: true……
  当前规则库不存在此类规则（全部 17477 条都有可精确获取的具体 buffer）。
  ```
- 但 `match_buffers.json` 里 `app_tx_lua` 恒为 `false`（0 条 true / 17,477 条 false），这个结论是生成器
  `规则检测/build_match_buffers.py:185-190` 把 `lua` 从 buffers 中剔除后的必然结果，不是独立校验；
  同时 R-03 已证明同一份元数据在 `http.uri.raw` 上写错 buffer、R-01 证明 5,544 条规则的实际锚点与 metadata 声称的
  buffer 不一致。也就是说「17477 条都有可精确获取的 buffer」这句话，证据来自被 R-03 证伪的那张表。

**为什么是绕过而非根治**
用生成器的输出给自己背书，循环论证最省事：只要生成器逻辑不变，README 永远"正确"，而生成器逻辑恰恰是问题所在（R-03）。
这类文档会让人误以为「buffer 精确性」已经被验证过，从而不会去补真正的验证（跨语言映射一致性、真实 SID 的元数据回归）。

**正面修复方向**
- 把这句话改成可验证的表述：「`match_buffers.json` 由 X 生成，其正确性由测试 Y 保证」，并真的补上 Y（见 R-03 修复方向）。
- README 中所有「全部 N 条都…」式断言，都必须指向一条 CI 断言或一个可复现的检查命令。

---

## 对任务中 5 个重点怀疑点的逐条结论

1. **是否仍残留对 `规则检测/zeek/威胁情报/*`、`zeek-rules/威胁情报/*` 的加载/引用？**
   - 加载侧**证伪（已清干净）**：`.github/workflows/xbits-images.yml` 的 Zeek 编译步骤里三行 `zeek-rules/威胁情报/*.zeek`
     已在 `git diff` 中删除；`grep -rn "zeek-rules/威胁情报" .` 0 命中；`docker/xbits-zeek.Dockerfile:32` 只整目录
     `COPY 规则检测/zeek/`（现在只有 3 个行为脚本）。
   - 文档/产物侧**证实（仍残留）**：`规则检测/README.md:16`、`:30`、`:42` 与 `规则检测/docs/规则质量QA数据.json:4229-4243`，见 R-08/R-09。
2. **`convert_probe_zeek.py` 是否还保留已删除产物的生成/写入逻辑或死函数，运行是否会重建目录？**
   - **证实**：三个写盘生成器 + `OUT = ROOT/"zeek"` 仍在（R-08）。**运行 main() 当前不会重建目录**（main 不调用它们），
     但机制上没有护栏，重新接线即重建。
3. **Suricata 规则转译是否有字段丢弃/语义漂移、sid 冲突、metadata 死字段？**
   - **语义漂移证实**：buffer 顺序反转（R-01）、`http_stat_code` 后置 content（R-02）、`http.uri.raw` 塌缩（R-03）。
   - **sid 冲突证伪**：全部 51 个 `.rules` 的 `sid:` 去重后 17,477 个，重复 0 条（脚本逐文件比对）。
   - **metadata 死字段部分证实**：`primary`/`has_payload`/`source` 在 Rust 侧只被用于两条诊断日志
     （`xbits/src/analysis.rs:726`、`:732`），不参与 key 构造；`app_tx_lua` 恒 false（R-12）。
4. **Lua 是否有 pcall/异常吞掉导致规则静默失效？**
   - **证伪**：49 个 `.lua` 文件中 `pcall`/`xpcall` **0 处**。但发现了更严重的等价问题：1,031 条无 buffer 的 `lua:` 规则
     可能整段不执行（R-05），以及 `dns_tunnel_confirm.lua` 这类靠 `flowbits:isset` 触发却被 R-04 整体删除的状态链。
5. **是否存在「规则看起来在但永远不命中」？**
   - **证实**：`http_stat_code` 后置 content 的 17 条（R-02）；5,544 条锚点落错 buffer 的规则（R-01，部分仍会命中但语义相反）；
     若 R-05 的 Lua 约束成立，则 1,031 条的上下文门形同虚设。核心成因一致：**没有一条语义级回归**，只有 `suricata -T` 加载验证。
