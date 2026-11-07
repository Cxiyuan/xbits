# 项目提示词 · DNS 隧道与带外探测检测

## 1. 项目定位

本仓库维护 DNS 隧道与带外探测（OOB）检测能力，交付物是**检测引擎内**的规则与脚本：

- **Suricata 8.0.8**：规则文件 + 规则内嵌 Lua（`lua:` / `luaxform`）
- **Zeek 9.0.1**：Zeek 脚本（`.zeek`）与配套检测逻辑

检测逻辑必须运行在 Suricata 或 Zeek 引擎内，**不交付**脱离检测引擎的日志分析脚本、独立 Python 工具或离线扫描器。

## 2. 硬性版本约束

- 只支持 **Suricata 8.0.8** 和 **Zeek 9.0.1**。
- **不做向下兼容**，不添加其他 Suricata/Zeek 版本的兼容分支或条件代码。
- 不使用目标版本不存在的关键字、Lua API、Zeek 内置函数或日志字段。
- 修改规则/脚本前，先核对 8.0.8 / 9.0.1 的官方文档或源码；无法确认时，明确标注“待验证”，不要猜测。
- CI 中的版本必须**精确锁定**：`8.0.8`、`9.0.1`，禁止 `latest`、`stable`、`master`、浮动 tag。

## 3. 验证与构建：只认 GitHub Actions

- **所有验证和构建全部依托 GitHub Actions**，本地检查只作为提交前预检，不作为“已验证”的依据。
- 不得在没有 CI 结果的情况下声称“测试通过”“已验证”“零误报”。
- CI 未运行或失败时，必须在回复中明确说明：未通过/未验证及原因。
- 新增或修改规则、Lua、Zeek 脚本时，必须同步更新 CI 用例；CI 不通过不得合并。

### 3.1 CI 必须覆盖的 Suricata 8.0.8 检查

- 安装/构建精确版本 Suricata 8.0.8。
- `suricata -T` 加载完整规则、dataset、Lua 脚本；加载失败即失败。
- 检查规则结构：SID 唯一、必填关键字、括号/引号平衡、`pcre` 分隔符、`dns.rrtype` 取值。
- 检查 dataset：条目带前导点、小写、无注释/逗号、无重复。
- 检查每个 `lua:` 引用：文件存在、含 `init`/`match`。
- PCAP 回归：正例必须命中、反例必须不命中；断言 `eve.json` 中的 `alert.signature_id`。
- 覆盖请求侧、响应侧、OOB、TXT 突发、DoT/DoH、Lua 二次过滤与 `flowbits` 联合确认路径。
- 上传 `eve.json`、`fast.log`、`stats.log`、测试报告作为 Actions artifacts。

### 3.2 CI 必须覆盖的 Zeek 9.0.1 检查

- 安装精确版本 Zeek 9.0.1。
- 加载 Zeek 脚本（`zeek -b`）无语法/加载错误。
- 用回归 PCAP 运行 `zeek -b -Cr <pcap> <scripts>`，断言 `dns.log` / `notice.log` / 自定义日志字段。
- 覆盖 DNS 查询/响应、qtype、rcode、answers、TXT/NULL 负载、OOB 域名等路径。
- 上传 Zeek 日志与测试报告作为 Actions artifacts。

### 3.3 CI 工程要求

- workflow 放在 `.github/workflows/`。
- runner 固定（如 `ubuntu-22.04` 或 `ubuntu-24.04`），不使用浮动镜像。
- 第三方 action 固定到精确版本或 commit SHA。
- 版本安装、构建缓存、测试命令必须可重复；失败信息要能定位到具体规则/SID/脚本。
- 不在 CI 中输出密钥；使用 GitHub Secrets（如需要）。

## 4. 目录约定

```text
ips/
├── CLAUDE.md                       # 本提示词
├── DNS隧道与带外检测/
│   ├── DNS隧道与带外检测规则.rules  # Suricata 8.0.8 规则
│   ├── lua/                         # 规则内嵌 Lua
│   ├── dns_tunnel_allow.lst         # dataset 白名单
│   ├── 误报分析与规则缺陷.md
│   ├── 精准化改造方案.md
│   ├── 验证用例与上线清单.md
│   ├── 能力边界与外挂扩展方案.md
│   └── Lua强化检测场景.md
├── zeek/                            # Zeek 9.0.1 脚本（如新增）
├── tests/                           # PCAP、EVE/Zeek 断言、测试脚本
└── .github/workflows/               # CI
```

- 规则与文档文件**不使用数字前缀编号**（不要 `01-`、`03-` 这类命名）。
- 新增 Zeek 检测放在 `zeek/`；新增测试放在 `tests/`；不要在检测目录里混入规则外分析脚本。

## 5. 规则与脚本规范

### 5.1 Suricata 规则

- 版本锁定 8.0.8；不使用未确认的关键字。
- 保留原 SID；新增规则使用独立 SID 段，不得重复。
- 规则来源限定 `$CLIENT_NET`；不要 `any any -> any any`。
- 规则内优先使用：`dns.query`、`dns.rrtype`、`dataset:isnotset,match subdomain`、`to_lowercase`、`dotprefix`、`flowbits`。
- 规则注释用描述性文字，不写 `R1/R2` 这类规则编号；SID 可以保留。
- `msg` 使用 `[DNS隧道]`、`[DNS带外]`、`[DNS隧道-Lua]` 等描述性前缀，不加 `01/02` 编号。
- 低置信规则使用 `tier telemetry`/`tier triage`；高置信确认规则使用 `tier alert`。
- 不在检测层用 `threshold type limit` 掩盖事件；限流放 `event_filter`。

### 5.2 规则内嵌 Lua

- 只使用 Suricata 8.0.8 的 Lua 5.4 与沙箱允许的库：`base/table/string/math/utf8`；没有 `io/os/package/debug`。
- 使用 `require("suricata.dns")`、`suricata.tls`、`suricata.http` 时，先确认 8.0.8 API。
- Lua 规则必须带 buffer（`dns.query`、`dns.queries.rrname`、`tls.alpn`、`http.request_header` 等）；只有 hook 没有 buffer 会被当作 straight match。
- 脚本必须定义 `init` 和 `match`。
- 不做跨包聚合；状态是 per-thread，不能依赖 Lua 全局表做全量计数。
- 所有阈值常量放在脚本顶部，便于影子期校准。
- Lua 语法检查、逻辑回归都必须进 CI。

### 5.3 Zeek 脚本

- 只使用 Zeek 9.0.1 的 API、事件与日志字段。
- 脚本加载与 PCAP 回归必须进 CI。
- 检测输出写入 Zeek 日志/Notice 时，字段命名稳定、可断言。
- 不引入需要外部网络下载的 Zeek 包；如必须依赖，固定版本并在 CI 中安装。

## 6. 测试与回归要求

- 每个新增/修改的规则或 Lua/Zeek 路径，必须有**正例**与**反例**：
  - 正例：预期命中对应 SID / Zeek notice。
  - 反例：预期不命中（合法 SaaS、SPF/DKIM、CDN、内网命名、授权扫描器等）。
- PCAP 或合成流量要可重复生成，放入 `tests/`；测试数据不得包含真实敏感数据。
- CI 断言尽量精确到 `signature_id` / Zeek 日志字段，而不是只看“有告警”。
- 修改阈值时，同时更新对应测试期望与文档。
- 回归集必须覆盖：
  - 32hex/UUID/长标签/单字符流
  - base32/base64url/拆分标签
  - TXT/NULL/CNAME 载荷与 SPF/DKIM/域名验证反例
  - OOB 根域/短 token/MX 反例
  - TXT 突发邮件认证反例
  - DoT ALPN/SNI、DoH method/URI/host
  - `flowbits` 请求+响应联合确认

## 7. 变更流程（Definition of Done）

1. 修改规则/Lua/Zeek/文档。
2. 更新或新增 `tests/` 用例。
3. 更新相关文档（README、验证清单、能力边界等）。
4. 提交 PR，等待 GitHub Actions 全绿。
5. CI 绿之前，不得声称完成或已验证。

## 8. 禁止事项

- 禁止为其他 Suricata/Zeek 版本做兼容。
- 禁止用规则外 Python/日志读取器替代规则内检测。
- 禁止未验证就宣称“零误报”“已验证”“CI 通过”。
- 禁止使用浮动版本或 `latest` 镜像/action。
- 禁止在仓库中提交密钥、真实 PCAP、客户数据。
- 禁止用 `threshold type limit` 在检测层隐藏事件。
- 禁止把白名单写成公共后缀（`com`、`co.uk`）或整个云厂商的过宽后缀。

## 9. 回复与文档语言

- 默认使用中文。
- 结论必须区分：**已验证（附 CI 结果）** / **待验证（需 CI）** / **未验证**。
- 不猜测 Suricata/Zeek 行为；不确定时先查 8.0.8 / 9.0.1 文档或源码，再给出依据。
