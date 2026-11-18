# Lua 强化方案

## 目标

按“Suricata 负责签名、Zeek 负责行为、xbits 负责关联”的分工，对转换后的
Suricata 规则做一次全量 QA：**只对内容命中后仍缺少上下文、容易误报的 HTTP 规则组
挂载 Lua 增强脚本**；不自研逐条 17k 脚本，也不把 Lua 变成行为聚合引擎。

## 已挂载 Lua 的规则组

共 **7,024 条转换规则**，另加自研场景 41 条 `lua:` 规则。

| 规则组 | 数量 | Lua 脚本 | 目的 |
|---|---:|---|---|
| WebShell 响应 | 2,847 | `webshell_response.lua` | 只在响应体出现命令输出/文件管理/错误回显时确认 |
| WebShell 请求 | 546 | `webshell_param.lua` | 检查 cmd/exec/pass/z0 等参数和已知路径 |
| SQLi（含扫描器内 2 条特例） | 543 | `sqli_context.lua` | 复用自研 SQLi 上下文检测，排除普通 SQL 词/文档 |
| 敏感关键词 | 1,488 | `keyword_context.lua` | 只在非 benign 参数、请求体参数赋值或危险头参数中命中 |
| 扫描器 | 184 | `scanner_context.lua` | 只对扫描器 UA/Header 指纹命中，不扩展到同文件注入规则 |
| 信息泄露响应 | 81 | `info_disclosure_context.lua` | 要求 2xx/403/500、文本类型和真实泄露标记 |
| 信息泄露请求（含扫描器内 1 条特例） | 406 | `info_disclosure_request.lua` | 要求路径确实指向敏感文件/目录 |
| 恶意 URL | 52 | `malice_url_context.lua` | 要求 HTML/JS 成功响应并出现脚本跳转/解码语义 |
| 命令执行/注入 | 314 | `cmdi_context.lua` | 复用命令注入上下文检测，排除普通命令词 |
| 目录遍历/文件包含 | 104 | `traversal_context.lua` | 复用路径穿越上下文检测，排除普通相对路径 |
| 文件上传 | 31 | `upload_context.lua` | 检查上传文件名/扩展名与脚本内容 |
| XSS | 428 | `xss_context.lua` | 要求出现可执行 HTML/JS 结构，不只看 onerror/script 单词 |

脚本位置在对应类别目录的 `lua/` 下，例如：

- `规则检测/suricata/Web攻击/WebShell/lua/`
- `规则检测/suricata/Web攻击/SQL注入/lua/`
- `规则检测/suricata/Web攻击/敏感关键词/lua/`
- `规则检测/suricata/Web攻击/扫描器/lua/`
- `规则检测/suricata/Web攻击/信息泄露/lua/`
- `规则检测/suricata/恶意URL/lua/`
- `规则检测/suricata/Web攻击/命令执行/lua/`
- `规则检测/suricata/Web攻击/命令注入/lua/`
- `规则检测/suricata/Web攻击/目录遍历/lua/`
- `规则检测/suricata/Web攻击/文件包含/lua/`
- `规则检测/suricata/Web攻击/文件上传/lua/`
- `规则检测/suricata/Web攻击/XSS/lua/`

规则本身没有改 content/pcre，只在 `sid:` 前追加 `lua:<script>.lua;`。
可重复执行：

```bash
python 规则检测/apply_lua_enhancements.py
```

清单：[Lua强化清单.json](Lua强化清单.json)。

## 为什么这些规则需要 Lua

这些规则共同的问题是“内容出现即命中”：

- WebShell 大量规则只匹配 PHP 函数名/表名；
- gray keyword 是通用运维词（gcc/ftp/ssh）出现在 URI 中；
- SQLi 弱规则只有单引号/and/or/having；
- 扫描器规则只匹配工具名；
- 信息泄露规则只匹配文件名；
- 恶意 URL 规则只匹配页面字节序列。

Lua 在这些规则命中后继续读取 URI、query、body、Cookie、headers、响应行/响应体，
做参数名、函数调用、响应状态、内容类型和真实泄露标记判定，从而压低误报。

## 没有挂 Lua 的规则及原因

| 规则组 | 数量 | 原因 |
|---|---:|---|
| Web 服务 CVE 产品签名 | 1,944 | 多为产品/版本特定 content/pcre，需要协议/产品解析，不适合通用 HTTP Lua |
| 木马/恶意软件 | 1,706 | 二进制/载荷签名，Lua 无文件内容上下文；应走 xbits/Zeek |
| 主机/应用软件 CVE | 1,567 | 单内容规则多为协议字段签名，需逐条补 pcre/byte_test，不是通用上下文问题 |
| `web_scan` 非扫描器注入规则 | 404 | SSI/HTTP splitting/null byte 等已有具体 pcre，挂 UA gate 会误伤 |
| 其余 55 条静态中风险 | 55 | 分布于 system/backdoor/web/FTP 等，需逐条补第二特征或字段约束，不适用统一 Lua |

## 验证

- 本地已通过 Python 编译、JSON 校验；
- 规则仍为 17,477 条，active 规则未减少；
- 由于暂未 commit，Containers/Suricata `-T` 与 Lua 脚本运行验证尚未在 CI 执行；
- 提交后重点验证：7,024 条挂载规则加载、Lua 沙箱无语法错误、弱规则负样本误报下降。