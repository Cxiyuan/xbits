# allowlist/ —— 统一白名单子模块

项目根目录下的独立子模块：**可维护、可更新、自定义添加**，对 xbits（及后续各消费方）提供统一白名单查询服务。

定位：白名单是"**允许/基线**"方向的数据（误报抑制 / 行为基线），与 `threat-intel/`（"恶意"方向）互补、互不合并：
- `threat-intel/` 命中 → 加分/加置信度（黑，参与评分）
- `allowlist/` 命中 → 置信度扣减（白，只降级；与威胁同时命中时以威胁为准）

## 结构
```
allowlist/
├─ sources.json           # 源声明（当前为静态转译源；后续可加远端公共白名单源）
├─ custom/                # 自定义白名单（add.py 增删；refresh 永不覆盖）
│  ├─ white_domains.txt      业务白域名（~100，探针 top100_white_domain.ini 转译）
│  ├─ public_dns_servers.txt 公共 DNS 基线（15，探针 common_dns_server.ini 转译）
│  ├─ domain.txt / ip.txt     通用白名单（初始为空，按需添加）
├─ data/                  # 快照（生成物；消费方只读这里）
│  ├─ domain.txt / ip.txt / public_dns.txt / meta.json
└─ tools/
   ├─ add.py              # 自定义添加/删除（add/remove/list）
   ├─ refresh.py          # 校验+归一化+重建 data/（--check 仅校验）
   └─ query.py            # 统一查询 CLI（--domain 含子域名匹配 / --ip / --stats）
```

## 自定义添加（核心能力）
```bash
python3 allowlist/tools/add.py add domain example.com
python3 allowlist/tools/add.py add domain a.com b.com      # 批量
python3 allowlist/tools/add.py add ip 203.0.113.10
python3 allowlist/tools/add.py add public_dns 9.9.9.9
python3 allowlist/tools/add.py remove domain example.com
python3 allowlist/tools/add.py list
python3 allowlist/tools/refresh.py        # 重建 data/ 生效
```

## 统一查询
```bash
python3 allowlist/tools/query.py --stats
python3 allowlist/tools/query.py --domain map.baidu.com   # 子域名命中 baidu.com
python3 allowlist/tools/query.py --ip 8.8.8.8
python3 allowlist/tools/query.py --ip 8.8.8.8 --kind public_dns
```
Python API：`tools/query.py` 的 `AllowlistStore`（domain 按后缀匹配，IP 精确匹配）。

> **IP 归一化（V-23）**：add.py / refresh.py / query.py 共用 `tools/ipnorm.py` 的 `canonical_ip()`
> （IPv6 规范压缩式、统一小写、拒绝 zone id）——`add.py add public_dns 2001:DB8::1` 与
> `query.py --ip 2001:0db8:0:0:0:0:0:1` 及 xbits 侧查询命中同一表示；单测见
> `allowlist/tests/test_allowlist.py`。

## xbits 消费
xbits 启动参数 `--allowlist-dir allowlist/data`（见 xbits README）：
- 告警分析时查 `domain/ip` 白名单 → 命中则**降级**：`confidence -= 25`、
  告警写 `intel_decision=allowlist-downgraded`、分析文档 reason 记 `intel-allowlist`；
  只降级、不在引擎里丢弃，也不阻断威胁命中（威胁与白名单同时命中时以威胁为准，
  写 `threat-overrides-allowlist`）。
- DNS 类事件查 `public_dns` → 非公共 DNS 的对端只写 `allowlist.public_dns_off_baseline`
  提示字段，不参与加权。
- 域名白名单按**最长后缀**匹配；公共后缀与单标签条目（如 `com`）在加载期被拒绝并打印。

## 更新 SOP
- 日常：`add.py` 增删 → `refresh.py` 重建 → 重启/重载 xbits。
- 定期：`refresh.py --check` 校验 custom 完整性；CI 不自动刷新（自定义数据以 git 管理为准）。
- 后续接远端公共白名单源（CDN/公共后缀等）：sources.json 加条目 + refresh.py 实现 fetch/parse。

## 边界
- Zeek 不再持有任何名单（`规则检测/zeek/威胁情报/` 已删除）：Zeek 只做纯行为分析，
  事件经 hook 到 xbits 后，由 xbits 统一查询 allowlist 与 threat-intel 再决策。
