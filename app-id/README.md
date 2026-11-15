# xbits app-id · 基于 Zeek 的应用识别引擎库

> 状态：**脚手架（骨架）**。目录已建立，作为"基于 Zeek 框架开发应用识别"的引擎库根目录。
> 目标引擎版本：**Zeek 9.0.1**（与本仓库 xbits 联动所用版本一致）。所有 Zeek API 字段名以 9.0.1 文档/源码核验为准。

## 定位
在 Zeek 事件框架内实现**应用识别（app-id）**：从协议解析/指纹信号映射到"应用 + 类别 + 置信度"，产出 `app_identity.log`，供检测关联与（后续）联动 Suricata 使用。它不是 Suricata 规则的替代，而是"识别大脑"。

## 识别信号（规划）
- TLS：`ssl` 的 SNI、JA3/JA3s、证书 subject/issuer
- HTTP：Host、User-Agent、URI
- DNS：qname 后缀
- 协议分析器/DPD 结果、HASSH（SSH）
- 自定义协议：Spicy 分析器（后续）
- 映射数据：`mapping/*.map`（SNI 后缀→应用、UA 子串→客户端应用）

## 目录结构
```
app-id/
├── README.md                  # 本文件
├── zkg.meta                   # Zeek 包元数据（zkg 可加载）
├── scripts/
│   ├── __load__.zeek          # 包入口
│   └── appid/
│       ├── __load__.zeek
│       └── main.zeek          # 模块：表/查找/日志/log 流 app_identity
├── mapping/
│   ├── sni_suffix.map         # SNI/域名后缀 -> 应用（示例）
│   └── ua_substr.map          # UA 子串 -> 客户端应用（示例）
└── tests/
    └── README.md              # btest/回归用例规划
```

## 与 Suricata 的联动（后续）
- 识别结果先落 `app_identity.log`；
- 需要"应用控制/告警"时，可经既有 `xbits` 桥或 `suricata unix-command dataset-add` 将紧凑指标（SNI/域名/IP）回灌 Suricata（详见历史分析：`开发文档/Snort3迁移-规则可转换性分析.md` 之外的 app-id 讨论）。
- 注意：Zeek 被动、不能 inline 丢包；精确逐流阻断需数据面（eBPF/nftables）执行。

## 开发约定
1. 只使用 Zeek 9.0.1 存在的 API/事件/字段；不确定处标"待验证"，核对后再定稿。
2. 识别逻辑尽量数据驱动（`mapping/*.map`），便于维护应用库。
3. 新增识别路径必须配回归（`tests/`），并纳入 CI（GitHub Actions + Zeek 9.0.1 容器）。
4. 本库不依赖 Suricata；输出为 Zeek 日志。
