# app-id 测试与回归（规划）

目标：用 Zeek 9.0.1 回放 PCAP，断言 `app_identity.log` 的应用/类别/置信度。

## 计划
- `tests/btest.cfg`：配置 btest 以 Zeek 9.0.1 运行本包脚本。
- 每个应用识别路径至少一组**正例/反例** PCAP：
  - TLS SNI（如 facebook.com）→ 应用 Facebook
  - HTTP Host/UA（如 Dropbox UA）→ 应用 Dropbox
  - DNS 后缀 → 应用/类别
  - 反例：CDN/多租户域名不应误判
- 断言方式：解析 `app_identity.log` 的 `app/category` 字段。

## 说明
- PCAP 复用仓库 `测试用例/` 既有语料，或新增到本目录 `tests/pcap/`。
- Zeek 版本固定 9.0.1（与仓库一致），CI 用固定镜像。
- 脚本字段名/事件签名以 Zeek 9.0.1 核验后再定稿。
