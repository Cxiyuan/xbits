# zeek · DNS 隧道与带外探测（Zeek 9.0.1）

当前提供请求侧检测脚本：

- `dns_tunnel_detect.zeek`：在 `dns_request` 上检测
  - OOB 平台子域（要求随机 token，拒绝平台根域/短 token/MX）
  - 32 位十六进制首标签
  - RFC 4122 UUID 首标签（版本/变体校验）
  - 60–63 字符字母数字长标签
  - 连续十六进制单字符标签流（≥12）
  - 跳过任意 `_` 服务标签

响应侧 TXT/NULL 载荷分析由 Suricata 的 `dns_tunnel_response.lua` /
`dns_tunnel_confirm.lua` 覆盖；Zeek 侧暂不重复实现。

## 运行

```bash
zeek -b -Cr test/pcap/tunnel_32hex.pcap zeek/dns_tunnel_detect.zeek
```

CI 使用精确版本镜像 `zeek/zeek:9.0.1`，见 `.github/workflows/zeek-9.0.1.yml`。

## 限制

- 这是请求侧启发式，不做跨包聚合（唯一子域数、慢速隧道等不在规则/脚本层解决）。
- 不做 TXT/NULL 响应载荷分析。
- 阈值/正则集中在脚本内，按影子期数据调整。
