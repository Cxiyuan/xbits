# local/ —— 自有情报（采集不覆盖，始终合并）

放**你们自己的**情报（内部处置沉淀、商业 feed 导出、人工确认的 IOC）。`collect.py` 每次刷新都会把这里的数据合并进 `data/`，且不会改动本目录。

## 文件名（与类型一一对应，缺省即不合并）
- `md5.txt` / `sha1.txt` / `sha256.txt`：一行一个哈希
- `ip.txt`：一行一个 IPv4/IPv6
- `domain.txt`：一行一个小写域名
- `#` 开头为注释；`*.example.txt` 只是格式示例，**不会**被合并

## 示例
- [md5.example.txt](md5.example.txt)、[sha256.example.txt](sha256.example.txt)：含 EICAR 测试哈希（安全、可用于验证链路）

要启用：把 example 复制成正式文件名再替换为真实数据，然后重跑 `tools/collect.py`。
