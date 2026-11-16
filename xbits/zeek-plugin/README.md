# xbits Zeek 薄 hook 插件

作用：在 **Zeek 进程内** 通过 `HookQueueEvent` 拦截 `signature_match` / `http_request` /
`http_reply` / `dns_request` / `dns_query` / `notice`，把事件描述 JSONL 推给 xbits
中央分析引擎的 Unix socket。规则与状态在 xbits，不在插件里。

## 构建

需要 Zeek 9.0.1 的 `zeek-config`：

```bash
make -C xbits/zeek-plugin
# 生成 lib/xbits_hook.linux-x86_64.so
```

## 启用（动态插件目录布局）

```bash
export ZEEK_PLUGIN_PATH="$PWD/xbits/zeek-plugin"
export ZEEK_PLUGIN_ACTIVATE="Xbits::Hook"
export XBITS_HOOK_SOCKET="/var/run/xbits/hook.sock"
zeek -Cr trace.pcap your_scene.zeek
```

目录结构必须为：

```text
xbits/zeek-plugin/
├── __zeek_plugin__                  # 内容：Xbits::Hook
└── lib/xbits_hook.linux-x86_64.so
```

## 说明

- 插件与 Zeek 9.0.1 的 **PLUGIN_API_VERSION=7** 及版本头绑定，升级 Zeek 需重编译。
- 这是薄 hook：只转发事件，不写日志、不做规则/状态。
- 需要更细的包级特征时，可扩展为 `PACKET_ANALYZER` / `HookUnprocessedPacket`。
