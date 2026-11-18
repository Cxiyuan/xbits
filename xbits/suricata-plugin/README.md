# xbits Suricata 薄 hook 插件

作用：在 **Suricata 进程内**通过公开的 EVE filetype 回调，把规则命中后的 EVE `alert`
JSON 推送到 xbits 中央分析引擎的 Unix socket。插件不做检测/状态/规则，只做薄转发。

## 构建

需要 Suricata 8.0.8 已安装且 `libsuricata-config` 在 PATH：

```bash
make -C xbits/suricata-plugin
```

## 加载

```yaml
plugins:
  - /usr/lib/suricata/plugins/xbits-suricata-hook.so
outputs:
  - eve-log:
      filetype: xbits-hook
      types:
        - alert:
            payload: yes
```

默认 hook socket：`/var/run/xbits/hook.sock`，可用环境变量覆盖：

```bash
export XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock
```

## 说明

- 当前实际注册的是 **EVE filetype `xbits-hook`**，不是 Packet Logger；`XbitsPacketLogger` 代码保留但未注册，避免同一告警重复上报。
- EVE filetype 只负责把 Suricata 已生成的 JSON 行发往 xbits；xbits 不能通过它回写 verdict、阻断或改规则。
- 需要 payload 判定时，EVE `alert` 必须开启 `payload: yes`；完整 HTTP Body 仍需要应用层事件或 Zeek 上下文。

## match_context 核心补丁

EVE 不携带规则实际命中的 sticky buffer。`http.header`、`file.data`、
`http.uri.raw` 和 Lua buffer 必须依赖 Suricata 8.0.8 核心补丁导出的
`match_context` 事件。

CI 在构建 Suricata 8.0.8 后执行：

```bash
python3 xbits/suricata-plugin/apply_match_context_patch.py /tmp/suricata-8.0.8
```

补丁在 generic/single/multi-buffer detect inspect 以及 Lua match 成功时调用插件注册的
`XbitsRegisterMatchContextExporter()`；插件把完整 buffer 以 Base64 通过同一个 Unix hook
socket 发给 xbits：

```json
{
  "source": "suricata",
  "kind": "match_context",
  "sid": 9103001,
  "src": "203.0.113.5",
  "dst": "10.0.0.80",
  "sport": 40000,
  "dport": 80,
  "proto": "TCP",
  "tx_id": 3,
  "buffer": "http.uri.raw",
  "buffer_len": 27,
  "buffer_b64": "..."
}
```

xbits 侧按 `SID + 五元组 + buffer` 缓存该值，并用它构造白名单 key。
白名单仍然只在 xbits 内部生效，不反馈给 Suricata/Zeek。