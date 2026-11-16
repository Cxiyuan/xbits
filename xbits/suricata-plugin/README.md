# xbits Suricata 薄 hook 插件

作用：在 **Suricata 进程内**通过公开的 Packet Logger 回调，在 `Packet->alerts.cnt > 0`
（规则已命中）时把 `sid/signature/5元组` 推送到 xbits 中央分析引擎的 Unix socket。
插件不实现检测/状态/规则，只做薄转发。

## 构建

需要 Suricata 8.0.8 已安装且 `libsuricata-config` 在 PATH：

```bash
make -C xbits/suricata-plugin
```

## 加载

```yaml
plugins:
  - /usr/lib/suricata/plugins/xbits-suricata-hook.so
```

默认 hook socket：`/var/run/xbits/hook.sock`，可用环境变量覆盖：

```bash
export XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock
```

## 说明

- 这是 **薄 hook**：规则命中后的 Packet 触发；不读 EVE 日志、不做引擎逻辑。
- 若需要“在 DetectEngine 命中函数内部同步回调（带完整 SigMatch 上下文）”，
  可在 `src/detect-engine-alert.c` / `AlertQueueAppend` 附近再加一个核心回调；
  当前插件版本优先保持零核心补丁、可独立编译。
