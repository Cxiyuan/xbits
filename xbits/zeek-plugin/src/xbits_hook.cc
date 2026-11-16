// xbits Zeek thin hook plugin
//
// 作用：在 Zeek 进程内拦截选定事件（signature_match/http_request/...），把事件
// 描述通过 Unix socket 推给 xbits 中央分析引擎。只做转发；规则/状态在 xbits。
//
// 构建（需要 Zeek 9.0.1 的 zeek-config）：
//   make
//
// 目录部署（Zeek 动态插件布局）：
//   xbits/zeek-plugin/
//     __zeek_plugin__        # 内容：Xbits::Hook
//     lib/xbits_hook.linux-x86_64.so
//   ZEEK_PLUGIN_PATH=/path/to/xbits/zeek-plugin
//   ZEEK_PLUGIN_ACTIVATE=Xbits::Hook
//
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/plugin/Plugin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace zeek::plugin::XbitsHook {

static std::string HookPath()
{
    const char *p = getenv("XBITS_HOOK_SOCKET");
    return (p != nullptr && p[0] != '\0') ? p : "/var/run/xbits/hook.sock";
}

static std::string JsonEscape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 16);
    for (unsigned char c : in) {
        switch (c) {
            case '"':
            case '\\':
                out.push_back('\\');
                out.push_back((char)c);
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
                break;
        }
    }
    return out;
}

static void SendLine(const std::string &line)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", HookPath().c_str());

    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0) {
        size_t off = 0;
        while (off < line.size()) {
            ssize_t n = send(fd, line.data() + off, line.size() - off, MSG_NOSIGNAL);
            if (n <= 0)
                break;
            off += static_cast<size_t>(n);
        }
    }
    close(fd);
}

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override
    {
        zeek::plugin::Configuration config;
        config.name = "Xbits::Hook";
        config.description = "Forward selected Zeek events to xbits central engine";
        return config;
    }

    void InitPreScript() override
    {
        Plugin::InitPreScript();
        EnableHook(HOOK_QUEUE_EVENT);
    }

    bool HookQueueEvent(Event *event) override
    {
        if (event == nullptr || !event->Handler())
            return false;

        std::string name = event->Handler()->Name();
        if (name != "signature_match" && name != "http_request" && name != "http_reply" &&
            name != "dns_request" && name != "dns_query" && name != "notice")
            return false;

        std::string desc = zeek::obj_desc(event);
        std::string line = "{\"source\":\"zeek\",\"kind\":\"event\",\"event\":\"" +
                           JsonEscape(name) + "\",\"desc\":\"" + JsonEscape(desc) + "\"}\n";
        SendLine(line);
        return false; // 继续让 Zeek 正常处理事件
    }
};

Plugin plugin;

} // namespace zeek::plugin::XbitsHook
