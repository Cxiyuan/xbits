// xbits Zeek thin hook plugin
//
// 作用：在 Zeek 进程内通过 HookQueueEvent 拦截选定事件，把事件名 + 连接上下文
// （uid/五元组/方法/URI/签名）推给 xbits 中央分析引擎。只做转发；规则/状态在 xbits。
//
#include "zeek/IPAddr.h"
#include "zeek/Val.h"
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

static bool ValStr(const zeek::ValPtr &v, std::string &out)
{
    if (!v)
        return false;
    if (const auto *s = v->AsStringVal()) {
        out = s->ToStdString();
        return true;
    }
    return false;
}

static bool ValAddr(const zeek::ValPtr &v, std::string &out)
{
    if (!v)
        return false;
    if (const auto *a = v->AsAddrVal()) {
        out = a->Get().AsString();
        return true;
    }
    return false;
}

static bool ValPort(const zeek::ValPtr &v, uint64_t &out)
{
    if (!v)
        return false;
    if (const auto *p = v->AsPortVal()) {
        out = p->Port();
        return true;
    }
    return false;
}

static std::string BuildEventJson(zeek::Event *event)
{
    std::string name = event->Handler() ? event->Handler()->Name() : "";
    std::string uid, src, dst, proto, method, uri, sig, sig_msg;
    std::string alert_kind, alert_name, severity;
    uint64_t sport = 0, dport = 0;

    auto fill_conn = [&](const zeek::ValPtr &v) {
        if (!v)
            return;
        const auto *conn = v->AsRecordVal();
        if (!conn)
            return;
        ValStr(conn->GetField("uid"), uid);
        const auto idv = conn->GetField("id");
        if (idv) {
            if (const auto *id = idv->AsRecordVal()) {
                ValAddr(id->GetField("orig_h"), src);
                ValAddr(id->GetField("resp_h"), dst);
                ValPort(id->GetField("orig_p"), sport);
                ValPort(id->GetField("resp_p"), dport);
            }
        }
    };

    const auto &args = event->Args();
    if (name == "signature_match") {
        /* signature_state field layout is not stable across Zeek builds.
         * The second event argument is the portable signature message. */
        if (args.size() >= 2)
            ValStr(args[1], sig_msg);
    } else if ((name == "http_request" || name == "http_reply" || name == "dns_request" ||
                name == "dns_query") &&
               !args.empty()) {
        // Do not blindly dereference args[0] as connection here: Zeek's
        // app-id scripts can register handlers whose argument layout differs
        // from the base analyzer's event signature.  Event name/args below
        // are sufficient for xbits context; signature_match and XbitsAlert
        // carry their own structured records.
        if (name == "http_request" && args.size() >= 3) {
            ValStr(args[1], method);
            ValStr(args[2], uri);
        } else if (name == "http_reply" && args.size() >= 4) {
            ValStr(args[3], sig_msg); // reason phrase as extra context
        } else if (name == "dns_request" && args.size() >= 3) {
            ValStr(args[2], uri); // query name
        }
    } else if (name == "XbitsAlert::alert" && !args.empty()) {
        // app-id / scanner 的统一告警事件：Info 记录
        if (const auto *info = args[0]->AsRecordVal()) {
            ValStr(info->GetField("kind"), alert_kind);
            ValStr(info->GetField("name"), alert_name);
            ValStr(info->GetField("severity"), severity);
            ValAddr(info->GetField("src"), src);
            ValStr(info->GetField("evidence"), sig_msg);
            sig = alert_name;
        }
    }

    std::string kind = (name == "XbitsAlert::alert") ? "alert" : "event";
    std::string out = "{\"source\":\"zeek\",\"kind\":\"" + kind + "\",\"event\":\"" + JsonEscape(name) + "\"";
    if (!uid.empty())
        out += ",\"uid\":\"" + JsonEscape(uid) + "\"";
    if (!src.empty())
        out += ",\"src\":\"" + JsonEscape(src) + "\"";
    if (!dst.empty())
        out += ",\"dst\":\"" + JsonEscape(dst) + "\"";
    if (sport != 0)
        out += ",\"sport\":" + std::to_string(sport);
    if (dport != 0)
        out += ",\"dport\":" + std::to_string(dport);
    if (!proto.empty())
        out += ",\"proto\":\"" + JsonEscape(proto) + "\"";
    if (!method.empty())
        out += ",\"method\":\"" + JsonEscape(method) + "\"";
    if (!uri.empty())
        out += ",\"uri\":\"" + JsonEscape(uri) + "\"";
    if (!sig.empty())
        out += ",\"signature\":\"" + JsonEscape(sig) + "\"";
    if (!sig_msg.empty())
        out += ",\"desc\":\"" + JsonEscape(sig_msg) + "\"";
    if (!alert_kind.empty())
        out += ",\"alert_kind\":\"" + JsonEscape(alert_kind) + "\"";
    if (!severity.empty())
        out += ",\"severity\":\"" + JsonEscape(severity) + "\"";
    if (sig_msg.empty() && name != "XbitsAlert::alert")
        out += ",\"desc\":\"" + JsonEscape(zeek::obj_desc(event)) + "\"";
    out += ",\"ts\":\"" + std::to_string(event->Time()) + "\"}";
    return out;
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
        zeek::plugin::Plugin::InitPreScript();
        EnableHook(HOOK_QUEUE_EVENT);
    }

    bool HookQueueEvent(Event *event) override
    {
        if (event == nullptr || !event->Handler())
            return false;

        std::string name = event->Handler()->Name();
        if (name != "signature_match" && name != "http_request" && name != "http_reply" &&
            name != "dns_request" && name != "dns_query" &&
            name != "XbitsAlert::alert")
            return false;

        fprintf(stderr, "xbits-hook event: %s\n", name.c_str());
        SendLine(BuildEventJson(event));
        return false; // 继续让 Zeek 正常处理事件
    }
};

Plugin plugin;

} // namespace zeek::plugin::XbitsHook
