/*
 * xbits Suricata thin hook plugin
 *
 * 在 Suricata 进程内通过公开的 packet logger 回调（SCOutputRegisterPacketLogger）
 * 获取“已命中规则”的 Packet（p->alerts.cnt > 0），把 alert 及 5 元组推送到
 * xbits 中央分析引擎的 Unix socket。只做薄转发，不做检测/状态。
 *
 * 构建（在安装 Suricata 且 libsuricata-config 可用后）：
 *   make -C xbits/suricata-plugin
 *
 * 加载：suricata.yaml
 *   plugins:
 *     - /path/to/xbits-suricata-hook.so
 * 环境变量：XBITS_HOOK_SOCKET（默认 /var/run/xbits/hook.sock）
 */
#include "suricata-common.h"
#include "suricata-plugin.h"

#include "decode.h"
#include "detect.h"
#include "flow.h"
#include "output.h"
#include "output-eve.h"
#include "output-packet.h"
#include "util-print.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define XBITS_JSON_MAX 4096

static const char *XbitsHookPath(void)
{
    const char *p = getenv("XBITS_HOOK_SOCKET");
    return (p != NULL && p[0] != '\0') ? p : "/var/run/xbits/hook.sock";
}

static void XbitsJsonEscape(const char *in, char *out, size_t outlen)
{
    size_t j = 0;
    if (outlen == 0)
        return;
    if (in == NULL)
        in = "";
    for (size_t i = 0; in[i] != '\0' && j + 2 < outlen; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':
            case '\\':
                out[j++] = '\\';
                out[j++] = (char)c;
                break;
            case '\n':
                out[j++] = '\\';
                out[j++] = 'n';
                break;
            case '\r':
                out[j++] = '\\';
                out[j++] = 'r';
                break;
            case '\t':
                out[j++] = '\\';
                out[j++] = 't';
                break;
            default:
                if (c < 0x20)
                    j += (size_t)snprintf(out + j, outlen - j, "\\u%04x", c);
                else
                    out[j++] = (char)c;
                break;
        }
    }
    out[j] = '\0';
}

static void XbitsSendLine(const char *line)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", XbitsHookPath());

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        size_t len = strlen(line);
        ssize_t ignored = send(fd, line, len, MSG_NOSIGNAL);
        (void)ignored;
    }
    close(fd);
}

static void XbitsSendBuf(const char *buf, size_t len)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", XbitsHookPath());

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        ssize_t ignored = send(fd, buf, len, MSG_NOSIGNAL);
        (void)ignored;
        if (len == 0 || buf[len - 1] != '\n') {
            const char nl = '\n';
            ignored = send(fd, &nl, 1, MSG_NOSIGNAL);
            (void)ignored;
        }
    }
    close(fd);
}

static const char *XbitsProtoName(uint8_t proto)
{
    switch (proto) {
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 1:
            return "ICMP";
        default:
            return "OTHER";
    }
}

static bool XbitsPacketCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv;
    (void)thread_data;
    return p != NULL && p->alerts.cnt > 0 && p->alerts.alerts != NULL;
}

static TmEcode XbitsThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    (void)tv;
    (void)initdata;
    *data = NULL;
    return TM_ECODE_OK;
}

static TmEcode XbitsThreadDeinit(ThreadVars *tv, void *data)
{
    (void)tv;
    (void)data;
    return TM_ECODE_OK;
}

static int XbitsPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    (void)tv;
    (void)thread_data;
    if (p == NULL || p->alerts.cnt == 0)
        return 0;

    char src[46] = {0};
    char dst[46] = {0};
    if (PacketIsIPv4(p)) {
        PrintInet(AF_INET, (const void *)&(p->src.addr_data32[0]), src, sizeof(src));
        PrintInet(AF_INET, (const void *)&(p->dst.addr_data32[0]), dst, sizeof(dst));
    } else if (PacketIsIPv6(p)) {
        PrintInet(AF_INET6, (const void *)&(p->src.address), src, sizeof(src));
        PrintInet(AF_INET6, (const void *)&(p->dst.address), dst, sizeof(dst));
    } else {
        return 0;
    }

    for (uint16_t i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (pa->s == NULL)
            continue;

        char msg[XBITS_JSON_MAX / 2];
        XbitsJsonEscape(pa->s->msg != NULL ? pa->s->msg : "", msg, sizeof(msg));

        char line[XBITS_JSON_MAX];
        snprintf(line, sizeof(line),
                 "{\"source\":\"suricata\",\"kind\":\"alert\","
                 "\"sid\":%u,\"signature\":\"%s\","
                 "\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,"
                 "\"proto\":\"%s\",\"tx_id\":%llu,\"action\":%u}\n",
                 (unsigned)pa->s->id, msg, src, dst, (unsigned)p->sp, (unsigned)p->dp,
                 XbitsProtoName(p->proto), (unsigned long long)pa->tx_id,
                 (unsigned)pa->action);
        XbitsSendLine(line);
    }
    return 0;
}

static void XbitsOnLoggingReady(void *arg)
{
    (void)arg;
    SCOutputRegisterPacketLogger(LOGGER_USER, "xbits-suricata-hook", XbitsPacketLogger,
                                 XbitsPacketCondition, NULL, XbitsThreadInit, XbitsThreadDeinit);
}

/*
 * EVE filetype hook：官方镜像/源码构建都稳定的输出 hook。
 * suricata.yaml 配置：
 *   outputs:
 *     - eve-log:
 *         filetype: xbits-hook
 *         types: [alert]
 * 收到的 buffer 是完整 EVE JSON 行，直接转发给 xbits 引擎。
 */
static int XbitsEveInit(const SCConfNode *conf, const bool threaded, void **init_data)
{
    (void)conf;
    (void)threaded;
    *init_data = NULL;
    return 0;
}

static int XbitsEveThreadInit(const void *init_data, const ThreadId thread_id, void **thread_data)
{
    (void)init_data;
    (void)thread_id;
    *thread_data = NULL;
    return 0;
}

static int XbitsEveWrite(const char *buffer, const int buffer_len, const void *init_data,
                         void *thread_data)
{
    (void)init_data;
    (void)thread_data;
    if (buffer != NULL && buffer_len > 0)
        XbitsSendBuf(buffer, (size_t)buffer_len);
    return 0;
}

static void XbitsEveThreadDeinit(const void *init_data, void *thread_data)
{
    (void)init_data;
    (void)thread_data;
}

static void XbitsEveDeinit(void *init_data)
{
    (void)init_data;
}

static SCEveFileType XbitsEveFileType = {
    .name = "xbits-hook",
    .Init = XbitsEveInit,
    .ThreadInit = XbitsEveThreadInit,
    .Write = XbitsEveWrite,
    .ThreadDeinit = XbitsEveThreadDeinit,
    .Deinit = XbitsEveDeinit,
};

static void XbitsPluginInit(void)
{
    /*
     * Use only the EVE filetype hook.  The packet logger is kept in this
     * plugin for reference/backward compatibility, but registering both
     * paths makes every alert arrive twice in a normal EVE configuration.
     */
    SCRegisterEveFileType(&XbitsEveFileType);
}

const SCPlugin XbitsPlugin = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "xbits-suricata-hook",
    .plugin_version = "0.1.0",
    .author = "xbits",
    .license = "GPL-2.0-only",
    .Init = XbitsPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &XbitsPlugin;
}
