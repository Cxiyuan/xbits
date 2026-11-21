#!/usr/bin/env python3
"""C5-D 转译规则 PCAP 命中回归（每类 buffer 2~3 条，正/负例成对）。

目的（V-10/V-11 的正面修复验收）：转译产物（规则检测/suricata/ 下探针规则族）在
Suricata 8.0.8 上按预期 buffer 语义命中——旧转换器产出"永不命中"的规则
（stat_code 段中毒、URI 回绑定退化为 payload）在这套 PCAP 对下会失败。

用例（SID × buffer × 正/负）：
  1. http.uri        14010049  SQL 注入 URI 特征（sql.rules）
     pos: GET /e/tool/gbook/?bid=1          neg: GET /e/tool/gbook/?bid=2（内容不同）
  2. http.uri.raw    11020030  Htdig 文件包含（%60 原始编码）
     pos: GET /htsearch?exclude=%60/etc/passwd%60
     neg: GET /htsearch?exclude=`/etc/passwd`  ← 解码后的反引号：raw 不匹配（区分 raw vs decoded）
  3. http.header     9101110   Acunetix 请求头（侦察场景规则）
     pos: Acunetix-Aspect: x                neg: 无 Acunetix 头
  4. http.method     9101113   异常 HTTP 方法（TRACE）
     pos: TRACE / HTTP/1.1                  neg: GET /（GET 不在规则方法集）
  5. http.stat_code  13060038  200 响应 + CRLF 后 #!/bin/bash（旧转换器永不命中）
     pos: 200 + body "#!/bin/bash\n"        neg: 200 + body 无 shebang（用 python 注释）
  6. payload         13020171  Havij 工具 UA（payload pcre: \r\nUser-Agent:… Havij）
     pos: UA "sqlmap/1.0 Havij 1.16"        neg: UA "Mozilla/5.0 (normal browser)"

R12-7：上述 6 类 buffer 各补第 2 组正/负例（不同 SID、不同载荷形态，共 +6 对 12 PCAP）：
  uri_2 11021402 SQL 布尔式（or）  raw_2 11020049 UTF-8 斜杠穿越 %d0%af
  hdr_2 11027642 X-Forwarded-For SQL 注入头  method_2 11021337 PUT + .jsp////
  stat_2 10020255 200 + PhpSpy 指纹  payload_2 13020172 sqlmap UA
  （产品规则里没有 403 的 http.stat_code 规则，故 stat 第 2 组用另一条 200 指纹规则；
    http.method 的产品规则都带 pkt_data，本文件的字节断言对 pkt_data 规则改为比对整条报文流。）

跑法：--generate 生成 PCAP 对（scapy，本地可跑）；--run-in-ci 形态由 CI 调
docker xbits-suricata 用 /opt/xbits/suricata-converter-pcap.yaml 跑每对 PCAP，
EVE 输出交 assert 断言。断言规则：
  pos PCAP → EVE 必须出现对应 SID（且 xbits hook 一致，见 --with-hook）；
  neg PCAP → EVE 不得出现对应 SID（负例旁必须有必中对照：每类负例同时包含
  另一 buffer 类的正例命中，防"规则没加载全绿"——由 config 加载全部规则文件保证）。

--check-config-vars（静态，无需 suricata；CI 在 `suricata -T` 之前跑）：
  解析合并配置 + 全部 rule-files 的规则头，确认每个 `$VAR` 都在 vars 中定义。
  背景：CI run 44770518104 的 `-T` 因缺 `HTTP_PORTS` 失败（17,268 条规则加载失败），
  而 `-T` 需要容器与 suricata 二进制，本地不可跑——本检查把这类失败前移到纯 python 静态断言。
  同时校验合并配置的规则清单 == probe-rules-validate 的规则清单 + 4 场景自研规则（t38 声明 51 个文件）。
  --self-test 覆盖四条负例（缺端口变量 / 别名未定义 / 规则头引用未定义变量 / 规则清单漂移）。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "测试用例" / "converter_pcap"

# (case, sid, buffer, description)
CASES = [
    ("uri_14010049", 14010049, "http.uri", "SQL 注入 URI 特征"),
    ("raw_11020030", 11020030, "http.uri.raw", "Htdig %60 原始编码"),
    ("hdr_9101110", 9101110, "http.header", "Acunetix-Aspect 请求头"),
    ("method_9101113", 9101113, "http.method", "TRACE 方法"),
    ("stat_13060038", 13060038, "http.stat_code", "200 + shebang body（t46 后改回临时端口）"),
    ("payload_13020171", 13020171, "payload", "Havij UA"),
    # --- to_client / from_server 响应方向命中回归（t46/t47） ---
    ("jspspy_10020245", 10020245, "http.stat_code", "响应 200 + JspSpy 标题（端口组变量，t46 已翻）"),
    ("pac_10010504", 10010504, "payload", "from_server PAC 文件 + import（端口组变量，t46 已翻）"),
    # 数字服务端口 443 的 to_client 规则（t48 承接 t46 遗留）；夹具按翻转后形态构造：
    # 服务端 443 → 客户端临时端口。t47 末轮已从重生规则核对 sid:11021334 头部为
    # `alert tcp any 443 -> any any`（t48 已翻），故 pos 现在应当命中。
    # 保留 t48 依赖标记以便回溯；若后续规则回退，本例会立刻暴露。
    ("tlsreneg_11021334", 11021334, "payload", "TLS 重协商 magic（数字端口 443；t48 已翻，头部已核对）"),
    # --- R12-7：6 类 buffer 的第 2 组（不同 SID / 不同载荷形态）---
    ("uri2_11021402", 11021402, "http.uri", "SQL 注入 URI：or 布尔式（不同 SID/关键字）"),
    ("raw2_11020049", 11020049, "http.uri.raw", "UTF-8 斜杠穿越 %d0%af（不同 SID）"),
    ("hdr2_11027642", 11027642, "http.header", "X-Forwarded-For SQL 注入头（不同 SID）"),
    ("method2_11021337", 11021337, "http.method", "PUT + .jsp////（不同 SID；规则含 pkt_data）"),
    ("stat2_10020255", 10020255, "http.stat_code", "200 + PhpSpy 指纹（不同 SID；产品无 403 stat_code 规则）"),
    ("payload2_13020172", 13020172, "payload", "sqlmap UA（另一种工具 UA，不同 SID）"),
]

T48_DEPENDENT_CASES = {"tlsreneg_11021334"}

CLIENT_IP = "203.0.113.9"
SERVER_IP = "10.0.0.80"
CLIENT_MAC = "02:00:00:00:00:09"
SERVER_MAC = "02:00:00:00:00:80"


def _http_exchange(packets, sport, method, path, headers, body, response, offset=0.0):
    """与 generate_web_pcaps.py 同构的最小 TCP+HTTP 会话。"""
    from scapy.all import Ether, IP, TCP, Raw

    cseq, sseq = 1000, 5000
    t0 = 1750000000.0 + offset
    cb = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT_IP, dst=SERVER_IP)
    sb = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER_IP, dst=CLIENT_IP)
    syn = cb / TCP(sport=sport, dport=80, flags="S", seq=cseq)
    syn.time = t0
    synack = sb / TCP(sport=80, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    synack.time = t0 + 0.001
    ack = cb / TCP(sport=sport, dport=80, flags="A", seq=cseq + 1, ack=sseq + 1)
    ack.time = t0 + 0.002
    lines = [f"{method} {path} HTTP/1.1", "Host: app.example.test"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    if body and not any(k.lower() == "content-length" for k in headers):
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    request_payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    req = cb / TCP(sport=sport, dport=80, flags="PA", seq=cseq + 1, ack=sseq + 1) / Raw(load=request_payload)
    req.time = t0 + 0.003
    # --- 严格的 seq/ack 记账 -------------------------------------------------
    # 旧实现把 ack 写成 cseq+1+len(req.load)-16：`req.load` 是 Raw 层的整段请求字节
    # （不存在要扣掉的 16 字节），所以客户端 ack 恒比真实值小 16 —— 对 Suricata 的
    # 流重组来说，响应报文携带的 ack 落在已确认窗口"之后/之前"的边界，响应方向的
    # HTTP 事务可能因此不被解析（stat_code 为空）。response 方向现在需要被断言，
    # 因此这里按 ISN 逐段推进，不再做任何偏移。
    c_next = cseq + 1 + len(request_payload)  # 客户端下一个序号
    s_next = sseq + 1  # 服务端下一个序号
    s_ack = sb / TCP(sport=80, dport=sport, flags="A", seq=s_next, ack=c_next)
    s_ack.time = t0 + 0.004
    resp = sb / TCP(sport=80, dport=sport, flags="PA", seq=s_next, ack=c_next) / Raw(load=response)
    resp.time = t0 + 0.005
    s_next += len(response)
    cack = cb / TCP(sport=sport, dport=80, flags="A", seq=c_next, ack=s_next)
    cack.time = t0 + 0.006
    fin_c = cb / TCP(sport=sport, dport=80, flags="FA", seq=c_next, ack=s_next)
    fin_c.time = t0 + 0.007
    fin_s = sb / TCP(sport=80, dport=sport, flags="FA", seq=s_next, ack=c_next + 1)
    fin_s.time = t0 + 0.008
    packets.extend([syn, synack, ack, req, s_ack, resp, cack, fin_c, fin_s])


def _raw_exchange(packets, sport, dport, server_payload: bytes, offset: float = 0.0):
    """最小 TCP 会话（无 HTTP 层）：用于非 HTTP 响应方向规则（如 TLS 443 magic）。

    三次握手 + 服务端单段载荷 + 客户端确认 + FIN；seq/ack 按 ISN 严格推进。
    """
    from scapy.all import Ether, IP, TCP, Raw

    cseq, sseq = 1000, 5000
    t0 = 1750000100.0 + offset
    cb = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT_IP, dst=SERVER_IP)
    sb = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER_IP, dst=CLIENT_IP)
    syn = cb / TCP(sport=sport, dport=dport, flags="S", seq=cseq)
    syn.time = t0
    synack = sb / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    synack.time = t0 + 0.001
    ack = cb / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1)
    ack.time = t0 + 0.002
    c_next = cseq + 1
    s_next = sseq + 1
    resp = sb / TCP(sport=dport, dport=sport, flags="PA", seq=s_next, ack=c_next) / Raw(load=server_payload)
    resp.time = t0 + 0.003
    s_next += len(server_payload)
    cack = cb / TCP(sport=sport, dport=dport, flags="A", seq=c_next, ack=s_next)
    cack.time = t0 + 0.004
    fin_c = cb / TCP(sport=sport, dport=dport, flags="FA", seq=c_next, ack=s_next)
    fin_c.time = t0 + 0.005
    fin_s = sb / TCP(sport=dport, dport=sport, flags="FA", seq=s_next, ack=c_next + 1)
    fin_s.time = t0 + 0.006
    packets.extend([syn, synack, ack, resp, cack, fin_c, fin_s])


def raw_packets(sport: int, dport: int, server_payload: bytes, offset: float = 0.0) -> list:
    packets: list = []
    _raw_exchange(packets, sport, dport, server_payload, offset)
    return packets


def _response(body: bytes, status: int = 200, ctype: str = "text/plain") -> bytes:
    reasons = {200: "OK", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}
    return (
        f"HTTP/1.1 {status} {reasons.get(status, 'Response')}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1") + body


def build_pairs() -> dict[str, dict[str, list]]:
    """返回 {case: {"pos": packets, "neg": packets}}。"""
    UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    def wrap(req: str, resp: bytes, sport: int, method: str, path: str, headers: dict, body: bytes, offset: float):
        p = []
        _http_exchange(p, sport, method, path, headers, body, resp, offset=offset)
        return p

    pairs: dict[str, dict[str, list]] = {}

    # 1. http.uri —— 14010049:
    #    http.uri; content:"/e/tool/gbook/?bid=1"; nocase; flow:to_server,established; lua:sqli_context.lua
    #    该规则除 content 外还挂了 lua:sqli_context.lua（SQL 注入上下文），lua 对 URI/body/Header
    #    做 URL 解码后要求命中 union+select / 布尔式 / 报错函数等特征；只放 "/e/tool/gbook/?bid=1"
    #    时 lua 返回 0，规则永不告警（CI run 44774234071 的 no-hit 正是这个原因）。
    #    因此 URI = 规则要求的前缀 + 编码后的 SQL 注入载荷：
    #      content 前缀 "/e/tool/gbook/?bid=1" 保持字面（http.uri 归一化后仍含它）；
    #      追加 "%20union%20select%201%2C2" —— lua 自己解码（sqli_context.lua decode(2)）后命中
    #      "union"+"select"，满足上下文。注意此处刻意验证 http.uri（归一化）而非 raw：
    #      %20/%2C 解码后是空格/逗号，raw 里则是 %XX。
    pos_uri = "/e/tool/gbook/?bid=1%20union%20select%201%2C2"
    # 负例：同样带 SQL 注入上下文（lua 会判真），但 content 前缀是 bid=2 → 证明拦在 content 上，
    # 而不是"lua 没命中所以没告警"的假阴性。
    neg_uri = "/e/tool/gbook/?bid=2%20union%20select%201%2C2"
    pairs["uri_14010049"] = {
        "pos": wrap("", _response(b"ok"), 40001, "GET", pos_uri, {"User-Agent": UA_NORMAL}, b"", 0.0),
        "neg": wrap("", _response(b"ok"), 40002, "GET", neg_uri, {"User-Agent": UA_NORMAL}, b"", 0.1),
    }

    # 2. http.uri.raw —— 11020030: content:"/htsearch?exclude=%60/etc/passwd%60"
    pairs["raw_11020030"] = {
        "pos": wrap("", _response(b"ok"), 40003, "GET", "/htsearch?exclude=%60/etc/passwd%60", {"User-Agent": UA_NORMAL}, b"", 0.2),
        # 解码后的反引号：http.uri.raw 语义下 %60 不应被再次解码 → 不得命中
        "neg": wrap("", _response(b"ok"), 40004, "GET", "/htsearch?exclude=`/etc/passwd`", {"User-Agent": UA_NORMAL}, b"", 0.3),
    }

    # 3. http.header —— 9101110: http.request_header; content:"Acunetix-"; pcre Acunetix-(Aspect|Product)
    pairs["hdr_9101110"] = {
        "pos": wrap("", _response(b"ok"), 40005, "GET", "/", {"User-Agent": UA_NORMAL, "Acunetix-Aspect": "2.0"}, b"", 0.4),
        "neg": wrap("", _response(b"ok"), 40006, "GET", "/", {"User-Agent": UA_NORMAL, "X-Scanner": "other"}, b"", 0.5),
    }

    # 4. http.method —— 9101113: http.method; pcre ^(TRACE|TRACK|PROPFIND|MKCOL|PUT|DELETE)$
    pairs["method_9101113"] = {
        "pos": wrap("", _response(b"ok"), 40007, "TRACE", "/", {"User-Agent": UA_NORMAL}, b"", 0.6),
        "neg": wrap("", _response(b"ok"), 40008, "GET", "/", {"User-Agent": UA_NORMAL}, b"", 0.7),
    }

    # 5. http.stat_code —— 13060038:
    #    http.stat_code; content:"200"; pkt_data; content:"|0d 0a 0d 0a|";
    #    content:"|23 21 2f|bin|2f|bash"; nocase; distance:0; within:11; flow:to_client,established
    #    三个匹配段：①响应状态码 200；②pkt_data 里 CRLFCRLF（响应头结束）；③紧随其后的
    #    "#!/bin/bash"（|23 21 2f| = "#!/"，|2f| = "/"，11 字节，正好 within:11 + distance:0
    #    要求紧贴在 CRLFCRLF 之后）。
    #
    #    关键坑（CI run 44774234071 的 no-hit）：规则头是 `any any -> any $HTTP_PORTS`，
    #    而 Suricata 的箭头只按报文实际 src/dst 取值比对端口（docs 8.1.5：-> 只评估同方向报文，
    #    端口/地址按写法与报文 src/dst 对应）。响应报文是 server:80 -> client:<临时端口>，
    #    其**目的端口**是客户端临时端口；只有客户端源端口落在 $HTTP_PORTS 里，规则的目的端口
    #    $HTTP_PORTS 才可能命中。原夹具用 40009/40010 这类临时端口 → 目的端口不在
    #    [80,8080,8000,443,8443] → 规则整条不会被评估 → no-hit。
    #    t45 曾把客户端端口取 8080 绕开 to_client 端口缺陷；t46 已把规则头翻成
    #    `any $HTTP_PORTS -> any any`（服务端 80 在源端口侧），故这里还原为普通临时端口，
    #    证明规则在真实客户端端口下也能命中。
    shebang = b"#!/bin/bash\nuid=0\n"
    # 负例：同样是 200 + CRLFCRLF 后紧跟 11 字节 shebang，但解释器是 /bin/sh 不是 /bin/bash
    # → 第三个 content 不命中（不是"没有 body"的弱负例）。
    other_shebang = b"#!/bin/sh\nuid=0\n"
    pairs["stat_13060038"] = {
        "pos": wrap("", _response(shebang), 40009, "GET", "/dl/backup.sh", {"User-Agent": UA_NORMAL}, b"", 0.8),
        "neg": wrap("", _response(other_shebang), 40010, "GET", "/dl/backup.sh", {"User-Agent": UA_NORMAL}, b"", 0.9),
    }

    # 6. payload —— 13020171: content:"Havij"; pcre /\x0d\x0aUser-Agent:.+[+\s]Havij/i
    #    Havij 必须出现在 UA 值内且 UA 行后有空白分隔（pcre 要求 [+ \s]Havij）
    pairs["payload_13020171"] = {
        "pos": wrap("", _response(b"ok"), 40011, "GET", "/news.php?id=1", {"User-Agent": "sqlmap/1.0 Havij"}, b"", 1.0),
        "neg": wrap("", _response(b"ok"), 40012, "GET", "/news.php?id=1", {"User-Agent": UA_NORMAL}, b"", 1.1),
    }

    # 7. to_client —— 10020245（端口组变量，t46 已翻为 any $HTTP_PORTS -> any any）
    #    http.stat_code; content:"200"; pkt_data; content:"|3c|html|3e 3c|head|3e 3c|title|3e|JspSpy"; nocase
    #    关键字节：响应状态码 200 + pkt_data 里字面 `<html><head><title>JspSpy`
    pair_body = b"<html><head><title>JspSpy Backdoor</title></head><body>ok</body></html>"
    plain_body = b"<html><head><title>Normal Page</title></head><body>ok</body></html>"
    pairs["jspspy_10020245"] = {
        "pos": wrap("", _response(pair_body, ctype="text/html"), 40013, "GET", "/index.jsp", {"User-Agent": UA_NORMAL}, b"", 1.2),
        "neg": wrap("", _response(plain_body, ctype="text/html"), 40014, "GET", "/index.jsp", {"User-Agent": UA_NORMAL}, b"", 1.3),
    }

    # 8. from_server —— 10010504（端口组变量，t46 已翻）
    #    content:"FindProxyForURL"; content:"import";
    #    pcre:"/^import\s+[a-zA-Z0-9\x2e_]+\x3b/im" —— 必须有一行以 import 开头 + token + ';'
    pac_ok = b'function FindProxyForURL(url, host) {\nimport proxy.config;\nreturn "DIRECT";\n}\n'
    pac_bad = b'function FindProxyForURL(url, host) {\n// proxy config omitted\nreturn "DIRECT";\n}\n'
    pairs["pac_10010504"] = {
        "pos": wrap("", _response(pac_ok), 40015, "GET", "/wpad.dat", {"User-Agent": UA_NORMAL}, b"", 1.4),
        "neg": wrap("", _response(pac_bad), 40016, "GET", "/wpad.dat", {"User-Agent": UA_NORMAL}, b"", 1.5),
    }

    # 9. to_client 数字端口 —— 11021334（【依赖 t48】服务端 443 → 客户端临时端口）
    #    content:"|7a 81 e7 87 6f ae 0d 7d 7f cf 4d e9 dd 46 27 4b|"; flow:to_client,established
    #    t46 已把规则头翻成 `any 443 -> any any`（t47 末轮核对：已由 t48 完成），
    #    服务端 443 为源端口，客户端 40017 临时端口即可命中。
    magic = bytes.fromhex("7a81e7876fae0d7d7fcf4de9dd46274b")
    pairs["tlsreneg_11021334"] = {
        "pos": raw_packets(40017, 443, b"\x16\x03\x01\x00\x30" + magic + b"\x00\x10", 1.6),
        "neg": raw_packets(40018, 443, b"\x16\x03\x01\x00\x30" + bytes(16) + b"\x00\x10", 1.7),
    }

    # ---- R12-7：6 类 buffer 的第 2 组 ----

    # 10. http.uri —— 11021402: http.uri; content:"js/hrm/getdata.jsp"; content:"cmd";
    #     content:"getSelectAllId"; pcre:"/sql\s*=[^\r\n&=]*('|"|`|;|\x82|UNION|OR|SELECT|FROM|AND|\+|...)/"
    #     pos：sql=1' or 1=1（or 布尔式，不同关键字）；neg：sql=1plus2（无 SQL 关键字 → pcre 不中）
    pos_uri2 = "/js/hrm/getdata.jsp?cmd=1&getSelectAllId=1&sql=1%27or%201=1"
    neg_uri2 = "/js/hrm/getdata.jsp?cmd=1&getSelectAllId=1&sql=1plus2"
    pairs["uri2_11021402"] = {
        "pos": wrap("", _response(b"ok"), 40019, "GET", pos_uri2, {"User-Agent": UA_NORMAL}, b"", 1.8),
        "neg": wrap("", _response(b"ok"), 40020, "GET", neg_uri2, {"User-Agent": UA_NORMAL}, b"", 1.9),
    }

    # 11. http.uri.raw —— 11020049: content:"%d0%af"; pcre:"/^(GET|PUT|PROPFIND)[^\r\n]+\.\.%d0%af/i"
    #     pos：/..%d0%afetc/passwd；neg：/..%d0%9cetc/passwd（不同字节，content/pcre 都不中）
    pairs["raw2_11020049"] = {
        "pos": wrap("", _response(b"ok"), 40021, "GET", "/..%d0%afetc/passwd", {"User-Agent": UA_NORMAL}, b"", 2.0),
        "neg": wrap("", _response(b"ok"), 40022, "GET", "/..%d0%9cetc/passwd", {"User-Agent": UA_NORMAL}, b"", 2.1),
    }

    # 12. http.header —— 11027642: http.header; content:"X-Requested-With"; content:"X-Forwarded-For";
    #     pkt_data; pcre:"/X-Forwarded-For[^\r\n&]*[^a-zA-Z](select|drop|...|union|...)[^a-zA-Z]/i"
    #     pos：X-Forwarded-For 里带 union；neg：带 plus（无 SQL 关键字）
    pairs["hdr2_11027642"] = {
        "pos": wrap("", _response(b"ok"), 40023, "GET", "/", {"User-Agent": UA_NORMAL, "X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": "1.1.1.1 union 1"}, b"", 2.2),
        "neg": wrap("", _response(b"ok"), 40024, "GET", "/", {"User-Agent": UA_NORMAL, "X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": "1.1.1.1 plus 2"}, b"", 2.3),
    }

    # 13. http.method —— 11021337: http.method; content:"PUT"; pkt_data; content:".jsp|2F 2F 2F 2F|"
    #     （规则含 pkt_data，字节断言按整条请求流比对）pos：PUT /shell.jsp////；neg：POST /shell.jsp
    pairs["method2_11021337"] = {
        "pos": wrap("", _response(b"ok"), 40025, "PUT", "/shell.jsp////", {"User-Agent": UA_NORMAL}, b"", 2.4),
        "neg": wrap("", _response(b"ok"), 40026, "POST", "/shell.jsp", {"User-Agent": UA_NORMAL}, b"", 2.5),
    }

    # 14. http.stat_code —— 10020255: http.stat_code; content:"200"; content:"PhpSpy";
    #     content:"www.4ngel.net"; pcre:"/Powered\s+?by\s*?<[^>]+?>PhpSpy/i"
    #     pos：200 + Powered by <b>PhpSpy</b> + www.4ngel.net；neg：OtherShell（无 PhpSpy 指纹）
    phpspy_ok = b"Powered by <b>PhpSpy</b> www.4ngel.net"
    phpspy_bad = b"Powered by <b>OtherShell</b> www.4ngel.net"
    pairs["stat2_10020255"] = {
        "pos": wrap("", _response(phpspy_ok, ctype="text/html"), 40027, "GET", "/p.php", {"User-Agent": UA_NORMAL}, b"", 2.6),
        "neg": wrap("", _response(phpspy_bad, ctype="text/html"), 40028, "GET", "/p.php", {"User-Agent": UA_NORMAL}, b"", 2.7),
    }

    # 15. payload —— 13020172: content:"sqlmap"; pcre:"/\r\nUser-Agent:[+\s]*sqlmap\/\d+\.\d+/i"
    #     pos：UA "sqlmap/1.0"（另一种工具 UA）；neg：普通浏览器 UA
    pairs["payload2_13020172"] = {
        "pos": wrap("", _response(b"ok"), 40029, "GET", "/news.php?id=1", {"User-Agent": "sqlmap/1.0"}, b"", 2.8),
        "neg": wrap("", _response(b"ok"), 40030, "GET", "/news.php?id=1", {"User-Agent": UA_NORMAL}, b"", 2.9),
    }

    return pairs


def generate(out_dir: Path) -> int:
    from scapy.all import wrpcap

    out_dir.mkdir(parents=True, exist_ok=True)
    pairs = build_pairs()
    count = 0
    for case, d in sorted(pairs.items()):
        for kind, packets in d.items():
            path = out_dir / f"{case}__{kind}.pcap"
            wrpcap(str(path), packets)
            print(f"wrote {path} ({len(packets)} packets)")
            count += 1
    print(f"\nGENERATE: {count} PCAPs -> {out_dir}")
    return 0


CONFIG_PATH = ROOT / "docker" / "suricata-converter-pcap.yaml"
PROBE_CONFIG_PATH = ROOT / "docker" / "probe-rules-validate.yaml"
RULE_ROOT = ROOT / "规则检测" / "suricata"
# R13-1：规则原文 → 夹具字节的运行时断言字段（见 check_rule_pcap_bytes）
CONTENT_RE = re.compile(r'content\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
PCRE_RE = re.compile(r'pcre\s*:\s*"?(/[^\s;"]+)"?', re.I)
SID_FIELD_RE = re.compile(r"\bsid\s*:\s*(\d+)")
FLOW_RE = re.compile(r"\bflow\s*:\s*[^;)]*", re.I)
BUFFER_TOKENS = (
    "http.uri.raw", "http_raw_uri", "http.uri", "http_uri", "http.stat_code", "http_stat_code",
    "http.request_header", "http.response_header", "http.header", "http_header",
    "http.method", "http_method", "file.data", "file_data",
    "http.user_agent", "http_user_agent", "http.cookie", "http_cookie",
)
BUFFER_ALIAS = {
    "http_raw_uri": "http.uri.raw", "http_uri": "http.uri", "http_stat_code": "http.stat_code",
    "http.request_header": "http.header", "http.response_header": "http.header",
    "http_header": "http.header", "http_method": "http.method", "file_data": "payload",
    "http_user_agent": "http.user_agent", "http_cookie": "http.cookie",
}
RULE_ROOT = ROOT / "规则检测" / "suricata"
SCENARIO_DIRS = ("DNS隧道与带外检测", "Web漏洞利用", "侦察与攻击工具指纹", "后门通信")

VAR_RE = re.compile(r"\$([A-Z][A-Z0-9_]*)")
RULE_FILE_RE = re.compile(r'^\s*-\s*"([^"]+\.rules)"\s*$', re.M)
# 规则头 = `alert <proto> <src> <sport> -> <dst> <dport> (` 之前的片段；
# content 里的 `$` 是负载字符（如 PHP `$_GET`），不是 vars，必须排除。
RULE_HEAD_RE = re.compile(r"^\s*(?:alert|drop|pass|reject)\s+[^(]*", re.I)


def parse_config(text: str) -> tuple[dict[str, str], list[str]]:
    """极简解析：返回 (vars 扁平表 {名: 值}, rule-files 列表)。

    只应付本仓配置的固定结构（vars.address-groups / vars.port-groups / rule-files），
    不引入 PyYAML 依赖（CI 的 python 环境没有保证装 pyyaml）。
    """
    variables: dict[str, str] = {}
    rule_files: list[str] = []
    in_vars = False
    in_rules = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "vars:":
            in_vars, in_rules = True, False
            continue
        if stripped == "rule-files:":
            in_vars, in_rules = False, True
            continue
        if not line.startswith((" ", "\t")):
            # 顶层其它键 → 退出两个块
            in_vars = in_rules = False
            continue
        if in_rules:
            m = RULE_FILE_RE.match(f'  - "{stripped[2:].strip().strip(chr(34))}"')
            if m:
                rule_files.append(m.group(1))
            continue
        if in_vars:
            if stripped in ("address-groups:", "port-groups:"):
                continue
            m = re.match(r'([A-Z][A-Z0-9_]*)\s*:\s*(.+)$', stripped)
            if m:
                variables[m.group(1)] = m.group(2).strip().strip("\"'")
    return variables, rule_files


def rule_header_vars(rule_text: str) -> set[str]:
    """抽取一个 .rules 文件里所有规则头引用的 $VAR（跳过 content 负载中的 $）。"""
    found: set[str] = set()
    for line in rule_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = RULE_HEAD_RE.match(s)
        if m:
            found.update(VAR_RE.findall(m.group(0)))
    return found


def check_config_vars(
    config_text: str,
    probe_config_text: str | None = None,
    rule_root: Path | None = None,
) -> tuple[list[str], list[str], dict]:
    """纯函数：配置 vars 与规则头 $VAR 的静态一致性检查。

    返回 (failures, notes, stats)。failures 为空即通过。
    规则：
      1. 规则头引用的每个 $VAR 必须在 vars 中定义（缺失即 FAIL，点名变量与示例文件）。
      2. vars 值里引用的 $VAR（例如 EXTERNAL_NET: "!$HOME_NET"）也必须已定义。
      3. 合并配置的 rule-files 必须 == probe-rules-validate 的 rule-files + 4 场景自研规则，
         且总数与 t38 声明的 51 一致（防止"少加载文件 → -T 假绿"）。
    """
    failures: list[str] = []
    notes: list[str] = []
    root = rule_root or RULE_ROOT

    variables, rule_files = parse_config(config_text)
    if not variables:
        failures.append("配置 vars 为空：规则头引用的 $VAR 必然全部未定义")
    if not rule_files:
        failures.append("配置 rule-files 为空：-T 会显示通过但实际没加载任何规则")

    # 2) vars 内部引用
    for name, value in sorted(variables.items()):
        for ref in VAR_RE.findall(value):
            if ref not in variables:
                failures.append(f"vars.{name} 的值引用了未定义变量 ${ref}")

    # 1) 规则头引用
    referenced: dict[str, str] = {}
    missing_files: list[str] = []
    scanned = 0
    for rel in rule_files:
        path = root / rel
        if not path.is_file():
            missing_files.append(rel)
            continue
        scanned += 1
        for var in rule_header_vars(path.read_text(encoding="utf-8", errors="replace")):
            referenced.setdefault(var, rel)
    for rel in missing_files:
        failures.append(f"rule-files 里的文件不存在: {rel}")
    for var, where in sorted(referenced.items()):
        if var not in variables:
            failures.append(f"规则头引用未定义变量 ${var}（示例文件 {where}）——suricata -T 会整批失败")
    unused = sorted(set(variables) - set(referenced))

    # 3) 规则清单对齐
    if probe_config_text is not None:
        probe_files = parse_config(probe_config_text)[1]
        scenario_files = [f for f in rule_files if f.split("/")[0] in SCENARIO_DIRS]
        expect = list(probe_files) + [f for f in scenario_files if f not in probe_files]
        if scenario_files and len(scenario_files) < 5:
            failures.append(
                f"4 个场景目录的规则文件只有 {len(scenario_files)} 个（期望 5：DNS/侦察/Web漏洞利用/后门通信 2 个）"
            )
        for f in probe_files:
            if f not in rule_files:
                failures.append(f"合并配置漏了 probe-rules-validate 的规则文件: {f}")
        extra = [f for f in rule_files if f not in expect]
        if extra:
            failures.append(f"合并配置含未登记来源的规则文件: {extra}")
        notes.append(
            f"规则清单: probe-rules-validate {len(probe_files)} + 场景 {len(scenario_files)} = {len(rule_files)} 个文件"
        )
        if len(rule_files) != len(probe_files) + len(scenario_files):
            failures.append("规则文件数 != probe + 场景（存在重复或漏算）")

    stats = {
        "variables": len(variables),
        "referenced": len(referenced),
        "unused": unused,
        "files": len(rule_files),
        "scanned": scanned,
    }
    notes.append(
        f"vars {len(variables)} 个已定义，规则头实际引用 {len(referenced)} 个"
        + (f"；未引用（保留）: {', '.join(unused)}" if unused else "")
    )
    notes.append(f"扫描规则文件 {scanned}/{len(rule_files)}")
    return failures, notes, stats


# ---------------------------------------------------------------------------
# R13-1：规则原文 ↔ PCAP 字节的运行时断言（不打印自证，失败点名 SID/字段）
# ---------------------------------------------------------------------------


def find_rule_by_sid(rule_root: Path, sid: int) -> tuple[Path | None, int, str]:
    """在规则产物里按 SID 定位原文（支持跨行的场景规则：sid: 单独一行）。

    返回 (path, 起始行号, 规则全文)；重复 SID 由 qa_converter_semantics 守卫。
    """
    for path in sorted(rule_root.rglob("*.rules")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = -1
        buf: list[str] = []
        for ln, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if stripped.lower().startswith(("alert", "drop", "reject", "pass")):
                start = ln
                buf = [stripped]
                # 不 continue：单行规则的 sid 就在本行，需要立刻检查
            else:
                if start < 0:
                    continue
                if stripped:
                    buf.append(stripped)
            m = SID_FIELD_RE.search(stripped)
            if m and int(m.group(1)) == sid:
                return path, start, " ".join(buf)
            if stripped.endswith(")") or (m and SID_FIELD_RE.search(stripped)):
                start = -1
                buf = []
    return None, 0, ""


def decode_snort_content(raw: str) -> bytes:
    """把 Suricata content 值解成字节：|hex| 逐字节展开，其余按 latin-1（含 \\" 转义）。"""
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == "|":
            j = raw.find("|", i + 1)
            if j < 0:
                out.extend(b"|")
                i += 1
                continue
            digits = re.sub(r"\s+", "", raw[i + 1 : j])
            out.extend(bytes.fromhex(digits))
            i = j + 1
            continue
        if raw[i] == "\\" and i + 1 < len(raw) and raw[i + 1] in ('"', "\\"):
            out.extend(raw[i + 1].encode("latin-1"))
            i += 2
            continue
        out.extend(raw[i].encode("latin-1"))
        i += 1
    return bytes(out)


def extract_rule_expectations(rule_line: str) -> dict:
    """从规则原文抽取可比对字段：buffer / flow 方向 / content 字节 / pcre 列表。"""
    low = rule_line.lower()
    flow_m = FLOW_RE.search(low)
    flow_text = flow_m.group(0) if flow_m else ""
    direction = "server_to_client" if ("to_client" in flow_text or "from_server" in flow_text) else "client_to_server"
    buffer = "payload"
    for token in BUFFER_TOKENS:
        if token in low:
            buffer = BUFFER_ALIAS.get(token, token)
            break
    contents = [decode_snort_content(x) for x in CONTENT_RE.findall(rule_line)]
    pcre_list = []
    for raw in PCRE_RE.findall(rule_line):
        m = re.match(r"^/(.*)/([a-zA-Z]*)$", raw)
        if not m:
            continue
        flags = 0
        known = True
        for f in m.group(2):
            flags |= {"i": re.I, "s": re.S, "m": re.M, "x": re.X}.get(f.lower(), 0) or 0
            if f.lower() not in ("i", "s", "m", "x"):
                known = False
        if known:
            pcre_list.append((m.group(1), flags))
    return {
        "buffer": buffer,
        "direction": direction,
        "contents": contents,
        "pcre": pcre_list,
        "has_lua": "lua:" in low,
        # R12-7：带 pkt_data 的规则，后续 content/pcre 匹配的是整条报文流而非 sticky buffer
        "has_pkt_data": "pkt_data" in low,
    }


def pcap_streams(path: Path) -> tuple[bytes, bytes]:
    """scapy 读回 PCAP，按端点角色分成 (客户端→服务端, 服务端→客户端) 两股字节流。"""
    from scapy.all import rdpcap, TCP, Raw

    req = bytearray()
    resp = bytearray()
    for pkt in rdpcap(str(path)):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue
        tcp = pkt[TCP]
        data = bytes(pkt[Raw].load)
        if tcp.sport in (80, 443) and tcp.dport >= 1024:
            resp.extend(data)
        else:
            req.extend(data)
    return bytes(req), bytes(resp)


def buffer_stream(buffer: str, req: bytes, resp: bytes) -> bytes:
    """按 sticky buffer 选择待比对字节流（归一化 URI / 方法 token / 原始流）。"""
    import urllib.parse

    if buffer in ("http.uri", "http.uri.raw"):
        first = req.split(b"\r\n", 1)[0]
        path = first.split(b" ", 2)[1] if b" " in first else b""
        if buffer == "http.uri":
            path = urllib.parse.unquote(path.decode("latin-1")).encode("latin-1")
        return path
    if buffer == "http.method":
        first = req.split(b"\r\n", 1)[0]
        return first.split(b" ", 1)[0]
    return resp  # 响应方向（stat_code / payload / header 等）由 direction 决定传入 resp


def check_rule_pcap_bytes(
    pcap_dir: Path,
    rule_root: Path = RULE_ROOT,
    cases: tuple | None = None,
    verbose: bool = True,
) -> tuple[list[str], list[str], dict]:
    """把规则原文的关键字节与 PCAP 载荷逐项比对：pos 必含、neg 必缺一，失败点名 SID/字段。

    返回 (failures, notes, stats)。不依赖 suricata / docker，CI 在 --eve-root 之前跑。
    """
    failures: list[str] = []
    notes: list[str] = []
    checked = 0
    for case, sid, expected_buffer, desc in (cases if cases is not None else CASES):
        rule_path, ln, rule_line = find_rule_by_sid(rule_root, sid)
        if not rule_path:
            failures.append(f"{case} sid={sid}: 规则产物中找不到 SID（rule_root={rule_root}）")
            continue
        exp = extract_rule_expectations(rule_line)
        # buffer 一致性：规则原文抽出的 buffer 必须与 CASE 标注一致（防夹具与规则漂移）
        if exp["buffer"] != expected_buffer:
            failures.append(
                f"{case} sid={sid}: buffer 不一致 CASE={expected_buffer} 规则原文={exp['buffer']} "
                f"({rule_path.name}:{ln})"
            )
        if not exp["contents"] and not exp["pcre"]:
            failures.append(f"{case} sid={sid}: 规则原文没有可比对 content/pcre（{rule_path.name}:{ln}）")
            continue

        for label, expect_hit in (("pos", True), ("neg", False)):
            pcap = pcap_dir / f"{case}__{label}.pcap"
            if not pcap.is_file():
                failures.append(f"{case}/{label}: PCAP 不存在 {pcap}")
                continue
            req, resp = pcap_streams(pcap)
            stream = buffer_stream(exp["buffer"], req, resp)
            # 方向一致性：to_client/from_server 的断言字节应在响应流；to_server 在请求流
            target = resp if exp["direction"] == "server_to_client" else req
            if exp["buffer"] in ("http.uri", "http.uri.raw", "http.method"):
                target = stream  # URI/方法已从对应流切出
            if exp.get("has_pkt_data"):
                # R12-7：规则在 sticky buffer 之外还要求 pkt_data → 后续字节比对整条报文流
                target = resp if exp["direction"] == "server_to_client" else req
            missing_content = [c for c in exp["contents"] if c not in target]
            missing_pcre = []
            for pat, flags in exp["pcre"]:
                try:
                    if re.search(pat, target.decode("latin-1"), flags) is None:
                        missing_pcre.append(pat)
                except re.error as exc:
                    failures.append(f"{case}/{label} sid={sid}: pcre 无法解析 {pat!r}: {exc}")
            all_present = not missing_content and not missing_pcre
            if expect_hit and not all_present:
                fails = []
                if missing_content:
                    fails.append("content=" + ",".join(c.hex() for c in missing_content))
                if missing_pcre:
                    fails.append("pcre=" + ",".join(missing_pcre))
                failures.append(f"{case}/pos sid={sid}: 规则关键字节在 PCAP 中缺失（{' | '.join(fails)}）")
            if (not expect_hit) and all_present:
                failures.append(
                    f"{case}/neg sid={sid}: 负例 PCAP 仍满足规则全部关键字节（content+pcre 全中），"
                    "负例失效"
                )
            checked += 1

        # lua 上下文（从规则原文抽取）：挂了 sqli_context.lua 的规则要求解码 URI 里 union+select
        if exp["has_lua"] and exp["buffer"] == "http.uri":
            for label in ("pos", "neg"):
                pcap = pcap_dir / f"{case}__{label}.pcap"
                if not pcap.is_file():
                    continue
                req, _ = pcap_streams(pcap)
                uri = buffer_stream("http.uri", req, b"").decode("latin-1").lower()
                if not re.search(r"union\s+select", uri):
                    failures.append(
                        f"{case}/{label} sid={sid}: 规则含 lua:sqli_context.lua 但解码 URI 无 SQL 上下文"
                        f"（{uri!r}）"
                    )

    stats = {"checked": checked, "cases": len(cases if cases is not None else CASES)}
    if verbose:
        notes.append(f"规则原文 ↔ PCAP 字节：{checked} 组（{stats['cases']} cases × pos/neg）")
    return failures, notes, stats


def self_test() -> int:
    """自测：4 条正例 + 4 条负例；负例必须 FAIL 且点名关键变量。"""
    checks: list[tuple[str, bool, str]] = []

    GOOD = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "[203.0.113.0/24]"
  port-groups:
    HTTP_PORTS: "[80,8080]"
rule-files:
  - "a.rules"
"""
    GOOD_RULES = {"a.rules": 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"x"; sid:1;)'}

    def run(config: str, rules: dict[str, str], probe: str | None = None):
        import tempfile

        tmp = Path(tempfile.mkdtemp(prefix="pcapcfg-"))
        for name, body in rules.items():
            (tmp / name).parent.mkdir(parents=True, exist_ok=True)
            (tmp / name).write_text(body, encoding="utf-8")
        return check_config_vars(config, probe, rule_root=tmp)

    f, _, st = run(GOOD, GOOD_RULES)
    checks.append(("正例：vars 齐全 → 通过", not f, str(f)))

    bad_missing = GOOD.replace('    HTTP_PORTS: "[80,8080]"\n', "")
    f, _, _ = run(bad_missing, GOOD_RULES)
    checks.append(("负例：缺 HTTP_PORTS（CI 实际故障）→ FAIL 点名", any("$HTTP_PORTS" in x for x in f), str(f)))

    f, _, _ = run(GOOD, {"a.rules": 'alert tcp any any -> any 80 (content:"$_GET"; sid:2;)'})
    checks.append(("正例：content 里的 $ 不算 vars → 通过", not f, str(f)))

    f, _, _ = run(GOOD, {"a.rules": 'alert tcp any any -> $UNKNOWN_SERVERS 80 (msg:"x"; sid:3;)'})
    checks.append(
        (
            "负例：规则头引用未定义的 $UNKNOWN_SERVERS → FAIL 点名",
            any("$UNKNOWN_SERVERS" in x for x in f),
            str(f),
        )
    )

    alias_bad = GOOD.replace('    EXTERNAL_NET: "[203.0.113.0/24]"', '    EXTERNAL_NET: "!$HOME_NET"').replace(
        '    HOME_NET: "[10.0.0.0/8]"\n', ""
    )
    f, _, _ = run(alias_bad, GOOD_RULES)
    checks.append(("负例：vars 值引用未定义变量（!$HOME_NET）→ FAIL", any("$HOME_NET" in x for x in f), str(f)))

    f, _, _ = run(GOOD.replace('  - "a.rules"', ""), GOOD_RULES)
    checks.append(("负例：rule-files 为空 → FAIL", any("rule-files 为空" in x for x in f), str(f)))

    f, _, _ = run(GOOD, {})  # 规则文件不存在
    checks.append(("负例：rule-files 指向不存在的文件 → FAIL", any("不存在" in x for x in f), str(f)))

    # 清单对齐：probe 有 b.rules 而合并配置没有 → FAIL
    probe = GOOD.replace('  - "a.rules"', '  - "a.rules"\n  - "b.rules"')
    f, _, _ = run(GOOD, GOOD_RULES, probe=probe)
    checks.append(
        ("负例：漏加载 probe 规则文件 → FAIL", any("漏了 probe-rules-validate" in x for x in f), str(f))
    )

    f, _, _ = run(GOOD.replace('  - "a.rules"', '  - "a.rules"\n  - "ghost.rules"'), GOOD_RULES, probe=GOOD)
    checks.append(
        ("负例：多出未登记来源的规则文件 → FAIL", any("未登记来源" in x for x in f), str(f))
    )

    # --- R13-1 规则原文 ↔ PCAP 字节运行时断言的自测（不依赖 CI/docker） ---
    import tempfile
    from scapy.all import wrpcap, rdpcap, TCP, Raw

    byte_tmp = Path(tempfile.mkdtemp(prefix="pcap-bytes-"))
    for case, d in build_pairs().items():
        for kind, packets in d.items():
            wrpcap(str(byte_tmp / f"{case}__{kind}.pcap"), packets)

    # R13-1 要求至少覆盖的 5 组必须都在 CASES 里（否则字节断言会漏掉）
    case_sids = {sid for _, sid, _, _ in CASES}
    required_sids = {14010049, 13060038, 10020245, 10010504, 11021334}
    checks.append(
        (
            "字节断言覆盖：5 个必需 SID 全在 CASES 中",
            required_sids <= case_sids,
            str(sorted(required_sids - case_sids)),
        )
    )

    f, _, st = check_rule_pcap_bytes(byte_tmp, verbose=False)
    checks.append(
        (
            f"字节断言：{st['cases']} 组 pos/neg 规则原文↔PCAP 全匹配 → 通过",
            not f and st["checked"] == 2 * len(CASES),
            str(f[:2]),
        )
    )

    # 负例：改坏 stat_13060038__pos 的 shebang 首字节（# -> X）→ 必须 FAIL 点名 SID/content
    broken = byte_tmp / "stat_13060038__pos.pcap"
    pkts = rdpcap(str(broken))
    changed = 0
    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and b"#!/bin/bash" in bytes(pkt[Raw].load):
            data = bytes(pkt[Raw].load)
            pkt[Raw].load = data.replace(b"#!/bin/bash", b"X!/bin/bash", 1)
            changed += 1
            break
    wrpcap(str(broken), pkts)
    f2, _, _ = check_rule_pcap_bytes(
        byte_tmp,
        cases=(("stat_13060038", 13060038, "http.stat_code", ""),),
        verbose=False,
    )
    checks.append(
        (
            "字节断言负例：改坏一个 PCAP 字节 → FAIL 点名 SID/content",
            changed == 1 and any("13060038" in x and "content" in x for x in f2),
            f"changed={changed} fails={f2[:2]}",
        )
    )

    # 负例：改坏规则原文里的关键 content（临时 rule_root）→ 必须 FAIL 点名 SID
    rule_tmp = Path(tempfile.mkdtemp(prefix="pcap-rules-"))
    rp, rln, rtext = find_rule_by_sid(RULE_ROOT, 14010049)
    if rp:
        mutated = rtext.replace('content:"/e/tool/gbook/?bid=1"', 'content:"/e/tool/gbook/?bid=9"')
        (rule_tmp / "mutated.rules").write_text(mutated + "\n", encoding="utf-8")
        f3, _, _ = check_rule_pcap_bytes(
            byte_tmp,
            rule_root=rule_tmp,
            cases=(("uri_14010049", 14010049, "http.uri", ""),),
            verbose=False,
        )
        checks.append(
            (
                "字节断言负例：规则原文 content 改一个字节 → FAIL 点名 SID",
                any("14010049" in x and "缺失" in x for x in f3),
                str(f3[:2]),
            )
        )

    bad = sum(1 for _, ok, _ in checks if not ok)
    for name, ok, detail in checks:
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  [{detail[:180]}]"))
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def run_rule_byte_check(pcap_dir: Path) -> int:
    """主流程入口：打印规则原文↔PCAP 字节断言结果；FAIL 点名 SID/字段并返回 1。"""
    if not RULE_ROOT.is_dir():
        print(f"FAIL: 规则产物目录不存在 {RULE_ROOT}", file=sys.stderr)
        return 1
    failures, notes, stats = check_rule_pcap_bytes(pcap_dir)
    print("== 规则原文 ↔ PCAP 字节断言（R13-1）==")
    for n in notes:
        print(" -", n)
    if failures:
        print("\nRULE-BYTE CHECK: FAIL", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print(f"\nRULE-BYTE CHECK: PASS ({stats['checked']} 组 pos/neg，逐字段比对规则原文与 PCAP 载荷)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true", help="生成正/负 PCAP 对到 测试用例/converter_pcap/")
    parser.add_argument("--list", action="store_true", help="打印用例清单（SID×buffer×正负）")
    parser.add_argument(
        "--check-config-vars",
        action="store_true",
        help="静态检查合并配置：规则头引用的 $VAR 是否都在 vars 中定义（无需 suricata）",
    )
    parser.add_argument(
        "--check-rule-bytes",
        action="store_true",
        help="运行时断言：按 SID 读规则原文，与生成的 PCAP 载荷逐字节比对（pos 必含/neg 必缺）",
    )
    parser.add_argument("--self-test", action="store_true", help="静态检查 + 字节断言自测（含负例）")
    parser.add_argument(
        "--eve-root",
        default=None,
        help="断言模式：读取 <eve-root>/<case>__{pos,neg}/eve.json 断言命中",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    if args.self_test:
        return self_test()

    if args.check_config_vars:
        if not CONFIG_PATH.is_file():
            print(f"FAIL: 配置文件不存在: {CONFIG_PATH}", file=sys.stderr)
            return 1
        probe_text = (
            PROBE_CONFIG_PATH.read_text(encoding="utf-8", errors="replace")
            if PROBE_CONFIG_PATH.is_file()
            else None
        )
        failures, notes, stats = check_config_vars(
            CONFIG_PATH.read_text(encoding="utf-8", errors="replace"), probe_text
        )
        print("== 合并 -T 配置 vars 静态检查 ==")
        for n in notes:
            print(" -", n)
        if failures:
            print("\nCONFIG VARS: FAIL", file=sys.stderr)
            for item in failures:
                print(" -", item, file=sys.stderr)
            return 1
        print(
            f"\nCONFIG VARS: PASS ({stats['variables']} vars defined, "
            f"{stats['referenced']} referenced by rule headers, {stats['files']} rule files)"
        )
        return 0

    if args.check_rule_bytes:
        return run_rule_byte_check(OUT_DIR)

    if args.list:
        print("用例清单（SID × buffer × 正/负）：")
        for case, sid, buffer, desc in CASES:
            if case in T48_DEPENDENT_CASES:
                print(f"  [t48 依赖已满足] {case} sid={sid}: 规则头 any 443 -> any any 已核对，pos 应命中")
            print(f"  {case:18s} sid={sid} buffer={buffer:14s} {desc}")
        return 0

    if args.generate:
        rc = generate(OUT_DIR)
        if rc:
            return rc
        # R13-1：生成后立刻做规则原文↔PCAP 字节断言（CI 的 generate 步骤会跑到）
        return run_rule_byte_check(OUT_DIR)

    if args.eve_root:
        # R13-1：断言 EVE 命中前先核对夹具字节（CI 的 hit-regression 步骤会跑到），
        # 防止"EVE 恰好命中但夹具与规则不匹配"的自证式绿。
        byte_rc = run_rule_byte_check(OUT_DIR)
        if byte_rc:
            print("规则原文↔PCAP 字节断言失败：拒绝继续 EVE 命中断言", file=sys.stderr)
            return byte_rc
        import json
        import os

        root = Path(args.eve_root)
        failures = []
        print("== PCAP 命中断言 ==")
        for case, sid, buffer, desc in CASES:
            if case in T48_DEPENDENT_CASES:
                print(f"  [t48 依赖已满足] {case} sid={sid}: 规则头 any 443 -> any any 已核对，pos 应命中")
            pos_path = root / f"{case}__pos" / "eve.json"
            neg_path = root / f"{case}__neg" / "eve.json"
            for label, path, expect in (("pos", pos_path, True), ("neg", neg_path, False)):
                if not path.is_file():
                    failures.append(f"{case}/{label}: missing {path}")
                    continue
                sids = set()
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event_type") == "alert":
                        a = ev.get("alert", {})
                        if isinstance(a.get("signature_id"), int):
                            sids.add(a["signature_id"])
                hit = sid in sids
                ok = hit if expect else not hit
                status = "OK" if ok else "FAIL"
                print(f"  {case} [{buffer}] {label}: sid={sid} expected={'hit' if expect else 'no-hit'} got={'hit' if hit else 'no-hit'} -> {status}")
                if not ok:
                    failures.append(f"{case}/{label}: sid={sid} expected={'hit' if expect else 'no-hit'}, got {'hit' if hit else 'no-hit'} (alerts={sorted(sids)})")
        if failures:
            print("\nCONVERTER PCAP REGRESSION: FAIL", file=sys.stderr)
            for item in failures:
                print(" -", item, file=sys.stderr)
            return 1
        print(f"\nCONVERTER PCAP REGRESSION: PASS ({len(CASES)} pairs, pos must hit, neg must not)")
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
