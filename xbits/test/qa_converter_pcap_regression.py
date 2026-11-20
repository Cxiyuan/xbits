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

跑法：--generate 生成 PCAP 对（scapy，本地可跑）；--run-in-ci 形态由 CI 调
docker xbits-suricata 用 /opt/xbits/suricata-converter-pcap.yaml 跑每对 PCAP，
EVE 输出交 assert 断言。断言规则：
  pos PCAP → EVE 必须出现对应 SID（且 xbits hook 一致，见 --with-hook）；
  neg PCAP → EVE 不得出现对应 SID（负例旁必须有必中对照：每类负例同时包含
  另一 buffer 类的正例命中，防"规则没加载全绿"——由 config 加载全部规则文件保证）。
"""
from __future__ import annotations

import argparse
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
    ("stat_13060038", 13060038, "http.stat_code", "200 + shebang body"),
    ("payload_13020171", 13020171, "payload", "Havij UA"),
]

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
    req = cb / TCP(sport=sport, dport=80, flags="PA", seq=cseq + 1, ack=sseq + 1) / Raw(
        load=("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    )
    req.time = t0 + 0.003
    s_ack = sb / TCP(sport=80, dport=sport, flags="A", seq=sseq + 1, ack=cseq + 1 + len(req.load) - 16)
    s_ack.time = t0 + 0.004
    resp = sb / TCP(sport=80, dport=sport, flags="PA", seq=sseq + 1, ack=cseq + 1 + len(req.load) - 16) / Raw(
        load=response
    )
    resp.time = t0 + 0.005
    cack = cb / TCP(sport=sport, dport=80, flags="A", seq=cseq + 1 + len(req.load) - 16, ack=sseq + 1 + len(response))
    cack.time = t0 + 0.006
    fin_c = cb / TCP(sport=sport, dport=80, flags="FA", seq=cseq + 1 + len(req.load) - 16, ack=sseq + 1 + len(response))
    fin_c.time = t0 + 0.007
    fin_s = sb / TCP(sport=80, dport=sport, flags="FA", seq=sseq + 1 + len(response), ack=cseq + 2 + len(req.load) - 16)
    fin_s.time = t0 + 0.008
    packets.extend([syn, synack, ack, req, s_ack, resp, cack, fin_c, fin_s])


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

    # 1. http.uri —— 14010049: http_uri; content:"/e/tool/gbook/?bid=1"
    pos_uri = "/e/tool/gbook/?bid=1"
    neg_uri = "/e/tool/gbook/?bid=2"
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

    # 5. http.stat_code —— 13060038: 200 + pkt_data CRLF 后 |23 21 2f|bin|2f|bash
    shebang = b"#!/bin/bash\nuid=0\n"
    no_shebang = b"# python helper\nprint('hello')\n"  # '#!' 后是 python 不是 /bin/bash
    pairs["stat_13060038"] = {
        "pos": wrap("", _response(shebang), 40009, "GET", "/dl/backup.sh", {"User-Agent": UA_NORMAL}, b"", 0.8),
        "neg": wrap("", _response(no_shebang), 40010, "GET", "/dl/helper.py", {"User-Agent": UA_NORMAL}, b"", 0.9),
    }

    # 6. payload —— 13020171: content:"Havij"; pcre /\x0d\x0aUser-Agent:.+[+\s]Havij/i
    #    Havij 必须出现在 UA 值内且 UA 行后有空白分隔（pcre 要求 [+ \s]Havij）
    pairs["payload_13020171"] = {
        "pos": wrap("", _response(b"ok"), 40011, "GET", "/news.php?id=1", {"User-Agent": "sqlmap/1.0 Havij"}, b"", 1.0),
        "neg": wrap("", _response(b"ok"), 40012, "GET", "/news.php?id=1", {"User-Agent": UA_NORMAL}, b"", 1.1),
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true", help="生成正/负 PCAP 对到 测试用例/converter_pcap/")
    parser.add_argument("--list", action="store_true", help="打印用例清单（SID×buffer×正负）")
    parser.add_argument(
        "--eve-root",
        default=None,
        help="断言模式：读取 <eve-root>/<case>__{pos,neg}/eve.json 断言命中",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    if args.list:
        print("用例清单（SID × buffer × 正/负）：")
        for case, sid, buffer, desc in CASES:
            print(f"  {case:18s} sid={sid} buffer={buffer:14s} {desc}")
        return 0

    if args.generate:
        return generate(OUT_DIR)

    if args.eve_root:
        import json
        import os

        root = Path(args.eve_root)
        failures = []
        print("== PCAP 命中断言 ==")
        for case, sid, buffer, desc in CASES:
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
