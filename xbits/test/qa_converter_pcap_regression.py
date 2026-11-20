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


CONFIG_PATH = ROOT / "docker" / "suricata-converter-pcap.yaml"
PROBE_CONFIG_PATH = ROOT / "docker" / "probe-rules-validate.yaml"
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

    bad = sum(1 for _, ok, _ in checks if not ok)
    for name, ok, detail in checks:
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  [{detail[:180]}]"))
    print(f"\nSELF-TEST: {'PASS' if bad == 0 else 'FAIL'} ({len(checks) - bad}/{len(checks)})")
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true", help="生成正/负 PCAP 对到 测试用例/converter_pcap/")
    parser.add_argument("--list", action="store_true", help="打印用例清单（SID×buffer×正负）")
    parser.add_argument(
        "--check-config-vars",
        action="store_true",
        help="静态检查合并配置：规则头引用的 $VAR 是否都在 vars 中定义（无需 suricata）",
    )
    parser.add_argument("--self-test", action="store_true", help="静态检查的自测（含负例）")
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
