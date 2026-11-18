# xbits-suricata 镜像
#
# 关键约束：Suricata 薄 hook 插件调用核心补丁导出符号
# XbitsRegisterMatchContextExporter，因此镜像内的 suricata 必须是
# 打了 xbits 核心补丁的 8.0.8。
#
# 根因修复：原实现把 Ubuntu runner 编译的 suricata 二进制拷进
# Fedora/dnf 系 jasonish 镜像，因 libpcap.so.0.8 vs .so.1 ABI 不匹配
# 无法启动。现改为全程以 Ubuntu 22.04 为基座，在与 CI runner 完全
# 相同的发行版环境内编译 patched Suricata，禁止跨发行版搬运二进制。
#
# 构建（在仓库根目录）：
#   docker build -t xbits-suricata -f docker/xbits-suricata.Dockerfile .

# ============================================================
# Stage 1: 在 Ubuntu 22.04 内编译带 xbits 核心补丁的 Suricata 8.0.8
# ============================================================
FROM ubuntu:22.04 AS suricata-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      autoconf automake build-essential libtool pkg-config \
      libcap-ng-dev libjansson-dev libmagic-dev libnet1-dev \
      libpcap-dev libpcre2-dev libyaml-dev zlib1g-dev \
      curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

# Rust 1.85 + cbindgen 0.27（与 CI runner 一致，Suricata 8 构建需要）
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain 1.85.0 \
    && cargo install cbindgen --version 0.27.0 --locked

ARG SURICATA_VERSION=8.0.8

COPY xbits/suricata-plugin/apply_match_context_patch.py /tmp/apply_match_context_patch.py
RUN set -euxo pipefail; \
    curl -fsSL \
      "https://github.com/OISF/suricata/archive/refs/tags/suricata-${SURICATA_VERSION}.tar.gz" \
      -o /tmp/suricata.tar.gz; \
    mkdir -p /tmp/suricata-src; \
    tar -xzf /tmp/suricata.tar.gz -C /tmp/suricata-src --strip-components=1; \
    python3 /tmp/apply_match_context_patch.py /tmp/suricata-src; \
    cd /tmp/suricata-src; \
    ./autogen.sh; \
    ./configure --prefix=/usr/local; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig

# ============================================================
# Stage 2: 运行时镜像（同为 Ubuntu 22.04，ABI 一致）
# ============================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcap-ng0 libjansson4 libmagic1 libnet1 libpcap0.8 \
      libpcre2-8-0 libyaml-0-2 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/xbits/plugins /opt/xbits/rules /var/log/suricata /var/run/suricata /var/lib/suricata

# 用同发行版编译的 patched Suricata 二进制与库
COPY --from=suricata-builder /usr/local/bin/suricata /usr/bin/suricata
COPY --from=suricata-builder /usr/local/lib/ /usr/local/lib/
RUN ldconfig && suricata --build-info | head -5

# 由 CI/本地预先编译好的 Suricata 薄 hook 插件
COPY xbits/suricata-plugin/xbits-suricata-hook.so /opt/xbits/plugins/

# 规则检测：suricata/ 为 Suricata 规则+Lua，xbits/ 为中央引擎分析规则与元数据
COPY 规则检测/suricata/ /opt/xbits/rules/suricata/
COPY 规则检测/xbits/ /opt/xbits/analysis-rules/
# Suricata Lua 规则用相对 rule-path 的 lua:xxx.lua 加载，把 lua 文件放到规则目录同级
COPY 规则检测/suricata/Web漏洞利用/lua/ /opt/xbits/rules/suricata/Web漏洞利用/
# 全规则 QA：只扁平化 4 个自研场景规则（转换来的分类规则不参与矩阵）
RUN mkdir -p /opt/xbits/rules/qa /tmp/suri-out \
    && for d in "DNS隧道与带外检测" "Web漏洞利用" "侦察与攻击工具指纹" "后门通信"; do \
         cp /opt/xbits/rules/suricata/"$d"/*.rules /opt/xbits/rules/qa/; \
         cp /opt/xbits/rules/suricata/"$d"/lua/*.lua /opt/xbits/rules/qa/; \
       done \
    && cp /opt/xbits/rules/suricata/DNS隧道与带外检测/dns_tunnel_allow.lst /opt/xbits/rules/qa/
COPY 测试用例/classification.config 测试用例/reference.config /opt/xbits/rules/
COPY docker/suricata-test.yaml docker/suricata-qa.yaml docker/suricata-qa-eve.yaml docker/probe-rules-validate.yaml docker/probe-rules-production.yaml docker/probe-rules-weak.yaml /opt/xbits/

# 运行测试时可通过 -e XBITS_HOOK_SOCKET=... 覆盖
ENV XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock

# 测试显式 --entrypoint suricata 运行
