# xbits-suricata 镜像
#
# 基于官方系 Suricata 8.0.8 镜像（jasonish/suricata，OISF 维护者发布），
# 额外安装：
#   - xbits Suricata 薄 hook 插件（/opt/xbits/plugins/xbits-suricata-hook.so）
#   - 规则检测目录（/opt/xbits/rules）
#   - xbits 测试配置（/opt/xbits/suricata-test.yaml）
#
# 构建前先由 CI/本地用 Suricata 8.0.8 源码头文件编译：
#   make -C xbits/suricata-plugin SURICATA_SRC=/tmp/suricata-8.0.8
# 然后：
#   docker build -t xbits-suricata -f docker/xbits-suricata.Dockerfile .

# ============================================================
# Stage 1: 在与运行时镜像相同发行版（Fedora/dnf）内部编译带
# xbits match-context 补丁的 Suricata 8.0.8。
#
# 根因：jasonish/suricata:8.0.8 基于 Fedora，libpcap 为
# libpcap.so.1；若把 Ubuntu runner 编译的 suricata 二进制拷进来，
# 会因 libpcap.so.0.8 缺失而无法启动。必须在相同发行版内编译，
# 禁止跨发行版搬运二进制这种兜底做法。
# ============================================================
FROM jasonish/suricata:8.0.8 AS suricata-builder

USER root

ARG SURICATA_VERSION=8.0.8

RUN dnf -y install \
      autoconf automake gcc gcc-c++ make libtool pkgconf-pkg-config \
      cbindgen rust cargo \
      libpcap-devel jansson-devel libyaml-devel pcre2-devel \
      libnet-devel libcap-ng-devel file-devel lz4-devel \
      zlib-devel libnfnetlink-devel libevent-devel \
      hyperscan-devel 2>/dev/null \
    || dnf -y install \
      autoconf automake gcc gcc-c++ make libtool pkgconf-pkg-config \
      cbindgen rust cargo \
      libpcap-devel jansson-devel libyaml-devel pcre2-devel \
      libnet-devel libcap-ng-devel file-devel lz4-devel \
      zlib-devel libnfnetlink-devel libevent-devel

# 下载源码、打 xbits 核心补丁、编译安装到 /usr/local
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
# Stage 2: 运行时镜像，使用同发行版编译出的 patched suricata
# ============================================================
FROM jasonish/suricata:8.0.8

USER root
RUN mkdir -p /opt/xbits/plugins /opt/xbits/rules

# 用同发行版编译的 patched Suricata 二进制与库替换官方版本
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

# 官方镜像通常自带 suricata 入口；测试显式 --entrypoint suricata
