# xbits-suricata 镜像
#
# 关键约束：Suricata 薄 hook 插件调用核心补丁导出符号
# XbitsRegisterMatchContextExporter，因此镜像内的 suricata 必须是
# 打了 xbits 核心补丁的 8.0.8。
#
# 根因修复：原实现把 Ubuntu runner 编译的 suricata 二进制拷进
# Fedora/dnf 系 jasonish 镜像，因 libpcap.so.0.8 vs .so.1 ABI 不匹配
# 无法启动。现改为运行时镜像使用 Ubuntu 22.04 —— 与 CI runner 同发行版，
# 二进制与动态库 ABI 一致，无需跨发行版适配。
#
# 构建前由 CI 用打了补丁的 Suricata 8.0.8 源码编译并 stage：
#   cp /usr/local/bin/suricata docker/stage/bin/suricata
#   cp /usr/local/lib/libsuricata* docker/stage/lib/
# 然后（仓库根目录）：
#   docker build -t xbits-suricata -f docker/xbits-suricata.Dockerfile .

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 与 runner 上 patched Suricata 链接的动态库对应的运行库
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcap-ng0 libjansson4 libmagic1 libnet1 libpcap0.8 \
      libpcre2-8-0 libyaml-0-2 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/xbits/plugins /opt/xbits/rules /opt/xbits/filestore /var/log/suricata /var/run/suricata /var/lib/suricata

# 用 CI runner（同为 Ubuntu 22.04）编译的 patched Suricata 二进制与库
COPY docker/stage/bin/suricata /usr/bin/suricata
COPY docker/stage/lib/ /usr/local/lib/
RUN ldconfig && suricata --build-info | head -5

# 由 CI/本地预先编译好的 Suricata 薄 hook 插件
COPY xbits/suricata-plugin/xbits-suricata-hook.so /opt/xbits/plugins/

# 规则检测：suricata/ 为 Suricata 规则+Lua，xbits/ 为中央引擎分析规则与元数据
COPY 规则检测/suricata/ /opt/xbits/rules/suricata/
COPY 规则检测/xbits/ /opt/xbits/analysis-rules/
# 规则用裸文件名 lua:xxx.lua 引用，Suricata 相对 default-rule-path 解析。
# 不同配置使用不同 rule-path（规则根、Web漏洞利用、qa），把所有分类下的
# lua 文件扁平化到每一个可能被用作 default-rule-path 的目录。
# 先集中到临时目录，避免 find 遍历写入目标目录导致同文件覆盖。
RUN mkdir -p /tmp/xbits-lua \
    && find /opt/xbits/rules/suricata -type f -name '*.lua' -exec cp -a {} /tmp/xbits-lua/ \; \
    && cp -a /tmp/xbits-lua/. /opt/xbits/rules/suricata/ \
    && mkdir -p /opt/xbits/rules/suricata/Web漏洞利用 \
    && cp -a /tmp/xbits-lua/. /opt/xbits/rules/suricata/Web漏洞利用/ \
    && rm -rf /tmp/xbits-lua
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
