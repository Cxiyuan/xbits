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

FROM jasonish/suricata:8.0.8

USER root
RUN mkdir -p /opt/xbits/plugins /opt/xbits/rules

# 由 CI/本地预先编译好的 Suricata 薄 hook 插件
COPY xbits/suricata-plugin/xbits-suricata-hook.so /opt/xbits/plugins/
# 使用打了 xbits match-context 补丁的 Suricata 8.0.8 二进制
COPY docker/stage/bin/suricata /usr/bin/suricata
COPY docker/stage/lib/ /usr/local/lib/
RUN ldconfig

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
