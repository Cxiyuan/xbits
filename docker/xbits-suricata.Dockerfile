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

# 规则检测与必要配置
COPY 规则检测/ /opt/xbits/rules/
# Suricata Lua 规则用相对 rule-path 的 lua:xxx.lua 加载，把 lua 文件放到规则目录同级
COPY 规则检测/Web漏洞利用/lua/ /opt/xbits/rules/Web漏洞利用/
COPY 测试用例/classification.config 测试用例/reference.config /opt/xbits/rules/
COPY docker/suricata-test.yaml /opt/xbits/suricata-test.yaml

# 运行测试时可通过 -e XBITS_HOOK_SOCKET=... 覆盖
ENV XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock

# 官方镜像通常自带 suricata 入口；测试显式 --entrypoint suricata
