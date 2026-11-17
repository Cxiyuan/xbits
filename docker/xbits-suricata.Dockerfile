# xbits-suricata 镜像
#
# 基于官方 Suricata 8.0.8 镜像，额外安装：
#   - xbits Suricata 薄 hook 插件（/opt/xbits/plugins/xbits-suricata-hook.so）
#   - 规则检测目录（/opt/xbits/rules）
#   - xbits 测试配置（/opt/xbits/suricata-test.yaml）
#
# 构建（在仓库根目录）：
#   docker build -t xbits-suricata -f docker/xbits-suricata.Dockerfile .

FROM debian:bookworm-slim AS plugin-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates tar \
    && rm -rf /var/lib/apt/lists/*
ARG SURICATA_VERSION=8.0.8
RUN curl -fsSL "https://github.com/OISF/suricata/archive/refs/tags/suricata-${SURICATA_VERSION}.tar.gz" \
      -o /tmp/suricata.tar.gz \
    && mkdir -p /tmp/suricata-src \
    && tar -xzf /tmp/suricata.tar.gz -C /tmp/suricata-src --strip-components=1
COPY xbits/suricata-plugin /src/xbits/suricata-plugin
RUN make -C /src/xbits/suricata-plugin SURICATA_SRC=/tmp/suricata-src

FROM oisf/suricata:8.0.8

USER root
RUN mkdir -p /opt/xbits/plugins /opt/xbits/rules

# Suricata 薄 hook 插件
COPY --from=plugin-builder /src/xbits/suricata-plugin/xbits-suricata-hook.so /opt/xbits/plugins/

# 规则检测与必要配置
COPY 规则检测/ /opt/xbits/rules/
COPY 测试用例/classification.config 测试用例/reference.config /opt/xbits/rules/
COPY docker/suricata-test.yaml /opt/xbits/suricata-test.yaml

# 运行测试时可通过 -e XBITS_HOOK_SOCKET=... 覆盖
ENV XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock

# 官方镜像通常自带 suricata 入口；测试显式 --entrypoint suricata
