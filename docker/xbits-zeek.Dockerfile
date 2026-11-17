# xbits-zeek 镜像
#
# 基于官方 Zeek 9.0.1 镜像，额外安装：
#   - xbits Zeek 薄 hook 动态插件（/opt/xbits/zeek-plugin）
#   - app-id（Zeek 应用识别脚本/签名，/opt/xbits/app-id）
#
# 构建（在仓库根目录）：
#   docker build -t xbits-zeek -f docker/xbits-zeek.Dockerfile .

FROM zeek/zeek:9.0.1 AS plugin-builder
USER root
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*
COPY xbits/zeek-plugin /src/xbits/zeek-plugin
RUN make -C /src/xbits/zeek-plugin

FROM zeek/zeek:9.0.1

USER root
RUN mkdir -p /opt/xbits

# Zeek 薄 hook 动态插件目录（__zeek_plugin__ + lib/*.so）
COPY --from=plugin-builder /src/xbits/zeek-plugin /opt/xbits/zeek-plugin

# app-id 应用识别库
COPY app-id/ /opt/xbits/app-id/

ENV ZEEK_PLUGIN_PATH=/opt/xbits/zeek-plugin
ENV ZEEK_PLUGIN_ACTIVATE=Xbits::Hook
ENV XBITS_HOOK_SOCKET=/var/run/xbits/hook.sock

# 官方镜像入口为 zeek；测试显式 --entrypoint /usr/local/zeek/bin/zeek
