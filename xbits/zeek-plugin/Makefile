# xbits Zeek thin hook plugin
#
# 依赖：Zeek 9.0.1（zeek-config 在 PATH、C++17 编译器）
# 构建：
#   make
# 产物：lib/xbits_hook.linux-x86_64.so
#
# 使用：
#   ZEEK_PLUGIN_PATH=$PWD/xbits/zeek-plugin \
#   ZEEK_PLUGIN_ACTIVATE=Xbits::Hook \
#   zeek -Cr trace.pcap ...
# 环境变量 XBITS_HOOK_SOCKET 可覆盖默认 /var/run/xbits/hook.sock
#
CXX ?= c++
CXXFLAGS ?= -O2 -fPIC -std=c++17 -Wall -Wextra
CXXFLAGS += $(shell zeek-config --include-dir 2>/dev/null)
LDFLAGS += -shared $(shell zeek-config --libs 2>/dev/null)

ARCH ?= linux-x86_64
TARGET := lib/xbits_hook.$(ARCH).so

all: $(TARGET)

$(TARGET): src/xbits_hook.cc
	mkdir -p lib
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
