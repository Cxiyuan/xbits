# xbits Suricata thin hook plugin
#
# 依赖：已安装 Suricata 8.0.8（libsuricata-config 在 PATH 中）
# 用法：
#   make
#   sudo cp xbits-suricata-hook.so /usr/lib/suricata/plugins/
#   # suricata.yaml:
#   # plugins:
#   #   - /usr/lib/suricata/plugins/xbits-suricata-hook.so
#
CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra
LDFLAGS ?=
SURICATA_SRC ?=

ifneq ($(SURICATA_SRC),)
CFLAGS += -I$(SURICATA_SRC)/src -I$(SURICATA_SRC)/rust -I$(SURICATA_SRC)
LDFLAGS += -shared
else
CFLAGS += $(shell libsuricata-config --cflags 2>/dev/null)
LDFLAGS += -shared $(shell libsuricata-config --libs 2>/dev/null)
endif

TARGET := xbits-suricata-hook.so
SRC := xbits-suricata-hook.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
