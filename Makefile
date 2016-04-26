ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP=dpdkcap

# all source are stored in SRCS-y
SRCS-y := dpdkcap.c core_write.c core_capture.c statistics_ncurses.c pcap.c utils.c lzo/minilzo/minilzo.c lzo/lzowrite.c

CFLAGS += $(WERROR_FLAGS)
LDFLAGS += -lncurses

ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

EXTRA_CFLAGS += -O3 -g -Wfatal-errors

include $(RTE_SDK)/mk/rte.extapp.mk
