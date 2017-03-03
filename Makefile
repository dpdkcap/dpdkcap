ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP=dpdkcap

# all source are stored in SRCS-y
SRC_DIR= src
SOURCES= dpdkcap.c core_write.c core_capture.c statistics_ncurses.c pcap.c utils.c lzo/minilzo/minilzo.c lzo/lzowrite.c

SRCS-y += $(addprefix $(SRC_DIR)/, $(SOURCES))

CFLAGS += -O3 -g $(WERROR_FLAGS) -Wfatal-errors -std=c99 -U__STRICT_ANSI__
LDLIBS += -lncurses

include $(RTE_SDK)/mk/rte.extapp.mk
