
# binary name
APP = dpdkcap

# all source (prefix gets added later)
SRC_DIR = src
#SOURCES := dpdkcap.c core_write.c core_capture.c statistics_ncurses.c pcap.c utils.c lzo/minilzo/minilzo.c lzo/lzowrite.c
SOURCES := dpdkcap.c core_write.c core_capture.c statistics.c timestamp.c numa.c tasks.c parse.c pcap.c utils.c lzo/minilzo/minilzo.c lzo/lzowrite.c

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

SRCS-y += $(addprefix $(SRC_DIR)/, $(SOURCES))

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

LDFLAGS_SHARED += $(shell $(PKGCONF) --libs ncurses)
LDFLAGS_STATIC += $(shell $(PKGCONF) --static --libs ncurses)

LDFLAGS_SHARED += $(shell $(PKGCONF) --libs libpcap)
LDFLAGS_STATIC += $(shell $(PKGCONF) --static --libs libpcap)

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true

