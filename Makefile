ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk


APP = vrouter.exe

# all source are stored in SRCS-y
SRCS-y := dpdk.c virtio.c virtio_rxtx.c ipv4.c mtrie.c vif.c

USER_FLAGS := -I/usr/include/python2.7

CFLAGS += -ggdb $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)

LDLIBS := -lpython2.7

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk
