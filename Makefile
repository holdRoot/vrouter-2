CC := gcc

DPDK_CFLAGS := -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2 -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX,RTE_CPUFLAG_RDRAND,RTE_CPUFLAG_FSGSBASE,RTE_CPUFLAG_F16C,RTE_CPUFLAG_AVX2 -DDPDK
DPDK_CFLAGS += -I$(RTE_SDK)/x86_64-native-linuxapp-gcc/include -include $(RTE_SDK)/x86_64-native-linuxapp-gcc/include/rte_config.h
DPDK_CFLAGS += -ggdb -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -fPIC
 
OBJS := dpdk.o mtrie.o

all: libdpdk.so

%.o: %.c
	@$(CC) -Wp,-MD,./.$@.o.d.tmp $(DPDK_CFLAGS) -c -o $@ $<
	@echo "Building $<"

libdpdk.so: $(OBJS)
	@$(CC) -fPIC -shared -o libdpdk.so $(OBJS)
	@echo "Building $<"

test:
	@$(CC) -L/home/user/dpdk_install/share/dpdk/x86_64-native-linuxapp-gcc/lib $(OBJS) -o test -Wl,--no-as-needed -Wl,-export-dynamic -L/home/user/workspace/vrouter/build/lib -L/home/user/dpdk_install/share/dpdk//x86_64-native-linuxapp-gcc/lib  -L/home/user/dpdk_install/share/dpdk//x86_64-native-linuxapp -gcc/lib -Wl,--whole-archive -Wl,-lrte_distributor -Wl,-lrte_reorder -Wl,-lrte_kni -Wl,-lrte_pipeline -Wl,-lrte_table -Wl,-lrte_port -Wl,-lrte_timer -Wl,-lrte_hash -Wl,-lrte_jobstats -Wl,-lrte_lpm -Wl,-lrte_power -Wl,-lrte_acl -Wl,-lrte_meter -Wl,-lrte_sched -Wl,-lm -Wl,-lrt -Wl,-lrte_vhost -Wl,--start-group -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_mbuf_offload -Wl,-lrte_ip_frag -Wl,-lethdev -Wl,-lrte_cryptodev -Wl,-lrte_mempool -Wl,-lrte_ring -Wl,-lrte_eal -Wl,-lrte_cmdline -Wl,-lrte_cfgfile -Wl,-lrte_pmd_bond -Wl,-lrte_pmd_vmxnet3_uio -Wl,-lrte_pmd_virtio -Wl,-lrte_pmd_cxgbe -Wl,-lrte_pmd_enic -Wl,-lrte_pmd_i40e -Wl,-lrte_pmd_fm10k -Wl,-lrte_pmd_ixgbe -Wl,-lrte_pmd_e1000 -Wl,-lrte_pmd_ring -Wl,-lrte_pmd_af_packet -Wl,-lrte_pmd_null -Wl,-lrt -Wl,-lm -Wl,-ldl -Wl,--end-group -Wl,--no-whole-archive -Wl,-lpthread
	@echo "Building $@"

clean:
	rm -fr dpdk.o test build *.so *.o* .o.*
 
#ifeq ($(RTE_SDK),)
#$(error "Please define RTE_SDK environment variable")
#endif
#
## Default target, can be overriden by command line or environment
#RTE_TARGET ?= x86_64-native-linuxapp-gcc
#
#include $(RTE_SDK)/mk/rte.vars.mk
#
## binary name
#APP = vrouter
#
## all source are stored in SRCS-y
#SRCS-y := dpdk.c
#
#CFLAGS += -ggdb
#CFLAGS += $(WERROR_FLAGS)
#
#include $(RTE_SDK)/mk/rte.extapp.mk

