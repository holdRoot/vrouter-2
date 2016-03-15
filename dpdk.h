#pragma once

#define _GNU_SOURCE
#include <sched.h>

#include <rte_common.h>
#include <rte_log.h>

/* ------------------------------------------------------------------------- *
 * Configurable area
 * ------------------------------------------------------------------------- *
 */
/* Passed as argument to -m command */
#define HUGEPAGE_MEMORY_SZ      "128"

/* Whitelisted PCI device */
#define PCI_DEVICE_BDF          "00:03.0"

/* ------------------------------------------------------------------------- *
 * Compiler directives
 * ------------------------------------------------------------------------- *
 */
#define CC_UNUSED   __attribute__((unused))
#define CC_PACKED   __attribute__((packed))

/* ------------------------------------------------------------------------- *
 * LOG Support
 * ------------------------------------------------------------------------- *
 */
#define LOG_CRIT				 RTE_LOG_CRIT
#define LOG_INFO				 RTE_LOG_INFO
#define log_info(FMT, args...) rte_log(LOG_INFO, RTE_LOGTYPE_USER1, FMT, ##args)
#define log_crit(FMT, args...) rte_log(LOG_CRIT, RTE_LOGTYPE_USER1, FMT, ##args)

/* ------------------------------------------------------------------------- *
 * Macros for code beautification
 * ------------------------------------------------------------------------- *
 */
#define MALLOC(T)               ((T)*) malloc(sizeof(T))
#define MALLOCN(T,N)            ((T)*) malloc(sizeof(T) * (N))

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */

/* VIRTIO Helper struct */
struct virtqueue {
    int callfd;
    int kickfd;
    struct vhost_virtqueue* txq;
    struct vhost_virtqueue* rxq;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t error_packets;
    uint32_t entry_read; /* Temporary area used by mac learning code */
};

/* State of the virtio dev */
enum virtio_state {
    VIRTIO_STATE_MAC_LEARNING,
    VIRTIO_STATE_READY
};

/* Linked-list */
struct virtio_net_ll {
    struct virtio_net_ll* next;
    struct virtio_net* dev;
    int nb_queues;
    struct virtqueue* queue;
    enum virtio_state state;
    struct vif* vif;
};

/* ------------------------------------------------------------------------- *
 * VIF structures
 * ------------------------------------------------------------------------- *
 */
struct vif {
    struct virtio_net_ll* dev;
    cpu_set_t cpusets[32];
    int cpus;
    char name[32];
    uint8_t ip[4];
    uint8_t macaddr[6];
    uint8_t mask;
    uint32_t label;
    char path[512];
    uint64_t dropped_packets;
    uint64_t rx_packets;
    uint64_t tx_packets;
};

struct nexthop {
    void* data;
    int (*fn)(void* data, void* pkt);
};

/* ------------------------------------------------------------------------- *
 * APIs
 * ------------------------------------------------------------------------- *
 */
int dpdk_init(void);

int event_handler_add(int core_id, int q_no, int slot, void* _vif, void* _lldev);

int event_handler_del(int core_id, int slot);

int engine_send_cmd(int lcore_id, void* buf);

struct vif* vif_add(char* name, uint8_t* ip, uint8_t mask, uint8_t* macaddr, uint32_t label, char* path, int cpus, int cpusets[]);

void vif_del(struct vif* vif);

unsigned GetCoreCount(void);

int ipv4_route_init(uint32_t nb_entries);

int ipv4_route_add(uint32_t label, uint8_t* ip, struct nexthop* nh);

int ipv4_route_del(uint32_t label, uint8_t* ip);
#ifdef DPDK
/* ------------------------------------------------------------------------- *
 * CGO Support
 * ------------------------------------------------------------------------- *
 */
typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef __complex float GoComplex64;
typedef __complex double GoComplex128;

typedef struct { char *p; GoInt n; } GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

extern GoInt GetFreeSlot(GoUint p0, void* p1);
extern void DeleteSlot(GoUint p0, GoInt p1);
extern void* VifFind(GoString p0, void* p1);

#endif

