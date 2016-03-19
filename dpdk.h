#pragma once

#define _GNU_SOURCE
#include <sched.h>

/* DPDK Include files */
#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ring.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_virtio_net.h>
#include <rte_errno.h>
#include <rte_interrupts.h>

/* ------------------------------------------------------------------------- *
 * Configurable area
 * ------------------------------------------------------------------------- *
 */
/* Passed as argument to -m command */
#define HUGEPAGE_MEMORY_SZ      "128"

/* Whitelisted PCI device */
#define PCI_DEVICE_BDF          "00:03.0"

/* Maximum number of packets in a burst */
#define MAX_PKT_BURST (32u)

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
#define MALLOC(T)               (T*) malloc(sizeof(T))
#define MALLOCN(T,N)            (T*) malloc(sizeof(T) * (N))

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
    rte_atomic64_t error_packets;
    rte_atomic64_t dropped_packets;
    rte_atomic64_t rx_packets;
    rte_atomic64_t tx_packets;
    uint32_t entry_read; /* Temporary area used by mac learning code */
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    rte_atomic32_t taxi_count;
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
 * Packet Structure
 * ------------------------------------------------------------------------- *
 */
struct packet {
    struct virtio_net_ll* lldev;
    uint16_t lcore_id;
    uint16_t q_no;
    struct rte_mbuf* mbuf;
    struct ipv4_hdr* ip_hdr;
    struct ether_hdr* ether_hdr;
    uint8_t* data;
    struct nexthop* nh;
    uint16_t len;
};

#define DEFAULT_PACKET_SZ   (2048)
#define PACKET_PRIV(MBUF)    (struct packet*)(rte_pktmbuf_mtod(MBUF, uint8_t*) + 2048)
#define ETHER_HEADER(X)  rte_pktmbuf_mtod((X), struct ether_hdr*)
#define IPV4_HEADER(X)   rte_pktmbuf_mtod_offset((X), struct ipv4_hdr*, sizeof(struct ether_hdr))

static inline struct packet* cast_packet(struct rte_mbuf* mbuf, void* lldev, uint16_t lcore_id, int q_no)
{
    struct packet* packet = PACKET_PRIV(mbuf);

    packet->data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    packet->lldev = (struct virtio_net_ll*)lldev;
    packet->mbuf = mbuf;
    packet->lcore_id = lcore_id;
    packet->q_no = q_no;
    packet->lcore_id = lcore_id;
    packet->ether_hdr = (struct ether_hdr*)packet->data;
    packet->len = mbuf->pkt_len;
    if ( likely(ntohs(packet->ether_hdr->ether_type) == 0x800))
        packet->ip_hdr = (struct ipv4_hdr*)&packet->data[sizeof(struct ether_hdr)];
    else
        packet->ip_hdr = NULL;
    return packet;
}

/* ------------------------------------------------------------------------- *
 * VIF structures
 * ------------------------------------------------------------------------- *
 */
struct nexthop {
    void* data;
    int (*fn)(void* data, struct packet* pkt); 
};

struct vif {
    struct virtio_net_ll* lldev;
    cpu_set_t cpusets[32];
    int cpus;
    char name[32];
    uint8_t ip[4];
    uint8_t macaddr[6];
    uint8_t mask;
    uint32_t label;
    char path[512];
    rte_atomic64_t error_packets;
    rte_atomic64_t dropped_packets;
    rte_atomic64_t rx_packets;
    rte_atomic64_t tx_packets;
    struct nexthop nh;
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

void* ipv4_lookup(uint32_t label, uint8_t* ip);

int dhcp_build_reply(uint8_t* pkt);

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

