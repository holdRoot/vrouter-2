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
 * Packet Structure
 * ------------------------------------------------------------------------- *
 */
struct virtio_net_ll;
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
#define PKTMBUF_PRIV_SZ     (sizeof (struct packet))
#define PACKET_PRIV(MBUF)   (struct packet*)((uint8_t*)(MBUF) + sizeof(struct rte_mbuf))
#define ETHER_HEADER(X)     rte_pktmbuf_mtod((X), struct ether_hdr*)
#define IPV4_HEADER(X)      rte_pktmbuf_mtod_offset((X), struct ipv4_hdr*, sizeof(struct ether_hdr))

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

extern struct rte_mempool *pktmbuf_pool[];

/* ------------------------------------------------------------------------- *
 * APIs
 * ------------------------------------------------------------------------- *
 */
int dpdk_init(void);

unsigned GetCoreCount(void);

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
