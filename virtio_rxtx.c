/* DPDK file */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sched.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <poll.h>
#include <unistd.h>

#include "dpdk.h"
#include "vif.h"
#include "virtio.h"
#include "virtio_rxtx.h"
#include "ipv4.h"

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */
int virtio_tx_packet(CC_UNUSED void* data, struct packet* pkt)
{
    struct vif* vif = (struct vif*)data;
    int q_no = VIRTIO_RXQ; // TODO: Fixme for RSS.

    if (!pkt->mbuf)
        rte_panic("Invalid packet received\n");

    if (!data && !pkt->lldev)
        rte_panic("Invalid packet state\n");

    if ( unlikely((data == NULL) && (pkt->lldev->vif != NULL)) ) {
        vif = pkt->lldev->vif;
    }

    if (rte_vhost_enqueue_burst(vif->lldev->dev, q_no, &pkt->mbuf, 1) == 1) {
        rte_atomic64_inc(&vif->rx_packets);
        rte_atomic64_inc(&vif->lldev->queue[q_no].rx_packets);
    }
    else {
        rte_atomic64_inc(&vif->dropped_packets);
        rte_atomic64_inc(&vif->lldev->queue[q_no].dropped_packets);
    }

    rte_pktmbuf_free(pkt->mbuf);
    return 0;
}

// Virtio rx event handler
void* virtio_rx_packet(void* arg)
{
    struct virtqueue* queue = (struct virtqueue*)arg;
    struct rte_mempool* pool =
                pktmbuf_pool[rte_lcore_to_socket_id(queue->lcore_id)];
    int q_no = queue->q_no * VIRTIO_QNUM + VIRTIO_TXQ;
    struct rte_mbuf *rpkts[VIRTIO_RX_BURST];
    struct pollfd fds[2];
    unsigned count;
    cpu_set_t cpusets;
    eventfd_t temp;

    CPU_ZERO(&cpusets);
    CPU_SET(queue->lcore_id, &cpusets);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpusets), &cpusets)
        != 0) {
        log_crit("Failed to set CPU affinity for device:queue %ld:%d\n",
            queue->lldev->dev->device_fh, queue->q_no);
    }

    fds[0].fd = queue->kickfd;
    fds[0].events = POLLIN | POLLERR;
    fds[1].fd = queue->notifyfd;
    fds[1].events = POLLIN | POLLERR;

    while (1) {
        int ret = poll(fds, 2, -1);
        if ( likely(ret >= 1) ) {
            if (fds[1].revents & POLLIN) {
                fds[1].revents = 0;
                eventfd_read(queue->notifyfd, &temp);
                pthread_testcancel();
                break;
            }
            if (fds[0].revents & POLLIN) {
                fds[0].revents = 0;
                eventfd_read(queue->kickfd, &temp);
                count = rte_vhost_dequeue_burst(queue->lldev->dev,
                                                q_no,
                                                pool,
                                                rpkts,
                                                VIRTIO_RX_BURST);
                if (likely(count > 0)) {
                    unsigned i;

                    for (i = 0; likely(i < count); i++) {
                        struct packet* pkt = cast_packet(rpkts[i], queue->lldev,
                            queue->lcore_id, queue->q_no);
                        struct nexthop* nh;

                        if ( likely(pkt->ip_hdr != NULL) ) { //IPv4?
                            nh = ipv4_lookup(queue->lldev->vif->label,
                                            (uint8_t*)&pkt->ip_hdr->dst_addr);
                            if (likely(nh != NULL)) {
                                pkt->nh = nh;
                                (*nh->fn)(nh->data, pkt);
                            }
                            else {
                                uint8_t* ip =(uint8_t*)(&pkt->ip_hdr->dst_addr);
                                printf("Error: No route to %d.%d.%d.%d found\n",
                                        ip[0], ip[1], ip[2], ip[3]);
                                rte_pktmbuf_free(rpkts[i]);
                            }
                        }
                        else if (ntohs(pkt->ether_hdr->ether_type) == 0x0806) {
                            bcast_pkt_handler(queue->lldev->vif, pkt);
                        }
                        else {
                            rte_pktmbuf_free(rpkts[i]);
                        }
                    }
                }
            }
        }
    }

    pthread_exit(NULL);
    return NULL;
}

