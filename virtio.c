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

#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>

#include "dpdk.h"

#include "vif.h"
#include "virtio.h"
#include "virtio_rxtx.h"

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */
#if 0
#define VIRTIO_MAX_NB_BUF       (4096)
#define VIRTIO_MIN_NB_BUF       (1024)
#define VIRTIO_MBUF_SIZE        (DEFAULT_PACKET_SZ + sizeof(struct rte_mbuf) + \
                    sizeof(struct packet) + RTE_PKTMBUF_HEADROOM)
#define VIRTIO_MP_CACHE_SIZE    (RTE_MEMPOOL_CACHE_MAX_SIZE)
#endif
// Lock for linkedlist OPs
static pthread_mutex_t ll_virtio_net_lock;

// Root of virtio device linkedlist
static struct virtio_net_ll* ll_virtio_net_root;

// Vhost worker thread
static pthread_t vhost_thread;

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */
#define VIRTIO_RXQ_NO(X) ((X) * VIRTIO_QNUM + VIRTIO_RXQ)
#define VIRTIO_TXQ_NO(X) ((X) * VIRTIO_QNUM + VIRTIO_TXQ)

// Called when a VM starts a vhost-user device
static int new_device(struct virtio_net *dev)
{
    struct virtio_net_ll* lldev = (struct virtio_net_ll*)
                                        malloc( sizeof(struct virtio_net_ll) );
    int q_no;
    struct virtqueue* queue;
    struct vif* vif;
//    GoString str;

    if (!lldev) {
        log_crit("Failed to allocate memory for lldev\n");
        return -ENOMEM;
    }

    pthread_mutex_lock(&ll_virtio_net_lock);
    lldev->dev = dev;
    lldev->next = ll_virtio_net_root;
    ll_virtio_net_root = lldev;
    dev->priv = lldev;
    pthread_mutex_unlock(&ll_virtio_net_lock);

    lldev->nb_queues = dev->virt_qp_nb;
    lldev->queue = (struct virtqueue*)
            malloc(sizeof(struct virtqueue) * lldev->nb_queues * VIRTIO_QNUM);
    if (!lldev->queue) {
        log_crit("Failed to allocate memory for lldev's virtqueue\n");
        return -ENOMEM;
    }

#if 0
//    str.p = lldev->dev->ifname;
//    str.n = strlen(lldev->dev->ifname);
    vif = VifFind(str, lldev);
    if (!vif) {
        log_crit("Failed to get associated VIF for this device (%ld)\n",
                    lldev->dev->device_fh);
        free(lldev->queue);
        free(lldev);
        return -ENODEV;
    }
#endif
    vif = NULL;
    lldev->vif = vif;
    vif->lldev = lldev;

    for (q_no = 0; q_no < lldev->nb_queues; q_no++) {
        queue = &lldev->queue[q_no];
        queue->callfd = dev->virtqueue[VIRTIO_RXQ_NO(q_no)]->callfd;
        queue->kickfd = dev->virtqueue[VIRTIO_TXQ_NO(q_no)]->kickfd;
        queue->rxq = dev->virtqueue[VIRTIO_TXQ_NO(q_no)];
        queue->txq = dev->virtqueue[VIRTIO_RXQ_NO(q_no)];
        rte_atomic64_clear(&queue->rx_packets);
        rte_atomic64_clear(&queue->tx_packets);
        rte_atomic64_clear(&queue->dropped_packets);
        rte_atomic64_clear(&queue->error_packets);
        queue->q_no = q_no;
        queue->notifyfd = eventfd(0, 0);
        queue->lcore_id = (q_no % vif->cpus);
        queue->lldev = lldev;

        // For each TXQ (Guest to Host) Q create a thread
        if (pthread_create(&queue->txq_thread, NULL, virtio_rx_packet, queue)
                != 0) {
            log_crit("Failed to create thread for virtio txq (%ld, %d) \n",
                dev->device_fh, q_no);
            /* TODO: Cancel all created threads */
            free(lldev->queue);
            free(lldev);
            return -1;
        }
    }

    // Link up
    dev->flags |= VIRTIO_DEV_RUNNING;
    return 0;
}

// Called when a VM destroys a vhost-user device
static void destroy_device(volatile struct virtio_net* dev)
{
    struct virtio_net_ll *ll_node, *ll_prev;
    int q_no;

    dev->flags &= ~VIRTIO_DEV_RUNNING;

    pthread_mutex_lock(&ll_virtio_net_lock);
    for (ll_node = ll_virtio_net_root, ll_prev = NULL;
        ll_node != NULL;
        ll_prev = ll_node, ll_node = ll_node->next) {
        if (ll_node->dev == dev) {
            if (ll_prev == NULL) {
                ll_virtio_net_root = ll_node->next;
            }
            else {
                ll_prev->next = ll_node->next;
            }
            break;
        }
    }
    pthread_mutex_unlock(&ll_virtio_net_lock);

    // Cancel thread
    for (q_no = 0; q_no < ll_node->nb_queues; q_no++) {
        pthread_cancel(ll_node->queue[q_no].txq_thread);
        eventfd_write(ll_node->queue[q_no].notifyfd, (eventfd_t)1);
    }

    // Wait for threads to die
    for (q_no = 0; q_no < ll_node->nb_queues; q_no++) {
        pthread_join(ll_node->queue[q_no].txq_thread, NULL);
    }
}

static const struct virtio_net_device_ops virtio_ops = {
    .new_device = new_device,
    .destroy_device = destroy_device
};

/* rte_vhost_driver_session_start is a blocking call, thus we create another
 * thread and call it from there */
static void* vhost_worker(CC_UNUSED void* arg)
{
    pthread_detach(pthread_self());

    log_info("vhost_worker started\n");

    if (rte_vhost_driver_session_start() < 0) {
        log_crit( "rte_vhost_driver_register failed to start\n");
    }

    return NULL;
}

int virtio_init(void)
{
    // Initialize the lock for virtio net linked list
    pthread_mutex_init(&ll_virtio_net_lock, NULL);

    // Initialize virtio framework
    if (rte_vhost_driver_callback_register(&virtio_ops) < 0) {
        log_crit( "rte_vhost_driver_callback_register failed\n");
        return -1;
    }

    // Run vhost-user listener
    if (pthread_create(&vhost_thread, NULL, vhost_worker, NULL) < 0) {
        log_crit( "Failed to create cmd thread\n");
        return -1;
    }

    return 0;
}