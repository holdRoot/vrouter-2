#pragma once

#define VIRTIO_RX_BURST         (32u)

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */
struct virtio_net_ll;

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
    pthread_t txq_thread;
    struct virtio_net_ll* lldev;
    int q_no;
    int notifyfd;
    int pcore_id;
};

/* Linked-list */
struct virtio_net_ll {
    struct virtio_net_ll* next;
    struct virtio_net* dev;
    int nb_queues;
    struct virtqueue* queue;
    struct vif* vif;
};

int virtio_init(void);

void virtio_exit(void);
