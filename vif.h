#pragma once

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
    uint8_t cpusets[32];
    uint32_t cpus;
    char name[32];
    uint8_t ip[4];
    uint8_t macaddr[6];
    uint32_t mask;
    uint32_t label;
    char path[512];
    rte_atomic64_t error_packets;
    rte_atomic64_t dropped_packets;
    rte_atomic64_t rx_packets;
    rte_atomic64_t tx_packets;
    struct nexthop nh;
};

struct vif* vif_add(char* name, uint8_t* ip, uint32_t mask, uint8_t* macaddr,
	uint32_t label, char* path, uint32_t cpus, int cpusets[]);

void vif_del(struct vif* vif);

int vif_init(int nb_lcores);

void vif_exit(void);

struct vif* vif_find_entry(char *path);
