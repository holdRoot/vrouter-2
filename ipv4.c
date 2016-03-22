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
#include "mtrie.h"
#include "vif.h"
#include "virtio.h"
#include "virtio_rxtx.h"
#include "ipv4.h"

/* --------------- SOCKET ----------------------------- */
static int send_all(int socket, void *buffer, size_t length)
{
    char *ptr = (char*) buffer;

    while (length > 0)
    {
        int i = send(socket, ptr, length, 0);
        if (i < 1) return -1;
        ptr += i;
        length -= i;
    }

    return 1;
}

// passes broadcast packets to the proxy packet server for processing.
// Gets the reply from the server and relay the packet to the VM back.
static int relay_packet_to_ppserver(struct packet* pkt)
{
    struct sockaddr_un addr;
    uint32_t temp;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/var/run/vrouter/packet-proxy.socket", sizeof(addr.sun_path)-1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        return -1;
    }

    temp = htonl(pkt->len);
    if (send_all(sock, (void *)&temp, sizeof(temp)) < 0) {
        return -1;
    }

    temp = htonl(pkt->lldev->vif->label);
    if (send_all(sock, (void *)&temp, sizeof(temp)) < 0) {
        return -1;
    }

    if (send_all(sock, (void *)pkt->data, pkt->len) < 0) {
        return -1;
    }

    if (recv(sock, &temp, sizeof(uint32_t), MSG_WAITALL) <= 0) {
        perror("recv1");
        return -1;
    }

    if (temp == 0)
        return -1;

    temp = ntohl(temp);
    printf("Temp: %d\n", temp);

    if (recv(sock, (void *)pkt->data, temp,  MSG_WAITALL) <= 0) {
        perror("recv2");
        return -1;
    }

    close(sock);

    return temp;
}

/* ------------------------------------------------------------------------- *
 * ipv4_route
 * ------------------------------------------------------------------------- *
 */
static mtrie_t *ipv4_route_table;
static struct nexthop bcast_nh;

// Handle BROADCAST packets (ARP, DHCP, etc)
int bcast_pkt_handler(CC_UNUSED void* data, struct packet* pkt)
{
    int pkt_size = relay_packet_to_ppserver(pkt);

    if (pkt_size <= 0) {
        rte_pktmbuf_free(pkt->mbuf);
        log_crit("Invalid response got from pp server\n");
        return -1;
    }

    pkt->mbuf->pkt_len = pkt_size;
    pkt->mbuf->data_len = pkt_size;
    virtio_tx_packet(data, pkt);

    return 0;
}

// Called by go code
int ipv4_route_init(uint32_t nb_entries)
{
    uint32_t i;
    uint32_t bcast_ip = IPv4(0xff, 0xff, 0xff, 0xff);
    ipv4_route_table = (mtrie_t*) malloc (sizeof(mtrie_t) * nb_entries);
    if (!ipv4_route_table)
        return -EAGAIN;

    bcast_nh.data = NULL;
    bcast_nh.fn = bcast_pkt_handler;

    for (i = 0; i < nb_entries; i++) {
        mtrie_init(&ipv4_route_table[i], 3);
        ipv4_route_add(i, (uint8_t*)&bcast_ip, &bcast_nh);
    }

    return 0;
}

// Called by go code
int ipv4_route_add(uint32_t label, uint8_t* ip, struct nexthop* nh)
{
    return mtrie_add_entry(&ipv4_route_table[label], ip, 32, nh);
}

// Called by go code
int ipv4_route_del(uint32_t label, uint8_t* ip)
{
    return mtrie_del_entry(&ipv4_route_table[label], ip, 32);
}

// Called from data path
void* ipv4_lookup(uint32_t label, uint8_t* ip)
{
    return mtrie_lookup(&ipv4_route_table[label], ip, 32);
}

