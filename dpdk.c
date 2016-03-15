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
#include <rte_ring.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_virtio_net.h>
#include <rte_errno.h>
#include <rte_interrupts.h>

#include "dpdk.h"
#include "mtrie.h"

/* ------------------------------------------------------------------------- *
 * ETHERDEV Configuration
 * ------------------------------------------------------------------------- *
 */
/* Number of sockets in NUMA */
#define NB_SOCKETS  (8u)

/* Number of buffer descriptor for RX */
#define RTE_RX_DESC_DEFAULT (128u)

/* Number of buffer descriptor for TX */
#define RTE_TX_DESC_DEFAULT (512u)

/* Memory pool cache size */
#define MEMPOOL_CACHE_SIZE (256u)

/* Maximum number of packets in a burst */
#define MAX_PKT_BURST (32u)

/* Number of packets to prefetch when rx */
#define NB_PREFETCH_PACKETS (3)

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define NB_MBUF RTE_MAX	(								\
				(nb_queues * RTE_RX_DESC_DEFAULT +	\
				 nb_queues * MAX_PKT_BURST +			\
				 nb_queues * RTE_TX_DESC_DEFAULT +	\
				 nb_queues * MEMPOOL_CACHE_SIZE),		\
				(unsigned)8192)

#define RX_PTHRESH (8u) /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH (8u) /**< Default values of RX host threshold reg. */
#define RX_WTHRESH (4u) /**< Default values of RX write-back threshold reg. */
#define TX_PTHRESH (36u) /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH (0u)  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH (0u)  /**< Default values of TX write-back threshold reg. */

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},

	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},

	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},

    .intr_conf = {
        .rxq = 1,
    },
};


static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	.txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS |
			      ETH_TXQ_FLAGS_NOVLANOFFL |
			      ETH_TXQ_FLAGS_NOXSUMSCTP |
			      ETH_TXQ_FLAGS_NOXSUMUDP  |
			      ETH_TXQ_FLAGS_NOXSUMTCP)

};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
	.rx_free_thresh = 32,
};

/* ------------------------------------------------------------------------- *
 * Cmd and Packet event support
 * ------------------------------------------------------------------------- *
 */
// Add a new fd to fd list
#define ENGINE_CMD_FD_ADD       (1u)
// Del a fd from fd list
#define ENGINE_CMD_FD_DEL       (2u)

#define MAX_EVENTS      (64*1024)

// Reserved for cmd events
#define CMD_EVENT_SLOT  (0)

/* Event handler slots are allocated in GO code. */
struct event_handler {
    void* data;
    void (*fn)(uint16_t lcore_id, void *data);
};

struct engine_cmd_msg {
    int cmd;
    int fd;
    int slot;
    struct event_handler handler;
    int ret_code;
} __attribute__ ((packed));

struct cmd_event_info {
    uint16_t core_id;
    struct pollfd* fds;
    int* nb_fd;
    struct event_handler* event_handlers;
};

/* ------------------------------------------------------------------------- *
 * Forward declarations
 * ------------------------------------------------------------------------- *
 */
static int engine_loop(CC_UNUSED void* arg);

int engine_send_cmd(int lcore_id, void* buf);

/* ------------------------------------------------------------------------- *
 * Globals
 * ------------------------------------------------------------------------- *
 */
/* Mac address */
static struct ether_addr port_eth_addr;

/* Per socket (NUMA) memory pool */
static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

// Engine loop started notification semaphore
static sem_t* engine_start_notify;

// RX Event FD
static int *rx_event_fd;

/* ------------------------------------------------------------------------- *
 * Inter-core communication support
 * ------------------------------------------------------------------------- *
 */
// Size of cmd ring
#define CMD_RING_SZ     (256)

// Eventfd for to-fro IPC.
static int lcore_cmd_efd[RTE_MAX_LCORE];
static int lcore_status_efd[RTE_MAX_LCORE];

// Ring buffer for inter-core IPC.
static struct rte_ring* lcore_cmd_ring[RTE_MAX_LCORE];
static struct rte_ring* lcore_status_ring[RTE_MAX_LCORE];

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */
#define VIRTIO_MAX_NB_BUF       (4096)
#define VIRTIO_MIN_NB_BUF       (1024)
#define VIRTIO_MBUF_SIZE        (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define VIRTIO_MP_CACHE_SIZE    (RTE_MEMPOOL_CACHE_MAX_SIZE)
#define VIRTIO_RX_BURST         (32u)

struct virtio_arg {
    struct virtio_net_ll* lldev;
    struct rte_mempool* pool;
    int q_no;
};

// Lock for linkedlist OPs
static pthread_mutex_t ll_virtio_net_lock;

// Root of virtio device linkedlist
static struct virtio_net_ll* ll_virtio_net_root;

// Vhost worker thread
static pthread_t vhost_thread;

/* ------------------------------------------------------------------------- *
 * APIS
 * ------------------------------------------------------------------------- *
 */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	log_info("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					log_info("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					log_info("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			log_info(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			log_info("done\n");
		}
	}
}

static void print_ethaddr(const struct ether_addr *eth_addr)
{
    printf ("%02X:%02X:%02X:%02X:%02X:%02X\n",
        eth_addr->addr_bytes[0],
        eth_addr->addr_bytes[1],
        eth_addr->addr_bytes[2],
        eth_addr->addr_bytes[3],
        eth_addr->addr_bytes[4],
        eth_addr->addr_bytes[5]);
}

static int dpdk_main(int port_id, int argc, char* argv[])
{
    struct rte_eth_dev_info dev_info;
    unsigned nb_queues;
    FILE* lfile;
    uint8_t core_id;
    char name[80];
    int ret;

    printf("In dpdk_main\n");

    // Open the log file
    lfile = fopen("./vrouter.log", "w");

    // Program the rte log
    rte_openlog_stream(lfile);

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
		log_crit( "Invalid EAL parameters\n");
        return -1;
    }

    log_info( "Programming cmd rings now!\n");

    rx_event_fd = (int *) malloc(sizeof(int *) * rte_lcore_count());
    if (!rx_event_fd) {
        log_crit("Failed to allocate memory for rx event fd arrays\n");
        return -ENOMEM;
    }

    // Allocate cmd ring for each core
    RTE_LCORE_FOREACH(core_id) {
        sprintf(name, "cmd_ring-%d", core_id);
        lcore_cmd_ring[core_id] = rte_ring_create(name,
                                                  CMD_RING_SZ,
                                                  rte_lcore_to_socket_id(core_id),
                                                  RING_F_SC_DEQ|RING_F_SP_ENQ);
        if (!lcore_cmd_ring[core_id]) {
            log_crit( "Failed to create cmd ring for %d\n", core_id);
            return -ENOMEM;
        }

        lcore_cmd_efd[core_id] = eventfd(0, 0);
    }

    // Allocate status ring for each core
    RTE_LCORE_FOREACH(core_id) {
        sprintf(name, "status_ring-%d", core_id);
        lcore_status_ring[core_id] = rte_ring_create(name,
                                                  CMD_RING_SZ,
                                                  rte_lcore_to_socket_id(core_id),
                                                  RING_F_SC_DEQ|RING_F_SP_ENQ);
        if (!lcore_status_ring[core_id]) {
            log_crit( "Failed to create status ring for %d\n", core_id);
            return -ENOMEM;
        }

        lcore_status_efd[core_id] = eventfd(0, EFD_SEMAPHORE);
    }

    rte_eth_macaddr_get(port_id, &port_eth_addr);
    log_info("Port%d: MAC Address: ", port_id);
    print_ethaddr(&port_eth_addr);


    /* Determine the number of RX/TX pairs supported by NIC */
    rte_eth_dev_info_get(port_id, &dev_info);

    dev_info.pci_dev->intr_handle.type = RTE_INTR_HANDLE_VFIO_MSIX;
    dev_info.pci_dev->intr_handle.max_intr = dev_info.max_rx_queues+ dev_info.max_tx_queues;
    ret = rte_intr_efd_enable(&dev_info.pci_dev->intr_handle, dev_info.max_rx_queues);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to enable rx interrupts\n");
    }

    ret = rte_intr_enable(&dev_info.pci_dev->intr_handle);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to enable interrupts\n");
    }

    ret = rte_eth_dev_configure(port_id, dev_info.max_rx_queues, dev_info.max_tx_queues, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure ethernet device\n");
    }

    /* For each RX/TX pair */
    nb_queues = dev_info.max_tx_queues;
    for (core_id = 0; core_id < nb_queues; core_id++) {
        char s[64];
        if (rte_lcore_is_enabled(core_id) == 0)
            continue;

        /* NUMA socket number */
        unsigned socketid = rte_lcore_to_socket_id(core_id);
        if (socketid >= NB_SOCKETS) {
            log_crit( "Socket %d of lcore %u is out of range %d\n",
				socketid, core_id, NB_SOCKETS);
            return -EBADF;
        }

        /* Create memory pool */
        snprintf(s, sizeof(s), "mbuf_pool_%d_%d", socketid, core_id);
        pktmbuf_pool[socketid] = rte_mempool_create(s,
                                                    NB_MBUF,
                                                    MBUF_SIZE,
                                                    MEMPOOL_CACHE_SIZE,
                                                    sizeof(struct rte_pktmbuf_pool_private),
                                                    rte_pktmbuf_pool_init,
                                                    NULL,
                                                    rte_pktmbuf_init,
                                                    NULL,
                                                    socketid,
                                                    0);
        if (!pktmbuf_pool[socketid]) {
            log_crit( "Cannot init mbuf pool on socket %d\n", socketid);
            return -ENOMEM;
        }

        /* Setup the TX queue */
        ret = rte_eth_tx_queue_setup(port_id,
                                     core_id,
                                     RTE_TX_DESC_DEFAULT,
                                     socketid,
                                     &tx_conf);
        if (ret < 0) {
            log_crit( "Cannot initialize TX queue (%d)\n", core_id);
            return -ENODEV;
        }

        /* Setup the RX queue */
        ret = rte_eth_rx_queue_setup(port_id,
                                     core_id,
                                     RTE_RX_DESC_DEFAULT,
                                     socketid,
                                     &rx_conf,
                                     pktmbuf_pool[socketid]);
        if (ret < 0) {
            log_crit( "Cannot initialize RX queue (%d)\n", core_id);
            return -ENODEV;
        }

        printf("%d: efd: %d\n", core_id, dev_info.pci_dev->intr_handle.efds[core_id]);
    }

    // Start the eth device
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        log_crit( "rte_eth_dev_start: err=%d, port=%d\n", ret, core_id);
        return -ENODEV;
    }

    // Put the device in promiscuous mode
    rte_eth_promiscuous_enable(port_id);

    // Wait for link up
    //check_all_ports_link_status(1, 1u << port_id);

    log_info( "Starting engines on every core\n");

    rte_eal_mp_remote_launch(engine_loop, &dev_info, CALL_MASTER);

    return 0;
}

/* -- */

/* ------------------------------------------------------------------------- *
 * VIRTIO Device Support
 * ------------------------------------------------------------------------- *
 */

// Virtio rx event handler
static void virtio_rx_packet(CC_UNUSED uint16_t lcore_id, CC_UNUSED void* _arg)
{
    struct virtio_arg* arg = (struct virtio_arg*)_arg;
    struct rte_mbuf *pkts[VIRTIO_RX_BURST];
    unsigned count;

    count = rte_vhost_dequeue_burst(arg->lldev->dev,
                                    (arg->q_no * 2 + VIRTIO_TXQ),
                                    arg->pool,
                                    pkts,
                                    VIRTIO_RX_BURST);
    if (count > 0) {
    }
    else {
        log_crit("virtio_rx_packet: got one rx event without any packets!!\n");
    }
}

// Called when a VM starts a vhost-user device
static int new_device(struct virtio_net *dev)
{
    struct virtio_net_ll* lldev = (struct virtio_net_ll*) malloc( sizeof(struct virtio_net_ll) );
    struct vif* vif;
    GoString str;
    int q_no;

    printf("new_device: %ld\n", dev->device_fh);

    pthread_mutex_lock(&ll_virtio_net_lock);
    lldev->dev = dev;
    lldev->next = ll_virtio_net_root;
    ll_virtio_net_root = lldev;
    dev->priv = lldev;
    pthread_mutex_unlock(&ll_virtio_net_lock);

    lldev->state = VIRTIO_STATE_MAC_LEARNING;
    lldev->nb_queues = dev->virt_qp_nb;
    lldev->queue = (struct virtqueue*) malloc(sizeof(struct virtqueue) * lldev->nb_queues);

    for (q_no = 0; q_no < lldev->nb_queues; q_no++) {
        lldev->queue[q_no].callfd = dev->virtqueue[q_no * 2 + VIRTIO_RXQ]->callfd;
        lldev->queue[q_no].kickfd = dev->virtqueue[q_no * 2 + VIRTIO_TXQ]->kickfd;
        lldev->queue[q_no].rxq = dev->virtqueue[q_no * 2 + VIRTIO_TXQ];
        lldev->queue[q_no].txq = dev->virtqueue[q_no * 2 + VIRTIO_TXQ];
        lldev->queue[q_no].rx_packets = 0;
        lldev->queue[q_no].tx_packets = 0;
        lldev->queue[q_no].error_packets = 0;
        lldev->queue[q_no].entry_read = 0;
    }

    str.p = dev->ifname;
    str.n = strlen(dev->ifname);
    printf("Calling VifFind\n");
    vif = VifFind(str, lldev);
    printf("VifFind: %p\n", vif);
    if (!vif) {
        log_crit("Failed to get associated VIF for this device (%ld)\n", dev->device_fh);
        return -1;
    }

    return 0;
}

// Called when a VM destroys a vhost-user device
static void destroy_device(volatile struct virtio_net* dev)
{
    struct virtio_net_ll *ll_node, *ll_prev;

    pthread_mutex_lock(&ll_virtio_net_lock);
    for (ll_node = ll_virtio_net_root, ll_prev = NULL; ll_node != NULL; ll_prev = ll_node, ll_node = ll_node->next) {
        if (ll_node->dev == dev) {
            ll_prev->next = ll_node->next;
            free(ll_prev);
        }
    }
    pthread_mutex_unlock(&ll_virtio_net_lock);
}

static const struct virtio_net_device_ops virtio_ops = {
    .new_device = new_device,
    .destroy_device = destroy_device
};

/* rte_vhost_driver_session_start is a blocking call, thus we create another thread and call it from there */
static void* vhost_worker(CC_UNUSED void* arg)
{
    pthread_detach(pthread_self());

    log_info("vhost_worker started\n");

    if (rte_vhost_driver_session_start() < 0) {
        log_crit( "rte_vhost_driver_register failed to start\n");
    }

    return NULL;
}

/* -- */

/* ------------------------------------------------------------------------- *
 * Core logic
 * ------------------------------------------------------------------------- *
 */
// rte_eal_mp_remote_launch causes calling thread to be hang/wait state.
// Thus calling dpdk_main in thread
static void* dpdk_init_worker(CC_UNUSED void* arg)
{
    const char *argv[5] = { "vrouter", "-m", HUGEPAGE_MEMORY_SZ, "-w", PCI_DEVICE_BDF};

    if (dpdk_main(0, 5, argv) < 0)
        rte_exit(EXIT_FAILURE, "DPDK Main failed\n");

    return NULL;
}

// Pthread handles
static pthread_t engine_thread;

// Called from CGO code.
int dpdk_init(void)
{
    int i;

    engine_start_notify = (sem_t*) malloc(sizeof(sem_t) * sysconf (_SC_NPROCESSORS_CONF));

    for (i = 0; i < sysconf (_SC_NPROCESSORS_CONF); i++)
        sem_init(&engine_start_notify[i], 0, 0);

    // Call dpdk_main from a thread
    pthread_create(&engine_thread, NULL, dpdk_init_worker, NULL);

    // Wait till all cores are in engine loop
    for (i = 0; i < sysconf (_SC_NPROCESSORS_CONF); i++)
        sem_wait(&engine_start_notify[i]);

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

    log_info( "VHOST Socket is up and running!\n");
    return 0;
}


static struct rte_mempool* create_mempool(int core_id, struct virtio_net* dev, int q_no)
{
    unsigned socketid = rte_lcore_to_socket_id(core_id);
    struct rte_mempool *pool;
    uint32_t mp_size;
    char name[32];

    /* Create memory pool */
    mp_size = VIRTIO_MAX_NB_BUF;
    snprintf(name, 32, "virtio_%ld_%d", dev->device_fh, q_no);
    do {
        pool = rte_mempool_create(name,
                mp_size,
                VIRTIO_MBUF_SIZE,
                VIRTIO_MP_CACHE_SIZE,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init,
                NULL,
                rte_pktmbuf_init,
                NULL,
                socketid,
                0);
        printf("errno: %d\n", rte_errno);
    } while(!pool && rte_errno == ENOMEM && (mp_size /= 2) >= VIRTIO_MIN_NB_BUF);

    return pool;
}


int event_handler_add(int core_id, int q_no, int slot, CC_UNUSED void* _vif, void* _lldev)
{
    struct virtio_net_ll* lldev = (struct virtio_net_ll*)_lldev; 
    struct engine_cmd_msg* msg;
    struct virtio_arg* arg;
    int ret;

    msg = (struct engine_cmd_msg*) malloc(sizeof(*msg));
    if (!msg)
        return -EAGAIN;

    arg = (struct virtio_arg*) malloc(sizeof(struct virtio_arg));
    if (!arg) {
        free(msg);
        return -EAGAIN;
    }

    msg->cmd = ENGINE_CMD_FD_ADD;
    msg->fd = lldev->queue[q_no].kickfd;
    msg->slot = slot;
    // Event handler for rx packet event
    arg->lldev = lldev;
    arg->q_no = q_no;
    msg->handler.data = arg;
    msg->handler.fn = virtio_rx_packet;
    msg->ret_code = -1;

    // Create the rte mempool
    arg->pool = create_mempool(core_id, lldev->dev, q_no);
    if (!arg->pool) {
        free(arg);
        free(msg);
        return -EAGAIN;
    }

    // Send the command to engine loop
    do {
        ret = engine_send_cmd(core_id, (void*)msg);
        printf("engine_send_cmd: %d\n", ret);
    } while(ret != 0);

    free(msg);

    return msg->ret_code;
}

int event_handler_del(int core_id, int slot)
{
    struct engine_cmd_msg* msg;

    msg = (struct engine_cmd_msg*) malloc(sizeof(*msg));
    if (!msg)
        return -EAGAIN;

    msg->cmd = ENGINE_CMD_FD_DEL;
    msg->slot = slot;
    msg->ret_code = -1;

    // Send the command to engine loop
    while (engine_send_cmd(core_id, (void*)msg) != 0);

    free(msg);

    return msg->ret_code;
}

/* Send a command to an engine loop */
int engine_send_cmd(int lcore_id, void* buf)
{
    uint64_t counter = 1;
    struct pollfd fds[1];
    int ret;

    if (rte_ring_full(lcore_cmd_ring[lcore_id]))
        return -EAGAIN;

    printf("Sending one cmd\n");
    rte_ring_sp_enqueue(lcore_cmd_ring[lcore_id], buf);
    write(lcore_cmd_efd[lcore_id], &counter, 8);

    // Wait for status notify
    fds[0].events = POLLIN|POLLERR;
    fds[0].fd = lcore_status_efd[lcore_id];

    do {
        ret = poll(&fds[0], 1, -1);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                read(lcore_status_efd[lcore_id], &counter, 8);
                return 0;
            }
            read(lcore_status_efd[lcore_id], &counter, 8);
            printf("@@revent: %d\n", fds[0].revents);
        }
        else {
            perror("poll");
            printf("poll return code: %d\n", ret);
            printf("errnno: %d\n", errno);
            return -EAGAIN;
        }
    } while(1);

    return 0;
}

// Called when user wants to update the fds list for a engine loop.
// This happens when a virtio/vm is created/destroyed.
static void engine_cmd_callback(uint16_t lcore_id, void* data)
{
    struct cmd_event_info* info = (struct cmd_event_info*)data;
    struct engine_cmd_msg* msg;
    uint64_t temp;

    // Eat the event
    //read(lcore_cmd_efd[lcore_id], &temp, 8);

    rte_ring_sc_dequeue(lcore_cmd_ring[info->core_id], (void**) &msg);

    if (msg->cmd == ENGINE_CMD_FD_ADD) {
        memset(&info->fds[msg->slot], 0, sizeof(struct pollfd));
        info->fds[msg->slot].fd = msg->fd;
        info->fds[msg->slot].events = POLLIN|POLLERR;
        info->event_handlers[msg->slot].fn = msg->handler.fn;
        info->event_handlers[msg->slot].data = msg->handler.data;
        (*info->nb_fd)++;
    }
    else {
        memset(&info->fds[msg->slot], 0, sizeof(struct pollfd));
        (*info->nb_fd)--;
    }

    msg->ret_code = 0;
    write(lcore_status_efd[lcore_id], &temp, 8);
}

// RX packet callback

static int engine_loop(CC_UNUSED void* arg)
{
    uint16_t lcore_id = rte_lcore_id();
//    struct rte_eth_dev_info* dev_info = (struct rte_eth_dev_info*)arg;
    struct event_handler* event_handlers;
    struct cmd_event_info info;
    struct pollfd* event_fds;
    uint64_t temp;
    int event_nb_fd;

    log_info( "DPDK Engine loop starting on (%d) core\n", lcore_id);

    // Notify we are up!
    sem_post(&engine_start_notify[lcore_id]);

    event_handlers = (struct event_handler*)malloc(sizeof(struct event_handler) * MAX_EVENTS);
    if (!event_handlers) {
        log_crit( "Engineloop%d: Unable to allocate memory event handlers\n", lcore_id);
        return 0;
    }
    memset(event_handlers, 0, sizeof(struct event_handler) * MAX_EVENTS);

    event_fds = (struct pollfd*) malloc(sizeof(struct pollfd) * MAX_EVENTS);
    if (!event_fds) {
        log_crit( "Engineloop%d: Unable to allocate memory pollfds\n", lcore_id);
        return 0;
    }
    memset(event_fds, 0, sizeof(struct pollfd) * MAX_EVENTS);

    // Cmd event handlers
    info.core_id = lcore_id;
    info.fds = event_fds;
    info.nb_fd = &event_nb_fd;
    info.event_handlers = event_handlers;
    event_handlers[CMD_EVENT_SLOT].data = (void*)&info;
    event_handlers[CMD_EVENT_SLOT].fn = engine_cmd_callback;

    // fds is dynamically modified for new fds.
    event_fds[CMD_EVENT_SLOT].fd = lcore_cmd_efd[lcore_id];
    event_fds[CMD_EVENT_SLOT].events = POLLIN | POLLERR;
    event_nb_fd = 1;

    while(1) {
        int ret = poll(event_fds, event_nb_fd, -1);
        if ( unlikely(ret < 0) ) {
            log_crit( "engine_loop (%d) encountered error\n", lcore_id);
        }

        if ( likely(ret > 0) ) {
            int cc = 0;
            int fd;

            for (fd = 0; likely ((fd < event_nb_fd) && (cc < ret)) ; fd++) {
                if ( likely(event_fds[fd].revents & POLLIN) ) {
                    if ( likely(event_handlers[fd].fn != NULL) ) {
                        (*event_handlers[fd].fn)(lcore_id, event_handlers[fd].data);
                        // Reset the event
                        read(event_fds[fd].fd, &temp, 8);
                    }
                    cc++;
                }
            }
        }
    }

    return 0;
}

/* -- */

// Attach a VIF to a vrf
struct vif* vif_add(char* name, uint8_t* ip, uint8_t mask, uint8_t* macaddr, uint32_t label, char* path, int cpus, int cpusets[])
{
    int i;
    struct vif* vif = (struct vif*) malloc (sizeof(struct vif));
    if (!vif) {
        log_crit("Failed to allocated memory for vif struct (%s)\n", name);
        return NULL;
    }

    printf("vif_add called\n");

    strcpy(vif->name, name);
    vif->label = label;
    vif->mask = mask;
    memcpy(vif->ip, ip, 4);
    memcpy(vif->macaddr, macaddr, 4);
    strcpy(vif->path, path);

    vif->cpus = cpus;
    for (i = 0; i < cpus; i++) {
        CPU_ZERO(&vif->cpusets[i]);
        CPU_SET(cpusets[i], &vif->cpusets[i]);
    }

    vif->dev = NULL;

    /* Create VHOST-User socket */
    unlink(vif->path);
    if (rte_vhost_driver_register(vif->path) < 0) {
        free(vif);
        return NULL;
    }

    return vif;
}

// detach a VIF from a vrf
void vif_del(struct vif* vif)
{
    rte_vhost_driver_unregister(vif->path);
    free(vif);
}

// Called by go code in main function
unsigned GetCoreCount(void)
{
    return rte_lcore_count();
}


/* ------------------------------------------------------------------------- *
 * ipv4_route
 * ------------------------------------------------------------------------- *
 */
static mtrie_t *ipv4_route_table;

// Called by go code
int ipv4_route_init(uint32_t nb_entries)
{
    int i;
    ipv4_route_table = (mtrie_t*) malloc (sizeof(mtrie_t) * nb_entries);
    if (!ipv4_route_table)
        return -EAGAIN;

    for (i = 0; i < nb_entries; i++) {
        mtrie_init(&ipv4_route_table[i], 3);
    }
}

// Called by go code
int ipv4_route_add(uint32_t label, uint8_t* ip, struct nexthop* nh)
{
}

// Called by go code
int ipv4_route_del(uint32_t label, uint8_t* ip)
{
}

// Called from data path
int ipv4_lookup(uint32_t label, uint8_t* ip)
{
}

