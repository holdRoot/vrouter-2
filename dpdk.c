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
#include <signal.h>

#include "dpdk.h"
#include "vif.h"
#include "virtio.h"

#include <Python.h>

/* ------------------------------------------------------------------------- *
 * ETHERDEV Configuration
 * ------------------------------------------------------------------------- *
 */
/* Number of sockets in NUMA */
#define NB_SOCKETS  (8u)

/* Number of buffer descriptor for RX for every Q */
#define RTE_RX_DESC_DEFAULT (128u)

/* Number of buffer descriptor for TX for every Q */
#define RTE_TX_DESC_DEFAULT (512u)

/* Memory pool cache size */
#define MEMPOOL_CACHE_SIZE (256u)

/* Number of packets to prefetch when rx */
#define NB_PREFETCH_PACKETS (3)

// Default MBUF Size
#define MBUF_SIZE (DEFAULT_PACKET_SZ + sizeof(struct rte_mbuf) + \
        PKTMBUF_PRIV_SZ)

// Maximum number of Qs (32 of HW device, 100 VMs each having 2Qs)
#define NB_QUEUES           (32 + 10)

// There is one big mempool for every socket.
#define NB_MBUF RTE_MAX	(								\
				(NB_QUEUES * RTE_RX_DESC_DEFAULT +	    \
				 NB_QUEUES * MAX_PKT_BURST +			\
				 NB_QUEUES * RTE_TX_DESC_DEFAULT +	    \
				 NB_QUEUES * MEMPOOL_CACHE_SIZE),		\
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
 * Globals
 * ------------------------------------------------------------------------- *
 */
/* Mac address */
static struct ether_addr port_eth_addr;

/* Per socket (NUMA) memory pool */
struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

/* ------------------------------------------------------------------------- *
 * APIS
 * ------------------------------------------------------------------------- *
 */
#if 0
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
#endif

/* -- */

/* ------------------------------------------------------------------------- *
 * Core logic
 * ------------------------------------------------------------------------- *
 */
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

static sem_t wait_sem;
static int main_loop(CC_UNUSED void* arg)
{
    sem_wait(&wait_sem);

    return 0;
}

static void vrouter_shutdown(CC_UNUSED int signo)
{
    uint16_t nb_cores = rte_lcore_count();

    log_crit("vrouter_shutdown called, shutdowning vrouter\n");

    while (nb_cores-- > 0)
        sem_post(&wait_sem);

    rte_eth_dev_stop(0);

    virtio_exit();

    vif_exit();

    exit(0);
}

int main(int argc, char* argv[])
{
    struct rte_eth_dev_info dev_info;
    char import_cmd[512];
    unsigned nb_queues;
    FILE* lfile;
    int port_id = 0;
    uint8_t core_id;
    int ret;

    if (getenv("VROUTER_HOME") == NULL) {
        printf("Please set VROUTER_HOME variable to point the vrouter "
            "installtion location\n");
        exit(0);
    }

    sem_init(&wait_sem, 0, 0);

    // Python bindings initialization
    Py_SetProgramName(argv[0]);
    Py_Initialize();
    PySys_SetArgv(argc, argv);
    PyRun_SimpleString("import sys");
    snprintf(import_cmd, 512, "sys.path.append(\"%s/scripts/\")",
                        getenv("VROUTER_HOME"));
    PyRun_SimpleString(import_cmd);

    // Open the log file
    lfile = fopen("./vrouter.log", "w");

    // Program the rte log
    rte_openlog_stream(lfile);

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        log_crit( "Invalid EAL parameters\n");
        return -1;
    }

    signal(SIGINT, vrouter_shutdown);
    signal(SIGTERM, vrouter_shutdown);

    rte_eth_macaddr_get(port_id, &port_eth_addr);
    log_info("Port%d: MAC Address: ", port_id);
    print_ethaddr(&port_eth_addr);

    /* Determine the number of RX/TX pairs supported by NIC */
    rte_eth_dev_info_get(port_id, &dev_info);

#if 0
    dev_info.pci_dev->intr_handle.type = RTE_INTR_HANDLE_VFIO_MSIX;
    dev_info.pci_dev->intr_handle.max_intr =
                            dev_info.max_rx_queues + dev_info.max_tx_queues;
    ret = rte_intr_efd_enable(&dev_info.pci_dev->intr_handle,
            dev_info.max_rx_queues);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to enable rx interrupts\n");
    }

    ret = rte_intr_enable(&dev_info.pci_dev->intr_handle);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to enable interrupts\n");
    }
#endif

    ret = rte_eth_dev_configure(port_id, dev_info.max_rx_queues,
                dev_info.max_tx_queues, &port_conf);
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
        if (pktmbuf_pool[socketid] == NULL) {
            log_info("Creating mempool on %d of ~%lx bytes\n",
                            socketid, NB_MBUF * MBUF_SIZE);
            printf("Creating mempool on %d of ~%lx bytes\n",
                        socketid, NB_MBUF * MBUF_SIZE);
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] = rte_mempool_create(s,
                                                        NB_MBUF,
                                                        MBUF_SIZE,
                                                        MEMPOOL_CACHE_SIZE,
                                                        PKTMBUF_PRIV_SZ,
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
    }

#if 0
    // Start the eth device
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        log_crit( "rte_eth_dev_start: err=%d, port=%d\n", ret, core_id);
        return -ENODEV;
    }
#endif

    // Put the device in promiscuous mode
    rte_eth_promiscuous_enable(port_id);

    // Wait for link up
    //check_all_ports_link_status(1, 1u << port_id);

    if (vif_init(rte_lcore_count()) < 0) {
        log_crit("vif_init failed\n");
        vrouter_shutdown(0);
    }

    virtio_init();

    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(core_id) {
        if (rte_eal_wait_lcore(core_id) < 0)
            return -1;
    }

    return 0;
}
