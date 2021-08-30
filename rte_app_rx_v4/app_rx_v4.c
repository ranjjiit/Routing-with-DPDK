/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf_dyn.h>
#include <sys/time.h>
#include <rte_time.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS ((64*1024)-1)
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
#define PTP_PROTOCOL 0x88F7
uint64_t rx_count; // global variable to keep track of the number of received packets (to be displayed every second)
uint64_t tx_count;
uint64_t max_packets = 1000000;

static int hwts_dynfield_offset = -1;
typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;
static inline tsc_t *
tsc_field(struct rte_mbuf *mbuf)
{
    return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}
static const char usage[] =
    "%s EAL_ARGS -- [-t]\n";
static struct {
    uint64_t total_cycles;
    uint64_t total_queue_cycles;
    uint64_t total_pkts;
} latency_numbers;
int hw_timestamping;
#define TICKS_PER_CYCLE_SHIFT 16
static uint64_t ticks_per_cycle_mult;
/* Callback added to the RX port and applied to packets. 8< */
static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts, uint16_t nb_pkts,
        uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
    unsigned i;
    uint64_t now = rte_rdtsc();
    for (i = 0; i < nb_pkts; i++)
        *tsc_field(pkts[i]) = now;
    return nb_pkts;
}
/* >8 End of callback addition and application. */
/* Callback is added to the TX port. 8< */
static uint16_t
calc_latency(uint16_t port, uint16_t qidx __rte_unused,
        struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
    uint64_t cycles = 0;
    uint64_t now = rte_rdtsc();
    unsigned i;

    for (i = 0; i < nb_pkts; i++) {
        cycles += now - *tsc_field(pkts[i]);   
    }
    latency_numbers.total_cycles += cycles;
    latency_numbers.total_pkts += nb_pkts;
    if (latency_numbers.total_pkts > (100 * 1000 * 1000ULL)) {
        printf("Latency = %"PRIu64" cycles\n",
        latency_numbers.total_cycles / latency_numbers.total_pkts);
        latency_numbers.total_cycles = 0;
        latency_numbers.total_queue_cycles = 0;
        latency_numbers.total_pkts = 0;
    }
    return nb_pkts;
}
/* >8 End of callback addition. */


static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};


/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        
	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Receiver is Port %u with MAC address: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;
        
        /* RX and TX callbacks are added to the ports. 8< */
//	rte_eth_add_rx_callback(0, 0, add_timestamps, NULL);
//	rte_eth_add_tx_callback(0, 0, calc_latency, NULL);
	/* >8 End of RX and TX callbacks. */

	return 0;
}

static int
lcore_stat(__rte_unused void *arg)
{
    for(; ;)
    {
        sleep(2); // report stats every second
        printf("Number of packets received %"PRIu64 "\n", rx_count);
    }
}
struct my_message{
    struct rte_ether_hdr eth_hdr;
    uint16_t type;
    uint16_t dst_addr;
    uint32_t seqNo;
    uint64_t timestamp;
    char payload[10];
};


void my_receive()
{
    int retval;
    struct my_message *my_pkt;
    uint16_t eth_type; 
    rx_count = 0;
    tx_count = 0;
    struct rte_ether_addr src_mac_addr;
    retval = rte_eth_macaddr_get(0, &src_mac_addr); // get MAC address of Port 0 on node1-1
    
    printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
                    rte_lcore_id());
    
    /* Receive maximum of max_packets */
    do{
        
        /* Get burst of RX packets, from first port of pair. */
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(0, 0,
                        bufs, BURST_SIZE);
        
        if (unlikely(nb_rx == 0))
                continue;
        
        for(int i = 0; i < nb_rx; i++)
        {
            my_pkt = rte_pktmbuf_mtod(bufs[i], struct my_message *);
            eth_type = rte_be_to_cpu_16(my_pkt->eth_hdr.ether_type);
            
            /* Check for data packet of interest and ignore other broadcasts 
             messages */
            
            if(likely(eth_type == PTP_PROTOCOL))
            {
                rx_count = rx_count + 1;
                struct rte_ether_addr dst_mac_addr = my_pkt->eth_hdr.s_addr; 
                
                rte_ether_addr_copy(&src_mac_addr, &my_pkt->eth_hdr.s_addr);
                rte_ether_addr_copy(&dst_mac_addr, &my_pkt->eth_hdr.d_addr);
            }
            
        }
        
        const uint16_t nb_tx = rte_eth_tx_burst(0, 0, bufs, nb_rx);
        tx_count = tx_count + nb_tx;
        
        if(unlikely(nb_tx < nb_rx))
        {
            uint16_t buf;
            for(buf = nb_tx; buf < nb_rx; buf++)
                rte_pktmbuf_free(bufs[buf]);
        }
        
    }while(rx_count <= max_packets);
    
    printf("\nTotal Number of packets received by machine 2 is %"PRIu64, rx_count);
    printf("\nTotal Number of packets transmitted by machine 2 is %"PRIu64"\n", tx_count);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    uint16_t port;
    unsigned lcore_id;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
            rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Get the number of ports */
    nb_ports = rte_eth_dev_count_avail();

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
            if (port_init(portid, mbuf_pool) != 0)
                    rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                                    portid);
    
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
            if (rte_eth_dev_socket_id(port) > 0 &&
                            rte_eth_dev_socket_id(port) !=
                                            (int)rte_socket_id())
                    printf("WARNING, port %u is on remote NUMA node to "
                                    "polling thread.\n\tPerformance will "
                                    "not be optimal.\n", port);


//    lcore_id = rte_get_next_lcore(-1, 1, 0);
//    if(lcore_id == RTE_MAX_LCORE)
//    {
//        rte_exit(EXIT_FAILURE, "Slave core id required!");
//    }
//    rte_eal_remote_launch(lcore_stat, NULL, lcore_id);
    
    /* Time to process the packets*/
    struct timespec sys_time;
    uint64_t nsec1, nsec2;
    clock_gettime(CLOCK_REALTIME, &sys_time);
    nsec1 = rte_timespec_to_ns(&sys_time);
    
    my_receive();
    
    clock_gettime(CLOCK_REALTIME, &sys_time);
    nsec2 = rte_timespec_to_ns(&sys_time);
    printf("Time to process %"PRIu64 "\n", nsec2-nsec1);
    
    
    return 0;
}
