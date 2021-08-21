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
#include <rte_vhost.h>
#include <stdbool.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS ((64*1024)-1)
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define PTP_PROTOCOL 0x88F7
#define MAX_PACKETS 3000000

static struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

struct send_params{
    struct rte_mempool *mbuf_pool;
    uint16_t port;
    uint16_t queue_id;
    uint64_t max_packets;
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
        const uint16_t rx_rings = 2, tx_rings = 2; //number of rx_rings and tx_rings changed from 1 to 2. 
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

        printf("Sender is Port %u with MAC address: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        port,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        if (retval != 0)
                return retval;

        return 0;
}

struct my_message{
    struct rte_ether_hdr eth_hdr;
    char payload[10];
};

static int
my_send(struct send_params *p)
{
    int retval;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_ether_addr src_mac_addr;
    retval = rte_eth_macaddr_get(0, &src_mac_addr); // get MAC address of Port 0 on node1-1
    struct rte_ether_addr dst_mac_addr = {{0x98,0x03,0x9b,0x6a,0x8e,0x12}}; //MAC address 98:03:9b:6a:8e:12
    struct my_message *my_pkt;
    
    struct rte_mempool *mbuf_pool = p->mbuf_pool;
    uint16_t port = p->port;
    uint16_t queue_id = p->queue_id;
    uint64_t max_packets = p->max_packets;

    int j=0;
    uint16_t sent_packets = BURST_SIZE;
    do{
        for(int i = 0; i < sent_packets; i ++)
        {
            bufs[i] = rte_pktmbuf_alloc(mbuf_pool);
            if (unlikely(bufs[i] == NULL)) {
                printf("Couldn't "
                    "allocate memory for mbuf.\n");
                break;
            }
            my_pkt = rte_pktmbuf_mtod(bufs[i], struct my_message*);
            *my_pkt->payload = 'Hello2021';    
            int pkt_size = sizeof(struct my_message);
            bufs[i]->pkt_len = bufs[i]->data_len = pkt_size;
            rte_ether_addr_copy(&src_mac_addr, &my_pkt->eth_hdr.s_addr);
            rte_ether_addr_copy(&dst_mac_addr, &my_pkt->eth_hdr.d_addr);
            my_pkt->eth_hdr.ether_type = htons(PTP_PROTOCOL);
        }

        sent_packets = rte_eth_tx_burst(port, queue_id, bufs, BURST_SIZE);
//        printf("Number of packets tx %" PRIu16 "\n", sent_packets);

        j = j + sent_packets;
    }
    while(j < max_packets);
        /* Free any unsent packets. */
    if (unlikely(sent_packets < BURST_SIZE)) {
            uint16_t buf;
            for (buf = sent_packets; buf < BURST_SIZE; buf++)
                    rte_pktmbuf_free(bufs[buf]);
        }
    
    return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    //struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    uint16_t port;
    uint64_t max_packets = 3000000;
    unsigned lcore_id;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
            rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;


    nb_ports = rte_eth_dev_count_avail();
    printf("Number of ports available%"PRIu16 "\n", nb_ports);

    if(nb_ports!=1)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be one\n");
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

//        if (rte_lcore_count() > 1)
//                printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

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

    lcore_id = rte_get_next_lcore(-1, 1, 0);
    if(lcore_id == RTE_MAX_LCORE)
    {
        rte_exit(EXIT_FAILURE, "Slave core id required!");
    }
    
    struct send_params p1 = {mbuf_pool, 0, 1, max_packets};
    struct send_params p2 = {mbuf_pool, 0, 0, max_packets};
    
//    struct send_params *p = rte_malloc(NULL, sizeof(*p), 0);
//    if (!p)
//        rte_panic("malloc failure\n");
//    *p = (struct send_params){mbuf_pool, 0, 1, max_packets/2};
    rte_eal_remote_launch((lcore_function_t *)my_send, &p1, lcore_id);
//    
//    
//    *p = (struct send_params){mbuf_pool, 0, 0, max_packets/2};
    my_send(&p2); 
    
    // sleep(1);
    return 0;
}