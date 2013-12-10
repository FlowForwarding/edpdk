/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2013 Tieto Global Oy. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _PMDENGINE_H_
#define _PMDENGINE_H_

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#define OK                                  0
#define RTE_LOGTYPE_PMDENGINE               RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_EDPDK                   RTE_LOGTYPE_USER2
#define RX_PTHRESH                          8
#define RX_HTHRESH                          8
#define RX_WTHRESH                          4
#define TX_PTHRESH                          36
#define TX_HTHRESH                          0
#define TX_WTHRESH                          0
#define MAX_TX_QUEUE_STATS_MAPPINGS         1024
#define MAX_RX_QUEUE_STATS_MAPPINGS         4096
#define RTE_TEST_RX_DESC_MAX                2048
#define RTE_TEST_TX_DESC_MAX                2048
#define RTE_TEST_RX_DESC_DEFAULT            128
#define RTE_TEST_TX_DESC_DEFAULT            512
#define DEF_PKT_BURST                       16
#define RTE_TEST_RX_DESC_MAX                2048
#define RTE_TEST_TX_DESC_MAX                2048
#define DEF_PKT_BURST                       16
#define MAX_PKT_BURST                       512
#define UMA_NO_CONFIG                       0xFF
#define DEFAULT_MBUF_DATA_SIZE              2048
#define ALL_PORTS_MASK                      (~(uint8_t)0x0)
#define RTE_PORT_STOPPED                    (uint16_t)0
#define RTE_PORT_STARTED                    (uint16_t)1
#define RTE_PORT_CLOSED                     (uint16_t)2
#define RTE_PORT_HANDLING                   (uint16_t)3
#define MSG_QUEUES_TABLE_SIZE               10
#define MSG_QUEUE_SIZE                      8192
#define MSG_QUEUE_NAME_CHARS_MAX            50
#define PORTS_PER_LCORE_MAX                 4
#define LCORE_PORTS_TABLE_SIZE              20
#define FWD_CONTEXT_PORTS_MAX               4
#define FWD_CONTEXT_MAX                     10
#define RXTX_RING_NAME_CHARS_MAX            50
#define PACKET_SIZE_MAX                     2048
#define NUM_MBUF                            16384
#define MBUF_SIZE                           (PACKET_SIZE_MAX + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MEMPOOL_CACHE_SIZE                  MAX_PKT_BURST

/**
 *
 */
struct rxtx_ring_pair {
    struct rte_ring * recv_ring;
    struct rte_ring * xmit_ring;
};

/**
 *
 */
struct fwd_port {
    /* Id of the port */
    uint8_t pid;
    /* Id of the rx queue */
    uint8_t rxq;
    /* Id of the tx queue */
    uint8_t txq;
    /* Where rx pkts are stored during reception */
    unsigned int rx_pkts;
    /* Where tx pkts are  stored before transmission*/
    unsigned int tx_pkts;
    unsigned int rx_bad_ip_csum;
    unsigned int rx_bad_l4_csum;
    /* Where rx/tx pkts are stored/retrieved
     * for multi-process communication*/
    struct rxtx_ring_pair * rxtx_rings;
    unsigned int dropped;
};

/**
 *
 */
struct fwd_lcore {
    struct rte_mempool * mbuf_pool;
    uint8_t cpuid;
    volatile char stopped;
};

/**
 *
 */
struct rx_port {
    struct fwd_port * port;
    struct rte_ring * recv_ring;
};

/**
 *
 */
struct tx_port {
    struct fwd_port * port;
    struct rte_ring * xmit_ring;
};

/**
 *
 */
struct fwd_context {
    /* Ports that lcore will rx/tx pkts */
    struct fwd_port *ports[FWD_CONTEXT_PORTS_MAX];
    /* The lcore that executes the rx/tx for all of
     * the assigned ports */
    struct fwd_lcore * lcore;
    unsigned int num_fwd_ports;

    /* Ports that lcore will rx */
    uint8_t rx_ports[FWD_CONTEXT_PORTS_MAX];
    unsigned int num_rx_ports;
    /* Ports that lcore will tx */
    uint8_t tx_ports[FWD_CONTEXT_PORTS_MAX];
    unsigned int num_tx_ports;
};

/**
 *
 */
struct queue_stats_mappings {
    uint8_t port_id;
    uint16_t queue_id;
    uint8_t stats_counter_id;
} __rte_cache_aligned;

/**
 *
 */
struct rte_port {
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf dev_conf;
    struct ether_addr eth_addr;
    struct rte_eth_stats stats;
    uint64_t tx_dropped;
    struct exec_unit *rx_stream;
    struct exec_unit *tx_stream;
    unsigned int socket_id;
    uint16_t tx_ol_flags;
    uint16_t tx_vlan_id;
    void *fwd_ctx;
    uint64_t rx_bad_ip_csum;
    uint64_t rx_bad_l4_csum;
    uint8_t tx_queue_stats_mapping_enabled;
    uint8_t rx_queue_stats_mapping_enabled;
    volatile uint16_t port_status;
    uint8_t need_reconfig;
    uint8_t need_reconfig_queues;
    uint8_t rss_flag;
    uint8_t dcb_flag;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
};

/**
 *
 */
struct port_driver_data {
    struct rte_eth_rxmode rx_mode;
    struct rte_eth_thresh rx_thresh;
    struct rte_eth_thresh tx_thresh;
    uint16_t rss_hf;
    uint8_t rx_drop_en;
    uint16_t tx_free_thresh;
    uint16_t tx_rs_thresh;
    uint32_t txq_flags;
    uint8_t no_flush_rx;
    uint16_t num_rxq;
    uint16_t num_txq;
    uint16_t num_rxd;
    uint16_t num_txd;
};

/**
 *
 */
struct ports_data {
    unsigned int num_probed_ports;
    uint8_t num_fwd_ports;
    uint8_t fwd_ports_ids[RTE_MAX_ETHPORTS];
    struct port_driver_data driver_d;
    struct rte_port * rte_ports;
    struct rte_fdir_conf fdir_conf;
    uint16_t num_tx_queue_stats_mappings;
    uint16_t num_rx_queue_stats_mappings;
    uint16_t num_pkt_per_burst;
    struct queue_stats_mappings *tx_queue_stats_mappings;
    struct queue_stats_mappings *rx_queue_stats_mappings;
    struct queue_stats_mappings tx_queue_stats_mappings_array[MAX_TX_QUEUE_STATS_MAPPINGS];
    struct queue_stats_mappings rx_queue_stats_mappings_array[MAX_RX_QUEUE_STATS_MAPPINGS];
};

/**
 *
 */
struct lcores_data {
    uint16_t mbuf_mempool_cache;
    uint16_t mbuf_data_size;
    uint8_t socket_num;
    uint8_t num_probed_lcores;
    uint8_t num_fwd_lcores;
    unsigned int fwd_lcores_cpuids[RTE_MAX_LCORE];
    struct fwd_lcore ** fwd_lcores;
};

/**
 *
 */
struct mbuf_ctor_arg {
    uint16_t seg_buf_offset;
    uint16_t seg_buf_size;
};

/**
 *
 */
struct mbuf_pool_ctor_arg {
    uint16_t seg_buf_size;
};

int pe_init(void);
int pe_init_ports(void);
int pe_init_lcores(void);
unsigned int pe_get_num_probed_ports(void);
void pe_free_pmd_resources(void);
int pe_start_ports(uint8_t);
int pe_start_pmdengine(void);
int pe_parse_args(int, char **, int);
int pe_init_fwd_contexts(void);
unsigned int get_num_fwd_contexts(void);
struct rte_mbuf * pe_create_rte_mbuf(void *, unsigned int, unsigned int);
int pe_init_mempool(void);
uint16_t pe_get_num_pkt_per_burst(void);
struct fwd_port * pe_get_fwd_port(unsigned int);
struct rte_port * get_rte_port(uint8_t);

/**
 *
 */
static inline int mbuf_poolname_build(unsigned int sock_id, char* mp_name,
        unsigned int name_size) {
    if (NULL == mp_name)
        return -1;
    rte_snprintf(mp_name, name_size, "mbuf_pool_socket_%u", sock_id);
    return 0;
}

/**
 *
 */
static inline struct rte_mempool *
mbuf_pool_find(unsigned int sock_id) {

    int rc;
    char pool_name[RTE_MEMPOOL_NAMESIZE];

    rc = mbuf_poolname_build(sock_id, pool_name, sizeof(pool_name));
    if (0 != rc)
        return NULL;

    return (rte_mempool_lookup((const char *) pool_name));
}

#endif
