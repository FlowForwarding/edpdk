/**
 * Copyright (c) 2013 Tieto Global Oy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

#include <rte_log.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>

#include "pmdengine.h"

static int map_port_queue_stats_mapping_registers( uint8_t, struct rte_port *);
static int set_tx_queue_stats_mapping_registers( uint8_t, struct rte_port *);
static int set_rx_queue_stats_mapping_registers( uint8_t, struct rte_port *);
static void free_all_fwd_lcores(void);
static void free_fwd_lcore( uint8_t);
static int mbuf_pool_create( uint16_t, unsigned int, unsigned int);
static void mbuf_pool_ctor(struct rte_mempool *, void *);
static void mbuf_ctor(struct rte_mempool *, void *, void *,
        __attribute__((unused)) unsigned);
static int stop_port_atomic(struct rte_port *);
static int start_port_atomic(struct rte_port *);
static void set_port_promisc_mode( uint8_t);
static void set_all_ports_promisc_mode(void);
static void check_ports_link_status( uint8_t, uint32_t);
static int is_mbuf_pools_initialized(void);
static int is_all_ports_started(void);
static int flush_fwd_rx_queues(void);
static int get_fwd_port_id( uint8_t, uint8_t *);
static int parse_args_helper(char *, unsigned int);
static struct fwd_lcore * get_fwd_lcore(unsigned int);
static int lcore_recv_pkts(struct fwd_context *);
static int lcore_xmit_pkts(struct fwd_context *);
static int run_fwd_context(void *);
static void free_all_fwd_ports(void);
static struct fwd_context * get_fwd_context(unsigned int);

/* All ports/ethernet hw data & configuration */
static struct ports_data ports_d;
/* All lcores data & configuration */
static struct lcores_data lcores_d;
static struct fwd_context *fwd_contexts[FWD_CONTEXT_MAX];
static unsigned int num_fwd_contexts;
static struct rte_mempool * pktmbuf_pool = NULL;

int pe_init(void) {
    memset(fwd_contexts, 0, FWD_CONTEXT_MAX);

    return pe_init_ports();
}

/**
 * Initialization of ports can be overriden
 * whenever necessary.
 */
int pe_init_ports(void) {
    struct rte_port * port;
    unsigned int index;

    rte_set_log_type(RTE_LOGTYPE_PMDENGINE, 1);

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);

    if (!is_mbuf_pools_initialized()) {
        RTE_LOG(ERR, PMDENGINE, "Mbuf pools are not initialized\n");
        return -1;
    }

    /* Save probed ports */
    ports_d.num_probed_ports = rte_eth_dev_count();
    if (ports_d.num_probed_ports <= 0)
        return -1;

    /* port configuration variables */
    ports_d.driver_d.rx_mode.max_rx_pkt_len = ETHER_MAX_LEN;
    ports_d.driver_d.rx_mode.split_hdr_size = 0;
    ports_d.driver_d.rx_mode.header_split = 0;
    ports_d.driver_d.rx_mode.hw_ip_checksum = 0;
    ports_d.driver_d.rx_mode.hw_vlan_filter = 1;
    ports_d.driver_d.rx_mode.hw_vlan_strip = 1;
    ports_d.driver_d.rx_mode.hw_vlan_extend = 0;
    ports_d.driver_d.rx_mode.jumbo_frame = 0;
    ports_d.driver_d.rx_mode.hw_strip_crc = 0;
    ports_d.driver_d.rx_thresh.pthresh = RX_PTHRESH;
    ports_d.driver_d.rx_thresh.hthresh = RX_HTHRESH;
    ports_d.driver_d.rx_thresh.wthresh = RX_WTHRESH;
    ports_d.driver_d.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6;
    ports_d.driver_d.rx_drop_en = 0;
    ports_d.driver_d.tx_free_thresh = 0;
    ports_d.driver_d.tx_rs_thresh = 0;
    ports_d.driver_d.txq_flags = 0;
    ports_d.driver_d.num_rxq = 1;
    ports_d.driver_d.num_txq = 1;
    ports_d.driver_d.num_rxd = RTE_TEST_RX_DESC_DEFAULT;
    ports_d.driver_d.num_txd = RTE_TEST_TX_DESC_DEFAULT;
    ports_d.driver_d.no_flush_rx = 0;

    ports_d.num_fwd_ports = ports_d.num_probed_ports;
    ports_d.num_tx_queue_stats_mappings = 0;
    ports_d.num_rx_queue_stats_mappings = 0;
    ports_d.num_pkt_per_burst = DEF_PKT_BURST;
    ports_d.tx_queue_stats_mappings = ports_d.tx_queue_stats_mappings_array;
    ports_d.rx_queue_stats_mappings = ports_d.rx_queue_stats_mappings_array;

    RTE_LOG(INFO, PMDENGINE, "  Probed %d port(s)\n", ports_d.num_probed_ports);

    /* save port ids */
    for (index = 0; index < ports_d.num_probed_ports; index++) {
        ports_d.fwd_ports_ids[index] = (uint8_t) index;
        RTE_LOG(INFO, PMDENGINE, "    port: %d\n", index);
        RTE_LOG(INFO, PMDENGINE, "      id: %d\n", index);
        RTE_LOG(INFO, PMDENGINE, "      socket id: %d\n",
                rte_eth_dev_socket_id(index));
    }

    ports_d.rte_ports = rte_zmalloc("ports_d.rte_ports",
            sizeof(struct rte_port) * ports_d.num_probed_ports,
            CACHE_LINE_SIZE);

    if (NULL == ports_d.rte_ports)
        return -1;

    /* configure ports */
    for (index = 0; index < ports_d.num_probed_ports; index++) {
        port = &(ports_d.rte_ports[index]);
        rte_eth_dev_info_get(index, &port->dev_info);
        port->need_reconfig = 1;
        port->need_reconfig_queues = 1;
    }

    for (index = 0; index < ports_d.num_probed_ports; index++) {
        port = &(ports_d.rte_ports[index]);
        port->dev_conf.rxmode = ports_d.driver_d.rx_mode;
        port->dev_conf.fdir_conf = ports_d.fdir_conf;

        if (ports_d.driver_d.num_rxq > 0) {
            port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
            port->dev_conf.rx_adv_conf.rss_conf.rss_hf =
                    ports_d.driver_d.rss_hf;
        } else {
            port->dev_conf.rx_adv_conf.rss_conf.rss_key = NULL;
            port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
        }

        port->rx_conf.rx_thresh = ports_d.driver_d.rx_thresh;
        port->rx_conf.rx_free_thresh = ports_d.driver_d.rss_hf;
        port->rx_conf.rx_drop_en = ports_d.driver_d.rx_drop_en;
        port->tx_conf.tx_thresh = ports_d.driver_d.tx_thresh;
        port->tx_conf.tx_rs_thresh = ports_d.driver_d.tx_rs_thresh;
        port->tx_conf.tx_free_thresh = ports_d.driver_d.tx_free_thresh;
        port->tx_conf.txq_flags = ports_d.driver_d.txq_flags;

        rte_eth_macaddr_get(index, &port->eth_addr);

        map_port_queue_stats_mapping_registers(index, port);
    }

    return 0;
}

/**
 *
 */
int pe_init_lcores(void) {

    unsigned int num_probed_lcores, index, num_mbuf_per_pool;
    int rc;
    struct rte_mempool * mempool;

    num_probed_lcores = 0;
    rc = 0;

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);
    RTE_LOG(INFO, PMDENGINE, "  Probing lcore(s)\n");

    for (index = 0; index < RTE_MAX_LCORE; index++) {
        if (!rte_lcore_is_enabled(index))
            continue;
        if (index == rte_get_master_lcore())
            continue;

        RTE_LOG(INFO, PMDENGINE, "  Lcore %d\n", num_probed_lcores);
        lcores_d.fwd_lcores_cpuids[num_probed_lcores++] = index;
        RTE_LOG(INFO, PMDENGINE, "     cpuid: %d\n", index);
    }
    RTE_LOG(INFO, PMDENGINE, "  Probed %d lcore(s)\n", num_probed_lcores);

    lcores_d.mbuf_mempool_cache = DEF_PKT_BURST;
    lcores_d.mbuf_data_size = DEFAULT_MBUF_DATA_SIZE;
    lcores_d.socket_num = UMA_NO_CONFIG;
    lcores_d.num_probed_lcores = num_probed_lcores;
    /* make this configurable - TODO(pepe) */
    lcores_d.num_fwd_lcores = 1;

    lcores_d.fwd_lcores = rte_zmalloc("lcores_d.fwd_lcores",
            sizeof(struct fwd_lcore *) * lcores_d.num_probed_lcores,
            CACHE_LINE_SIZE);

    if (NULL == lcores_d.fwd_lcores) {
        RTE_LOG(ERR, PMDENGINE, "Failed to allocate lcores\n");
        return -1;
    }

    /* Allocate each lcore */
    for (index = 0; index < lcores_d.num_probed_lcores; index++) {
        lcores_d.fwd_lcores[index] = rte_zmalloc("lcores_d.fwd_lcores",
                sizeof(struct fwd_lcore), CACHE_LINE_SIZE);

        if (NULL == lcores_d.fwd_lcores[index]) {
            /* Free allocated cores */
            free_all_fwd_lcores();
            RTE_LOG(ERR, PMDENGINE, "Failed to allocate each lcore\n");
            return -1;
        }
        lcores_d.fwd_lcores[index]->cpuid = lcores_d.fwd_lcores_cpuids[index];
    }

    num_mbuf_per_pool = RTE_TEST_RX_DESC_MAX + RTE_TEST_TX_DESC_MAX
            + MAX_PKT_BURST;

    num_mbuf_per_pool = (num_mbuf_per_pool * ports_d.num_probed_ports);

    if (lcores_d.socket_num == UMA_NO_CONFIG)
        rc = mbuf_pool_create(lcores_d.mbuf_data_size, num_mbuf_per_pool, 0);
    else
        rc = mbuf_pool_create(lcores_d.mbuf_data_size, num_mbuf_per_pool,
                lcores_d.socket_num);

    if (OK != rc) {
        free_all_fwd_lcores();
        RTE_LOG(ERR, PMDENGINE,
                "Failed to allocate mbuf memory pool for lcores\n");
        return -1;
    }

    /* Assign mbuf pool to lcores */
    for (index = 0; index < lcores_d.num_probed_lcores; index++) {

        mempool = mbuf_pool_find(rte_lcore_to_socket_id(index));
        if (NULL == mempool)
            mempool = mbuf_pool_find(0);

        if (NULL != lcores_d.fwd_lcores)
            lcores_d.fwd_lcores[index]->mbuf_pool = mempool;
    }

    return 0;
}

/**
 *
 */
int pe_start_ports(uint8_t portmask) {

    struct rte_port * port;
    unsigned int index;
    uint16_t qindex;
    int rc;

    rc = 0;

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);

    if (!is_mbuf_pools_initialized()) {
        RTE_LOG(ERR, PMDENGINE,
                "Can't start ports with uninitialized mbuf pools\n");
        return -1;
    }

    for (index = 0; index < ports_d.num_probed_ports; index++) {

        if (portmask < ports_d.num_probed_ports && portmask != index)
            continue;

        port = &(ports_d.rte_ports[index]);

        if (OK != stop_port_atomic(port))
            continue;

        if (port->need_reconfig > 0) {
            port->need_reconfig = 0;

            rc = rte_eth_dev_configure(index, ports_d.driver_d.num_rxq,
                    ports_d.driver_d.num_txq, &(port->dev_conf));

            if (OK != rc) {
                stop_port_atomic(port);
                RTE_LOG(WARNING, PMDENGINE, "Failed to configure port %d\n",
                        index);
                /* try to reconfigure port next time */
                port->need_reconfig = 1;
                return -1;
            }
        }

        /* Configure queues */
        if (port->need_reconfig_queues > 0) {
            port->need_reconfig_queues = 0;

            for (qindex = 0; qindex < ports_d.driver_d.num_txq; qindex++) {

                rc = rte_eth_tx_queue_setup(index, qindex,
                        ports_d.driver_d.num_txd, port->socket_id,
                        &(port->tx_conf));

                if (OK == rc)
                    continue;

                /* Fail to setup tx queue, return */
                if (OK != stop_port_atomic(port)) {
                    RTE_LOG(WARNING, PMDENGINE,
                            "Failed to configure port %d tx queues\n", index);
                    /* try to reconfigure queues next time */
                    port->need_reconfig_queues = 1;
                    return -1;
                }
            }

            for (qindex = 0; qindex < ports_d.driver_d.num_rxq; qindex++) {

                rc = rte_eth_rx_queue_setup(index, qindex,
                        ports_d.driver_d.num_rxd, port->socket_id,
                        &(port->rx_conf), mbuf_pool_find(port->socket_id));

                if (rc == 0)
                    continue;

                if (OK != stop_port_atomic(port))
                    RTE_LOG(WARNING, PMDENGINE,
                            "Failed to configure port %d rx queues\n", index);

                /* try to reconfigure queues next time */
                port->need_reconfig_queues = 1;
                return -1;
            }
        }

        rc = rte_eth_dev_start(index);
        if (rc < 0) {

            RTE_LOG(WARNING, PMDENGINE, "Failed to start port %d\n", index);
            stop_port_atomic(port);
            continue;
        }

        if (OK != start_port_atomic(port))
            RTE_LOG(WARNING, PMDENGINE, "Failed to start port %d\n", index);

    }

    check_ports_link_status(ports_d.num_probed_ports, ALL_PORTS_MASK);

    set_all_ports_promisc_mode();

    return 0;
}

#define RX_OPT          0
#define TX_OPT          1

/**
 * Fill fwd contexts
 */
int pe_parse_args(int argc, char ** argv, int argindex) {

    int opt, opt_index, rc;
    const char * optname;
    static struct option lgopts[] = { { "rx", required_argument, 0, RX_OPT }, {
            "tx", required_argument, 0, TX_OPT } };

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);

    rc = -1;
    argc -= argindex;
    argv += argindex;

    while (EOF != (opt = getopt_long(argc, argv, "", lgopts, &opt_index))) {
        switch (opt) {
        case RX_OPT:
            optname = lgopts[opt_index].name;
            if (OK == strcmp(optname, "rx")) {
                rc = parse_args_helper(optarg, RX_OPT);
            }
            break;
        case TX_OPT:
            optname = lgopts[opt_index].name;
            if (OK == strcmp(optname, "tx")) {
                rc = parse_args_helper(optarg, TX_OPT);
            }
            break;
        default:
            break;
        }
    }
    return rc;
}

/**
 * lcore_id1:port1:port2:portN,lcore_idN:...
 * e.g.
 *    "1:0:1,2:2:3"
 */
static int parse_args_helper(char *arg, unsigned int opt) {

#define MAX_TOKENS         50
#define MAX_ARG_LEN        100
    char *level1_tokens[MAX_TOKENS];
    char *level2_tokens[MAX_TOKENS];
    int arglen;
    unsigned int index1, index2, num_tokens1, num_tokens2, lcore_index;
    struct fwd_port * fwdp = NULL;
    char * name = NULL;
    struct rxtx_ring_pair * ring_pair = NULL;
    uint8_t pid;

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);

    RTE_LOG(INFO, PMDENGINE, "  Construct fwd contexts (%s) using: %s\n",
            ((RX_OPT == opt) ? "rx" : "tx"), arg);

    if (NULL == arg)
        return -1;

    memset(level1_tokens, 0, MAX_TOKENS);
    memset(level2_tokens, 0, MAX_TOKENS);

    arglen = strnlen(arg, MAX_ARG_LEN);

    if (arglen <= 0)
        return -1;

    /* Construct fwd_contexts using user config. */
    num_tokens1 = rte_strsplit(arg, arglen, level1_tokens, MAX_TOKENS, ',');
    num_fwd_contexts = num_tokens1;

    for (index1 = 0; index1 < num_tokens1; index1++) {
        arglen = strnlen(level1_tokens[index1], MAX_ARG_LEN);
        num_tokens2 = rte_strsplit(level1_tokens[index1], arglen, level2_tokens,
        MAX_TOKENS, ':');

        index2 = 0;

        /* first token is the lcore id, succeeding are the ports */

        /* Assign lcore id */
        RTE_LOG(INFO, PMDENGINE, "  context %d:\n", index1);
        lcore_index = atoi(level2_tokens[index2]);
        RTE_LOG(INFO, PMDENGINE, "    lcore cpu id %d:\n",
                get_fwd_lcore(lcore_index)->cpuid);

        if (lcore_index >= FWD_CONTEXT_MAX)
            return -1;

        /* fwd contexts are indexed by lcore indices */
        if (NULL == fwd_contexts[lcore_index]) {
            /* Use rte malloc - TODO(pepe) */
            fwd_contexts[lcore_index] = malloc(sizeof(struct fwd_context));
            memset(fwd_contexts[lcore_index], 0, sizeof(struct fwd_context));
            memset(fwd_contexts[lcore_index]->ports, 0, FWD_CONTEXT_PORTS_MAX);
            fwd_contexts[lcore_index]->lcore = get_fwd_lcore(lcore_index);
        }

        for (index2 += 1; index2 < num_tokens2; index2++) {

            /* Construct Fwd ports */

            pid = atoi(level2_tokens[index2]);

            /* fwd ports are indexed by port ids */
            if (NULL == fwd_contexts[lcore_index]->ports[pid]) {

                /* Use rte_zmalloc ? - TODO(pepe) */
                name = malloc(MSG_QUEUE_NAME_CHARS_MAX);
                if (NULL == name) {
                    RTE_LOG(ERR, PMDENGINE,
                            "Failed to allocate msg queue name\n");
                    return -1;
                }
                memset(name, 0, RXTX_RING_NAME_CHARS_MAX);

                /* Use rte_zmalloc ? - TODO(pepe) */
                fwdp = malloc(sizeof(struct fwd_port));
                if (NULL == fwdp) {
                    RTE_LOG(ERR, PMDENGINE, "Failed to allocate fwd port\n");
                    return -1;
                }

                fwdp->rxtx_rings = NULL;
                fwdp->pid = pid;
                fwdp->rxq = 0;
                fwdp->txq = 0;

                if (NULL == fwdp->rxtx_rings) {
                    /* How to destroy rings ? - TODO(pepe) */
                    ring_pair = malloc(sizeof(struct rxtx_ring_pair));
                    memset(ring_pair, 0, sizeof(struct rxtx_ring_pair));
                    fwdp->rxtx_rings = ring_pair;
                }

                /* Check return value - TODO(pepe). port id will make it unique,
                 * assuming there is only one rxtx ring per port */
                if (NULL == fwdp->rxtx_rings->recv_ring) {
                    rte_snprintf(name, RXTX_RING_NAME_CHARS_MAX,
                            "rxtx_ring_recv_%u", fwdp->pid);
                    RTE_LOG(INFO, PMDENGINE, "      recv_ring: %s\n", name);
                    ring_pair->recv_ring = rte_ring_create(name,
                    MSG_QUEUE_SIZE, rte_socket_id(),
                            RING_F_SP_ENQ | RING_F_SC_DEQ);

                }

                if (NULL == fwdp->rxtx_rings->xmit_ring) {

                    memset(name, 0, RXTX_RING_NAME_CHARS_MAX);
                    rte_snprintf(name, RXTX_RING_NAME_CHARS_MAX,
                            "rxtx_ring_xmit_%u", fwdp->pid);
                    RTE_LOG(INFO, PMDENGINE, "      xmit_ring: %s\n", name);
                    ring_pair->xmit_ring = rte_ring_create(name,
                    MSG_QUEUE_SIZE, rte_socket_id(),
                            RING_F_SP_ENQ | RING_F_SC_DEQ);
                }

                fwd_contexts[lcore_index]->ports[pid] = fwdp;

            } else {
                fwdp = fwd_contexts[lcore_index]->ports[pid];
            }

            RTE_LOG(INFO, PMDENGINE, "      id: %d\n", fwdp->pid);

            if (RX_OPT == opt) {
                RTE_LOG(INFO, PMDENGINE, "    rx ports\n");
                fwd_contexts[lcore_index]->rx_ports[fwd_contexts[lcore_index]->num_rx_ports++] =
                        pid;
            } else if (TX_OPT == opt) {
                RTE_LOG(INFO, PMDENGINE, "    tx ports\n");
                fwd_contexts[lcore_index]->tx_ports[fwd_contexts[lcore_index]->num_tx_ports++] =
                        pid;
            }

            if (NULL != name)
                free(name);

        }

        RTE_LOG(INFO, PMDENGINE, "    num rx ports: %d\n",
                fwd_contexts[lcore_index]->num_rx_ports);
        RTE_LOG(INFO, PMDENGINE, "    num tx ports: %d\n",
                fwd_contexts[lcore_index]->num_tx_ports);
    }

    return 0;
}

/**
 *
 */
int pe_start_pmdengine(void) {

    int rc;
    unsigned int index;
    uint8_t pt_id;
    struct rte_port * port;
    struct fwd_context *fwc;

    rc = 0;
    pt_id = 0;

    if (!is_all_ports_started()) {
        RTE_LOG(ERR, PMDENGINE, "Some ports weren't started\n");
        return -1;
    }

    if (!ports_d.driver_d.no_flush_rx) {
        rc = flush_fwd_rx_queues();
        if (OK != rc)
            return -1;
    }

    /* Setup stats */
    for (index = 0; index < ports_d.num_fwd_ports; index++) {
        if (OK != rc)
            return -1;

        port = get_rte_port(pt_id);
        rte_eth_stats_get(pt_id, &port->stats);
        port->tx_dropped = 0;

        rc = map_port_queue_stats_mapping_registers(pt_id, port);
        if (OK != rc)
            return -1;
    }

    /* Launch lcores per fwd context */
    for (index = 0; index < num_fwd_contexts; index++) {

        fwc = fwd_contexts[index];

        if (fwc->lcore->cpuid != rte_lcore_id()) {

            if (fwc->num_rx_ports == 0 && fwc->num_tx_ports == 0)
                continue;

            RTE_LOG(INFO, PMDENGINE, "Launching forward context: %d\n", index);
            fwc->lcore->stopped = 0;
            rc = rte_eal_remote_launch(run_fwd_context, fwc, fwc->lcore->cpuid);

            if (OK != 0)
                RTE_LOG(WARNING, PMDENGINE,
                        "Failed to launch lcore %u (rc, %d)\n", index, rc);
        }
    }

    return 0;
}

/**
 *
 */
static int run_fwd_context(void *fwd_arg) {
    struct fwd_context *fwc;
    int rc = 0;

    fwc = (struct fwd_context *) fwd_arg;

    do {
        rc = lcore_recv_pkts(fwc);
        rc = lcore_xmit_pkts(fwc);
    } while (OK == rc);

    return 0;
}

/**
 *
 */
static int lcore_recv_pkts(struct fwd_context *fwc) {

    uint16_t num_recv_pkts, num_qd_pkts;
    unsigned int index, pid;
    struct fwd_port * port = NULL;
    struct rte_mbuf *rpackets[MAX_PKT_BURST];
    int rc;

    /* Receive packets and queue, per port */
    for (index = 0; index < fwc->num_rx_ports; index++) {

        rc = 0;
        num_qd_pkts = 0;
        num_recv_pkts = 0;

        pid = fwc->rx_ports[index];

        port = fwc->ports[pid];
        if (NULL == port)
            continue;

        num_recv_pkts = rte_eth_rx_burst(port->pid, port->rxq, rpackets,
                ports_d.num_pkt_per_burst);

        if (unlikely(num_recv_pkts == 0))
            continue;

        RTE_LOG(INFO, PMDENGINE, "got packets\n");

        do {
            /* Will attempt to enqueue all recv pkts */
            rc = rte_ring_sp_enqueue_burst(port->rxtx_rings->xmit_ring,
                    (void **) rpackets, num_recv_pkts);

            num_qd_pkts += rc;

        } while (num_qd_pkts < num_recv_pkts);

        port->rx_pkts += num_recv_pkts;
    }

    return 0;
}

/**
 *
 */
static int lcore_xmit_pkts(struct fwd_context *fwc) {

    void *xpackets[MAX_PKT_BURST];
    uint16_t num_tx_pkts;
    struct fwd_port *port;
    unsigned int index, pid;
    unsigned int unsent_pkts;
    int rc;

    rc = 0;

    for (index = 0; index < fwc->num_tx_ports; index++) {

        pid = fwc->tx_ports[index];

        port = fwc->ports[pid];
        if (NULL == port)
            continue;

        rc = rte_ring_sc_dequeue_burst(port->rxtx_rings->recv_ring, xpackets,
                ports_d.num_pkt_per_burst);

        if (0 == rc)
            continue;

        RTE_LOG(INFO, PMDENGINE, "sending packets\n");

        num_tx_pkts = rte_eth_tx_burst(port->pid, port->txq,
                (struct rte_mbuf **) xpackets, rc);
        RTE_LOG(INFO, PMDENGINE, "Sent(%d, %d)\n", index, num_tx_pkts);

        port->tx_pkts += num_tx_pkts;

        if (unlikely(num_tx_pkts < ports_d.num_pkt_per_burst)) {
            unsent_pkts = ports_d.num_pkt_per_burst - num_tx_pkts;
            port->dropped += unsent_pkts;
            for (index = num_tx_pkts; index < unsent_pkts; index++) {
                rte_pktmbuf_free(xpackets[index]);
            }
        }

    }

    return 0;
}

/**
 *
 */
static int map_port_queue_stats_mapping_registers(uint8_t pi,
        struct rte_port * port) {
    int rc;

    rc = 0;

    rc = set_tx_queue_stats_mapping_registers(pi, port);
    if (OK != rc) {
        if (rc == -ENOTSUP) {
            port->tx_queue_stats_mapping_enabled = 0;
            RTE_LOG(WARNING, EAL,
                    "TX queue stats mapping not supported for port %d", pi);
        } else {
            RTE_LOG(ERR, PMDENGINE, "Failed to map queue statistics");
            return -1;
        }
    }

    rc = set_rx_queue_stats_mapping_registers(pi, port);
    if (OK != rc) {
        if (rc == -ENOTSUP) {
            port->rx_queue_stats_mapping_enabled = 0;
            RTE_LOG(WARNING, EAL,
                    "RX queue stats mapping not supported for port %d", pi);
        } else {
            RTE_LOG(ERR, PMDENGINE, "Failed to map queue statistics");
            return -1;
        }
    }

    return 0;
}

/**
 *
 */
static int set_tx_queue_stats_mapping_registers(uint8_t port_id,
        struct rte_port *port) {

    uint16_t index;
    int rc;
    uint8_t mapping_found = 0;

    for (index = 0; index < ports_d.num_tx_queue_stats_mappings; index++) {
        if ((ports_d.tx_queue_stats_mappings[index].port_id == port_id)
                && (ports_d.tx_queue_stats_mappings[index].queue_id
                        < ports_d.driver_d.num_txq)) {
            rc = rte_eth_dev_set_tx_queue_stats_mapping(port_id,
                    ports_d.tx_queue_stats_mappings[index].queue_id,
                    ports_d.tx_queue_stats_mappings[index].stats_counter_id);
            if (rc != 0)
                return rc;
            mapping_found = 1;
        }
    }
    if (mapping_found)
        port->tx_queue_stats_mapping_enabled = 1;
    return 0;
}

/**
 *
 */
static int set_rx_queue_stats_mapping_registers(uint8_t port_id,
        struct rte_port *port) {
    uint16_t i;
    int rc;
    uint8_t mapping_found = 0;

    for (i = 0; i < ports_d.num_rx_queue_stats_mappings; i++) {
        if ((ports_d.rx_queue_stats_mappings[i].port_id == port_id)
                && (ports_d.rx_queue_stats_mappings[i].queue_id
                        < ports_d.driver_d.num_rxq)) {
            rc = rte_eth_dev_set_rx_queue_stats_mapping(port_id,
                    ports_d.rx_queue_stats_mappings[i].queue_id,
                    ports_d.rx_queue_stats_mappings[i].stats_counter_id);
            if (rc != 0)
                return rc;
            mapping_found = 1;
        }
    }
    if (mapping_found)
        port->rx_queue_stats_mapping_enabled = 1;
    return 0;
}

/**
 *
 */
unsigned int pe_get_num_probed_ports(void) {
    return ports_d.num_probed_ports;
}

/**
 *
 */
static void free_all_fwd_lcores(void) {
    uint8_t index;

    for (index = 0; index < lcores_d.num_probed_lcores; index++)
        free_fwd_lcore(index);

    if (lcores_d.fwd_lcores) {
        rte_free(lcores_d.fwd_lcores);
        lcores_d.fwd_lcores = NULL;
    }
}

/**
 *
 */
static void free_fwd_lcore(uint8_t index) {
    if (NULL != lcores_d.fwd_lcores[index]) {
        rte_free(lcores_d.fwd_lcores[index]);
        lcores_d.fwd_lcores[index] = NULL;
    }
}

/*
 *
 */
static void free_all_fwd_ports(void) {
    unsigned int index1, index2;
    struct fwd_port ** ports;

    for (index1 = 0; index1 < num_fwd_contexts; index1++) {

        ports = fwd_contexts[index1]->ports;

        if (NULL != ports)
            for (index2 = 0; index2 < fwd_contexts[index1]->num_fwd_ports;
                    index2++) {
                free(ports[index2]);
                ports[index2] = NULL;
            }
    }
}

/**
 *
 */
static int mbuf_pool_create(uint16_t mbuf_seg_size, unsigned int num_mbuf,
        unsigned int socket_id) {

    int rc;
    char pool_name[RTE_MEMPOOL_NAMESIZE];
    struct rte_mempool *rte_mp;
    struct mbuf_pool_ctor_arg mbp_ctor_arg;
    struct mbuf_ctor_arg mb_ctor_arg;
    uint32_t mb_size;

    mbp_ctor_arg.seg_buf_size = (uint16_t)(
            RTE_PKTMBUF_HEADROOM + mbuf_seg_size);
    mb_ctor_arg.seg_buf_offset = (uint16_t) CACHE_LINE_ROUNDUP(
            sizeof(struct rte_mbuf));
    mb_ctor_arg.seg_buf_size = mbp_ctor_arg.seg_buf_size;
    mb_size = mb_ctor_arg.seg_buf_offset + mb_ctor_arg.seg_buf_size;

    rc = mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name));
    if (OK != rc)
        return -1;

    rte_mp = rte_mempool_create(pool_name, num_mbuf, (unsigned) mb_size,
            (unsigned) lcores_d.mbuf_mempool_cache,
            sizeof(struct rte_pktmbuf_pool_private), mbuf_pool_ctor,
            &mbp_ctor_arg, mbuf_ctor, &mb_ctor_arg, socket_id, 0);
    if (NULL == rte_mp) {
        RTE_LOG(ERR, PMDENGINE, "Failed to allocate mbuf pool for socket %u\n",
                socket_id);
        return -1;
    }

    return 0;
}

/**
 *
 */
static void mbuf_pool_ctor(struct rte_mempool *mp, void *opaque_arg) {
    struct mbuf_pool_ctor_arg *mbp_ctor_arg;
    struct rte_pktmbuf_pool_private *mbp_priv;

    if (mp->private_data_size < sizeof(struct rte_pktmbuf_pool_private)) {

        RTE_LOG(WARNING, PMDENGINE,
                "Private data size is less than private data of mbuf pool");
        return;
    }
    mbp_ctor_arg = (struct mbuf_pool_ctor_arg *) opaque_arg;
    mbp_priv = (struct rte_pktmbuf_pool_private *) ((char *) mp
            + sizeof(struct rte_mempool));
    mbp_priv->mbuf_data_room_size = mbp_ctor_arg->seg_buf_size;
}

/**
 *
 */
static void mbuf_ctor(struct rte_mempool *mp, void *opaque_arg, void *raw_mbuf,
        __attribute__((unused)) unsigned i) {
    struct mbuf_ctor_arg *mb_ctor_arg;
    struct rte_mbuf *mb;

    mb_ctor_arg = (struct mbuf_ctor_arg *) opaque_arg;
    mb = (struct rte_mbuf *) raw_mbuf;

    mb->type = RTE_MBUF_PKT;
    mb->pool = mp;
    mb->buf_addr = (void *) ((char *) mb + mb_ctor_arg->seg_buf_offset);
    mb->buf_physaddr = (uint64_t)(
            rte_mempool_virt2phy(mp, mb) + mb_ctor_arg->seg_buf_offset);
    mb->buf_len = mb_ctor_arg->seg_buf_size;
    mb->type = RTE_MBUF_PKT;
    mb->ol_flags = 0;
    mb->pkt.data = (char *) mb->buf_addr + RTE_PKTMBUF_HEADROOM;
    mb->pkt.nb_segs = 1;
    mb->pkt.vlan_macip.data = 0;
    mb->pkt.hash.rss = 0;
}

/**
 *
 */
void pe_free_pmd_resources(void) {
    free_all_fwd_lcores();
    free_all_fwd_ports();
}

/**
 *
 */
static int stop_port_atomic(struct rte_port *port) {

    if (rte_atomic16_cmpset(&(port->port_status), RTE_PORT_STOPPED,
    RTE_PORT_HANDLING) == 0)
        return -1;
    return 0;
}

/**
 *
 */
static int start_port_atomic(struct rte_port *port) {
    if (rte_atomic16_cmpset(&(port->port_status), RTE_PORT_HANDLING,
    RTE_PORT_STARTED) == 0)
        return -1;
    return 0;
}

/**
 *
 */
static void set_port_promisc_mode(uint8_t p) {
    rte_eth_promiscuous_enable(p);
}

/**
 *
 */
void set_all_ports_promisc_mode(void) {
    uint8_t pindex;

    for (pindex = 0; pindex < ports_d.num_probed_ports; pindex++)
        set_port_promisc_mode(pindex);
}

/**
 *
 */
static void check_ports_link_status(uint8_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    RTE_LOG(INFO, PMDENGINE, "Checking link status\n");
    /*fflush(stdout);*/
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
                    RTE_LOG(INFO, PMDENGINE, "  port %d (up, %d Mbps, %s)\n",
                            (uint8_t) portid, (unsigned) link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                                    ("full-duplex") : ("half-duplex"));
                else
                    RTE_LOG(WARNING, PMDENGINE, "  port %d (down)\n",
                            (uint8_t) portid);
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
            /*fflush(stdout);*/
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
        }
    }
}

/**
 * @briev Check if mbuf pools per socket is initialized
 * @return 1 if all mbuf pools are initialized, 0 otherwise
 */
static int is_mbuf_pools_initialized(void) {
    struct rte_port * port;
    int index;

    for (index = 0; index < ports_d.driver_d.num_rxq; index++) {
        port = &(ports_d.rte_ports[index]);
        if (NULL == mbuf_pool_find(port->socket_id))
            return 0;
    }
    return 1;
}

/**
 *
 */
static int is_all_ports_started(void) {
    uint8_t pi;
    struct rte_port *port;

    for (pi = 0; pi < ports_d.num_probed_ports; pi++) {
        port = &(ports_d.rte_ports[pi]);
        /* Check if there is a port which is not started */
        if (port->port_status != RTE_PORT_STARTED)
            return 0;
    }
    return 1;
}

/**
 *
 */
static int flush_fwd_rx_queues(void) {

    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint8_t rxp;
    uint8_t port_id;
    uint16_t rxq;
    uint16_t num_rx;
    uint16_t i;
    uint8_t j;
    int rc;

    rc = 0;

    for (j = 0; j < 2; j++) {
        for (rxp = 0; rxp < ports_d.num_fwd_ports; rxp++) {
            for (rxq = 0; rxq < ports_d.driver_d.num_rxq; rxq++) {
                rc = get_fwd_port_id(rxp, &port_id);
                if (OK != rc) {
                    RTE_LOG(ERR, PMDENGINE, "Failed to flush fwd rx queues\n");
                    return -1;
                }
                do {
                    /* Flush port queue */
                    num_rx = rte_eth_rx_burst(port_id, rxq, pkts_burst,
                    MAX_PKT_BURST);
                    for (i = 0; i < num_rx; i++)
                        rte_pktmbuf_free(pkts_burst[i]);
                } while (num_rx > 0);
            }
        }
        /* wait 10 milli-seconds before retrying */
        rte_delay_ms(10);
    }
    return 0;
}

/**
 *
 */
static int get_fwd_port_id(uint8_t index, uint8_t * pid) {
    if (RTE_MAX_ETHPORTS <= index) {
        RTE_LOG(ERR, PMDENGINE, "Invalid port id\n");
        return -1;
    }

    *pid = ports_d.fwd_ports_ids[index];
    return 0;
}

/**
 * Optimize - TODO(pepe)
 */
struct fwd_port * pe_get_fwd_port(unsigned int pid) {
    unsigned int index1, index2;
    struct fwd_context * fwdc = NULL;
    struct fwd_port * fwdp = NULL;

    /* fwd contexts are usually few in numbers */
    for (index1 = 0; index1 < FWD_CONTEXT_MAX; index1++) {
        fwdc = get_fwd_context(index1);
        if (fwdc == NULL)
            continue;

        for (index2 = 0; index2 < FWD_CONTEXT_PORTS_MAX; index2++) {
            fwdp = fwdc->ports[index2];
            if (NULL == fwdp)
                continue;
            if (fwdp->pid == pid) {
                return fwdp;
            }
        }

    }
    return NULL;
}

/**
 *
 */
static struct fwd_context * get_fwd_context(unsigned int index) {

    if (index >= FWD_CONTEXT_MAX)
        return NULL;

    return fwd_contexts[index];
}

/**
 *
 */
struct rte_port * get_rte_port(uint8_t pid) {
    if (pid >= ports_d.num_probed_ports)
        return NULL;

    return &ports_d.rte_ports[pid];
}

/**
 *
 */
struct fwd_lcore * get_fwd_lcore(unsigned int index) {
    if (index >= RTE_MAX_LCORE) {
        RTE_LOG(ERR, PMDENGINE, "Invalid index\n");
        return NULL;
    }
    return lcores_d.fwd_lcores[index];
}

/**
 *
 */
unsigned int get_num_fwd_contexts(void) {
    return num_fwd_contexts;
}

/**
 *
 */
struct rte_mbuf * pe_create_rte_mbuf(void * payload, unsigned int size,
        unsigned int port) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(pktmbuf_pool);

    if (NULL == m)
        return NULL;

    if (NULL == rte_memcpy(m->pkt.data, payload, size))
        return NULL;

    m->pkt.nb_segs = 1;
    m->pkt.next = NULL;
    m->pkt.pkt_len = (uint16_t) size;
    m->pkt.data_len = (uint16_t) size;
    m->pkt.in_port = port;
    return m;
}

/**
 *
 */
int pe_init_mempool(void) {

    RTE_LOG(INFO, PMDENGINE, "%s\n", __func__);

    pktmbuf_pool = rte_mempool_create("mbuf_pool", NUM_MBUF, MBUF_SIZE,
    MEMPOOL_CACHE_SIZE, sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
            rte_socket_id(), 0);

    if (pktmbuf_pool == NULL)
        return -1;

    return 0;
}

/**
 *
 */
uint16_t pe_get_num_pkt_per_burst(void) {
    return ports_d.num_pkt_per_burst;
}
