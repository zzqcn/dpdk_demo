/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_string_fns.h>

#include <rte_vect.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "public_api.h"

/* Log type */
#define RTE_LOGTYPE_L3FWD_GRAPH RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_RX_QUEUE_PER_LCORE 16

#define MAX_LCORE_PARAMS 32

#define NB_SOCKETS 8

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

static int numa_on = 1;   /**< NUMA is enabled by default. */
static int per_port_pool; /**< Use separate buffer pools per port; disabled */
                          /**< by default */

static volatile bool force_quit;

static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* Mask of enabled ports */
static uint32_t enabled_port_mask;

struct lcore_rx_queue
{
    uint16_t port_id;
    uint8_t queue_id;
    char node_name[RTE_NODE_NAMESIZE];
};

enum
{
    LCORE_TYPE_MASTER,
    LCORE_TYPE_RX,
    LCORE_TYPE_WORKER,
    LCORE_TYPE_MAX
};

/* Lcore conf */
struct lcore_conf
{
    int type;
    uint16_t n_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];

    struct rte_graph *graph;
    char name[RTE_GRAPH_NAMESIZE];
    rte_graph_t graph_id;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params
{
    int type;
    uint16_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

// clang-format off
static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 0, 1}, {1, 0, 0, 2}, {1, 0, 0, 3}
};
// clang-format on

static int lcore_type_map[RTE_MAX_LCORE] = {0, 1, 2, 2};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = RTE_DIM(lcore_params_array_default);

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS,
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
            .split_hdr_size = 0,
        },
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = NULL,
                    .rss_hf = ETH_RSS_IP,
                },
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];

static int check_lcore_params(void)
{
    uint8_t queue, lcore;
    int socketid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].type == LCORE_TYPE_RX) {
            queue = lcore_params[i].queue_id;
            if (queue >= MAX_RX_QUEUE_PER_PORT) {
                printf("Invalid queue number: %hhu\n", queue);
                return -1;
            }
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
            return -1;
        }

        if (lcore == rte_get_master_lcore()) {
            printf("Error: lcore %u is master lcore\n", lcore);
            return -1;
        }
        socketid = rte_lcore_to_socket_id(lcore);
        if ((socketid != 0) && (numa_on == 0)) {
            printf("Warning: lcore %hhu is on socket %d with numa off\n", lcore,
                   socketid);
        }
    }

    return 0;
}

static int check_port_config(void)
{
    uint16_t portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].type != LCORE_TYPE_RX)
            continue;

        portid = lcore_params[i].port_id;
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("Port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (!rte_eth_dev_is_valid_port(portid)) {
            printf("Port %u is not present on the board\n", portid);
            return -1;
        }
    }

    return 0;
}

static uint8_t get_port_n_rx_queues(const uint16_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].type != LCORE_TYPE_RX)
            continue;

        if (lcore_params[i].port_id == port) {
            if (lcore_params[i].queue_id == queue + 1)
                queue = lcore_params[i].queue_id;
            else
                rte_exit(EXIT_FAILURE,
                         "Queue ids of the port %d must be"
                         " in sequence and must start with 0\n",
                         lcore_params[i].port_id);
        }
    }

    return (uint8_t)(++queue);
}

static uint8_t get_port_n_tx_queues(const uint16_t port)
{
    uint8_t n = 0;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].type == LCORE_TYPE_RX)
            n++;
    }

    return n;
}

static int init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].type != LCORE_TYPE_RX) {
            continue;
        }

        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("Error: too many queues (%u) for lcore: %u\n",
                   (unsigned int)nb_rx_queue + 1, (unsigned int)lcore);
            return -1;
        }

        lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
            lcore_params[i].port_id;
        lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
            lcore_params[i].queue_id;
        lcore_conf[lcore].n_rx_queue++;
    }

    return 0;
}

/* Display usage */
static void print_usage(const char *prgname)
{
    fprintf(stderr,
            "%s [EAL options] --"
            " -p PORTMASK"
            " [-P]"
            " --config (port,queue,lcore)[,(port,queue,lcore)]"
            " [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
            " [--enable-jumbo [--max-pkt-len PKTLEN]]"
            " [--no-numa]"
            " [--per-port-pool]\n\n"

            "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
            "  -P : Enable promiscuous mode\n"
            "  --config (type,port,queue,lcore): lcore type & Rx queue "
            "configuration\n"
            "    type: 0-master, 1-rx, 2-worker\n"
            "  --enable-jumbo: Enable jumbo frames\n"
            "  --max-pkt-len: Under the premise of enabling jumbo,\n"
            "                 maximum packet length in decimal (64-9600)\n"
            "  --no-numa: Disable numa awareness\n"
            "  --per-port-pool: Use separate buffer pool per port\n\n",
            prgname);
}

static int parse_max_pkt_len(const char *pktlen)
{
    unsigned long len;
    char *end = NULL;

    /* Parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}

static int parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* Parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;

    return pm;
}

static int parse_config(const char *q_arg)
{
    enum fieldnames
    {
        FLD_TYPE = 0,
        FLD_PORT,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    const char *p, *p0 = q_arg;
    char *str_fld[_NUM_FLD];
    uint32_t size;
    char s[256];
    char *end;
    int i;

    nb_lcore_params = 0;

    while ((p = strchr(p0, '(')) != NULL) {
        ++p;
        p0 = strchr(p, ')');
        if (p0 == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        memcpy(s, p, size);
        s[size] = '\0';
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i])
                return -1;
        }

        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("Exceeded max number of lcore params: %hu\n",
                   nb_lcore_params);
            return -1;
        }

        if (int_fld[FLD_TYPE] >= LCORE_TYPE_MAX) {
            printf("invalid lcore type\n");
            return -1;
        }

        if (int_fld[FLD_PORT] >= RTE_MAX_ETHPORTS ||
            int_fld[FLD_LCORE] >= RTE_MAX_LCORE) {
            printf("Invalid port/lcore id\n");
            return -1;
        }

        if (int_fld[FLD_TYPE] == LCORE_TYPE_RX)
            lcore_type_map[int_fld[FLD_LCORE]] = LCORE_TYPE_RX;
        else
            lcore_type_map[int_fld[FLD_LCORE]] = LCORE_TYPE_WORKER;

        lcore_params_array[nb_lcore_params].type = int_fld[FLD_TYPE] & 0xf;
        lcore_params_array[nb_lcore_params].port_id =
            (uint8_t)int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id =
            (uint8_t)int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id =
            (uint8_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;

    return 0;
}

#define MAX_JUMBO_PKT_LEN 9600
#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
    "p:" /* portmask */
    "P"  /* promiscuous */
    ;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_PER_PORT_POOL "per-port-pool"
enum
{
    /* Long options mapped to a short option */

    /* First long only option value must be >= 256, so that we won't
     * conflict with short options
     */
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_CONFIG_NUM,
    CMD_LINE_OPT_NO_NUMA_NUM,
    CMD_LINE_OPT_ENABLE_JUMBO_NUM,
    CMD_LINE_OPT_PARSE_PER_PORT_POOL,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
    {CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
    {CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, CMD_LINE_OPT_ENABLE_JUMBO_NUM},
    {CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
    {NULL, 0, 0, 0},
};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports)                                                      \
    RTE_MAX((nports * nb_rx_queue * nb_rxd +                                 \
             nports * nb_lcores * RTE_GRAPH_BURST_SIZE +                     \
             nports * n_tx_queue * nb_txd + nb_lcores * MEMPOOL_CACHE_SIZE), \
            8192u)

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
    char *prgname = argv[0];
    int option_index;
    char **argvopt;
    int opt, ret;

    argvopt = argv;

    /* Error or normal output strings. */
    while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                              &option_index)) != EOF) {
        switch (opt) {
        /* Portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                fprintf(stderr, "Invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;

        case 'P':
            promiscuous_on = 1;
            break;

        /* Long options */
        case CMD_LINE_OPT_CONFIG_NUM:
            ret = parse_config(optarg);
            if (ret) {
                fprintf(stderr, "Invalid config\n");
                print_usage(prgname);
                return -1;
            }
            break;

        case CMD_LINE_OPT_NO_NUMA_NUM:
            numa_on = 0;
            break;

        case CMD_LINE_OPT_ENABLE_JUMBO_NUM: {
            const struct option lenopts = {"max-pkt-len", required_argument, 0,
                                           0};

            port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
            port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;

            /*
             * if no max-pkt-len set, use the default
             * value RTE_ETHER_MAX_LEN.
             */
            if (getopt_long(argc, argvopt, "", &lenopts, &option_index) == 0) {
                ret = parse_max_pkt_len(optarg);
                if (ret < 64 || ret > MAX_JUMBO_PKT_LEN) {
                    fprintf(stderr,
                            "Invalid maximum "
                            "packet length\n");
                    print_usage(prgname);
                    return -1;
                }
                port_conf.rxmode.max_rx_pkt_len = ret;
            }
            break;
        }

        case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
            printf("Per port buffer pool is enabled\n");
            per_port_pool = 1;
            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;
    ret = optind - 1;
    optind = 1; /* Reset getopt lib */

    return ret;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static int init_mem(uint16_t portid, uint32_t nb_mbuf)
{
    uint32_t lcore_id;
    int socketid;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
                     socketid, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[portid][socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d:%d", portid, socketid);
            /* Create a pool with priv size of a cacheline */
            pktmbuf_pool[portid][socketid] = rte_pktmbuf_pool_create(
                s, nb_mbuf, MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE,
                RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[portid][socketid] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
                         socketid);
            else
                printf("Allocated mbuf pool on socket %d\n", socketid);
        }
    }

    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    uint16_t portid;
    int ret;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid)
        {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                all_ports_up = 0;
                if (print_flag == 1)
                    printf("Port %u link get failed: %s\n", portid,
                           rte_strerror(-ret));
                continue;
            }
            /* Print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                        "Port%d Link Up. Speed %u Mbps "
                        "-%s\n",
                        portid, link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX)
                            ? ("full-duplex")
                            : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* Clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* After finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* Set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("Done\n");
        }
    }
}

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static void print_stats(void)
{
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
    const char clr[] = {27, '[', '2', 'J', '\0'};
    struct rte_graph_cluster_stats_param s_param;
    struct rte_graph_cluster_stats *stats;
    const char *pattern = "worker_*";

    /* Prepare stats object */
    memset(&s_param, 0, sizeof(s_param));
    s_param.f = stdout;
    s_param.socket_id = SOCKET_ID_ANY;
    s_param.graph_patterns = &pattern;
    s_param.nb_graph_patterns = 1;

    stats = rte_graph_cluster_stats_create(&s_param);
    if (stats == NULL)
        rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

    while (!force_quit) {
        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);
        rte_graph_cluster_stats_get(stats, 0);
        rte_delay_ms(1E3);
    }

    rte_graph_cluster_stats_destroy(stats);
}

/* Main processing loop */
static int graph_main_loop(void *conf)
{
    struct lcore_conf *qconf;
    struct rte_graph *graph;
    uint32_t lcore_id;

    RTE_SET_USED(conf);

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];
    graph = qconf->graph;

    if (!graph) {
        RTE_LOG(INFO, L3FWD_GRAPH, "Lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L3FWD_GRAPH, "Entering main loop on lcore %u, graph %s(%p)\n",
            lcore_id, qconf->name, graph);

    while (likely(!force_quit))
        rte_graph_walk(graph);

    return 0;
}

static int create_graphs()
{
    int ret;
    static const char *rx_patterns[] = {"rx", "dispatch"};
    static const char *worker_patterns[] = {"dequeue", "flow", "drop"};
    uint16_t nb_patterns;
    struct rte_graph_param graph_conf;
    struct lcore_conf *qconf;
    unsigned lcore_id;
    FILE *f;
    char fname[RTE_GRAPH_NAMESIZE + 4];


    memset(&graph_conf, 0, sizeof(graph_conf));

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        rte_graph_t graph_id;
        rte_edge_t i;

        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        qconf = &lcore_conf[lcore_id];

        /* Skip graph creation if no source exists */
        // if (!qconf->n_rx_queue)
        //     continue;
        if (qconf->type == LCORE_TYPE_MASTER)
            continue;
        else if (qconf->type == LCORE_TYPE_RX) {
            graph_conf.nb_node_patterns = RTE_DIM(rx_patterns);
            graph_conf.node_patterns = rx_patterns;
        } else if (qconf->type == LCORE_TYPE_WORKER) {
            graph_conf.nb_node_patterns = RTE_DIM(worker_patterns);
            graph_conf.node_patterns = worker_patterns;
        } else {
            return -1;
        }

        graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

        snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

        graph_id = rte_graph_create(qconf->name, &graph_conf);
        if (graph_id == RTE_GRAPH_ID_INVALID)
            rte_exit(EXIT_FAILURE,
                     "rte_graph_create(): graph_id invalid"
                     " for lcore %u\n",
                     lcore_id);

        sprintf(fname, "%s.dot", qconf->name);
        f = fopen(fname, "w");
        ret = rte_graph_export(qconf->name, f);
        if (ret != 0)
            return -1;
        fclose(f);

        qconf->graph_id = graph_id;
        qconf->graph = rte_graph_lookup(qconf->name);
        if (!qconf->graph)
            rte_exit(EXIT_FAILURE, "rte_graph_lookup(): graph %s not found\n",
                     qconf->name);
    }
}

int main(int argc, char **argv)
{
    /* Rewrite data of src and dst ether addr */
    uint8_t rewrite_data[2 * sizeof(struct rte_ether_addr)];
    uint8_t nb_rx_queue, queue, socketid;
    struct rte_eth_dev_info dev_info;
    uint32_t nb_ports;
    uint32_t n_tx_queue, nb_lcores;
    struct rte_eth_txconf *txconf;
    uint16_t queueid, portid, i;
    const char **node_patterns;
    struct lcore_conf *qconf;
    uint8_t rewrite_len;
    uint32_t lcore_id;
    int ret;

    /* Init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD_GRAPH parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params() failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues() failed\n");

    if (check_port_config() < 0)
        rte_exit(EXIT_FAILURE, "check_port_config() failed\n");

    nb_ports = rte_eth_dev_count_avail();
    nb_lcores = rte_lcore_count();

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        qconf = &lcore_conf[lcore_id];
        qconf->type = lcore_type_map[lcore_id];
    }

    /* Initialize all ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        struct rte_eth_conf local_port_conf = port_conf;

        /* Skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* Init port */
        printf("Initializing port %d ... ", portid);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = get_port_n_tx_queues(portid);
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue,
               n_tx_queue);

        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
            dev_info.flow_type_rss_offloads;
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
            port_conf.rx_adv_conf.rss_conf.rss_hf) {
            printf(
                "Port %u modified RSS hash function based on "
                "hardware support,"
                "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
                portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        ret = rte_eth_dev_configure(portid, nb_rx_queue, n_tx_queue,
                                    &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
                     ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot adjust number of descriptors: err=%d, "
                     "port=%d\n",
                     ret, portid);

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr(" Address:", &ports_eth_addr[portid]);
        printf(", ");

        /* Init memory */
        if (!per_port_pool) {
            /* portid = 0; this is *not* signifying the first port,
             * rather, it signifies that portid is ignored.
             */
            ret = init_mem(0, NB_MBUF(nb_ports));
        } else {
            ret = init_mem(portid, NB_MBUF(1));
        }
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem() failed\n");

        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            qconf = &lcore_conf[lcore_id];
            if (qconf->type != LCORE_TYPE_RX)
                continue;

            if (numa_on)
                socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            txconf = &dev_info.default_txconf;
            txconf->offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid,
                                         txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: err=%d, "
                         "port=%d\n",
                         ret, portid);
            queueid++;
        }

        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        if (lcore_type_map[lcore_id] != LCORE_TYPE_RX)
            continue;

        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        fflush(stdout);

        /* Init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            struct rte_eth_rxconf rxq_conf;

            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

            if (numa_on)
                socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            rte_eth_dev_info_get(portid, &dev_info);
            rxq_conf = dev_info.default_rxconf;
            rxq_conf.offloads = port_conf.rxmode.offloads;
            if (!per_port_pool)
                ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
                                             &rxq_conf,
                                             pktmbuf_pool[0][socketid]);
            else
                ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
                                             &rxq_conf,
                                             pktmbuf_pool[portid][socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: err=%d, "
                         "port=%d\n",
                         ret, portid);

            /* Add this queue node to its graph */
            snprintf(qconf->rx_queue_list[queue].node_name, RTE_NODE_NAMESIZE,
                     "ethdev_rx-%u-%u", portid, queueid);
        }
    }

    printf("\n");

    {
        struct rx_node_config rx_cfg;
        rx_cfg.port_id = 0;
        rx_cfg.queue_id = 0;
        ret = config_rx_node(&rx_cfg);
        if (ret != 0)
            return -1;

        struct dispatch_node_config dispatch_cfg;
        struct rte_ring *r;
        dispatch_cfg.pkt_queues[0] = r =
            rte_ring_create("pkt_queue_0", 1024, 0, 0);
        if (NULL == r)
            return -1;
        dispatch_cfg.pkt_queues[1] = r =
            rte_ring_create("pkt_queue_1", 1024, 0, 0);
        if (NULL == r)
            return -1;
        ret = config_dispatch_node(&dispatch_cfg);
        if (ret != 0)
            return -1;

        struct dequeue_node_config dequeue_cfg;
        dequeue_cfg.pkt_queues[0] = dispatch_cfg.pkt_queues[0];
        dequeue_cfg.pkt_queues[1] = dispatch_cfg.pkt_queues[1];
        ret = config_dequeue_node(&dequeue_cfg);
        if (ret != 0)
            return -1;
    }

    /* Start ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret,
                     portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    printf("\n");

    check_all_ports_link_status(enabled_port_mask);

    /* Graph Initialization */
    ret = create_graphs();
    if (ret != 0)
        return -1;

    memset(&rewrite_data, 0, sizeof(rewrite_data));
    rewrite_len = sizeof(rewrite_data);


    /* Launch per-lcore init on every slave lcore */
    rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MASTER);

    /* Accumulate and print stats on master until exit */
    if (rte_graph_has_stats_feature())
        print_stats();

    /* Wait for slave cores to exit */
    ret = 0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        ret = rte_eal_wait_lcore(lcore_id);
        /* Destroy graph */
        if (ret < 0 ||
            rte_graph_destroy(rte_graph_from_name(lcore_conf[lcore_id].name))) {
            ret = -1;
            break;
        }
    }
    free(node_patterns);

    /* Stop ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return ret;
}
