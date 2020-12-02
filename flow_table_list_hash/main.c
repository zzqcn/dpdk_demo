/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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

#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_jhash.h>

// #include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l2fwd.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

#define FLOW_MAX_DEFAULT (1 * 1024 * 1024)

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

static int numa_on = 1; /**< NUMA is enabled by default. */
static int parse_ptype; /**< Parse packet type using rx callback, and */
                        /**< disabled by default */

static unsigned flow_per_lcore = FLOW_MAX_DEFAULT;
static unsigned flow_bucket_ratio = 2;

/* Global variables. */

volatile bool force_quit;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

/* Used only in exact match mode. */
int ipv6; /**< ipv6 is false by default. */

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* flow table */
struct ipv4_5tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __attribute__((__packed__));

union flow_key
{
    struct
    {
        uint8_t pad0;
        uint8_t proto;
        uint16_t pad1;
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
    };
    xmm_t xmm;
};

struct flow
{
    union flow_key key;
    struct flow **prev_next; /**< hash桶链表项 */
    struct flow *next;       /**< hash桶链表项 */
};

#define FLOW_HASH_LIST_ADD_TAIL(p, tail)   \
    (p)->prev_next = &(tail);              \
    (p)->next = (tail);                    \
    (tail) = (p);                          \
    if (NULL != (p)->next) {               \
        (p)->next->prev_next = &(p)->next; \
    }

#define FLOW_HASH_LIST_DELETE(p)               \
    *(p)->prev_next = (p)->next;               \
    if (NULL != (p)->next) {                   \
        (p)->next->prev_next = (p)->prev_next; \
    }

// struct flow_value {
//     uint64_t pkt_cnt;
//     uint64_t byte_cnt;
// };


#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static rte_xmm_t mask_v4;

static inline xmm_t mask_key(void *key, xmm_t mask)
{
    __m128i data = _mm_loadu_si128((__m128i *)(key));
    return _mm_and_si128(data, mask);
}

// IPv4地址格式化
/* not defined under linux */
#ifndef NIPQUAD
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr)                                \
    (unsigned)((const unsigned char *)&addr)[0],     \
        (unsigned)((const unsigned char *)&addr)[1], \
        (unsigned)((const unsigned char *)&addr)[2], \
        (unsigned)((const unsigned char *)&addr)[3]
#endif

static void print_flow_key(const union flow_key *key)
{
    printf(NIPQUAD_FMT ":%u " NIPQUAD_FMT ":%u %hhu\n", NIPQUAD(key->ip_src),
           rte_be_to_cpu_16(key->port_src), NIPQUAD(key->ip_dst),
           rte_be_to_cpu_16(key->port_dst), key->proto);
}

static inline struct flow *
find_flow(struct lcore_conf *qconf, const union flow_key *key, uint32_t hash)
{
    struct flow *f = qconf->buckets[hash];
    while (NULL != f) {
        if (0 == memcmp(key, &f->key, sizeof(union flow_key)))
            break;
        f = f->next;
    }

    return f;
}

static void process_flow_table(struct lcore_conf *qconf, struct rte_mbuf *m)
{
    // int ret;
    union flow_key key;
    struct flow *f;
    uint32_t hash;

    key.xmm = mask_key(rte_pktmbuf_mtod(m, void *) + RTE_ETHER_HDR_LEN +
                           offsetof(struct rte_ipv4_hdr, time_to_live),
                       mask_v4.x);
    if (key.ip_src > key.ip_dst) {
        uint32_t ip_tmp;
        uint16_t port_tmp;
        ip_tmp = key.ip_src;
        key.ip_src = key.ip_dst;
        key.ip_dst = ip_tmp;
        port_tmp = key.port_src;
        key.port_src = key.port_dst;
        key.port_dst = port_tmp;
    }

    hash = rte_jhash(&key, sizeof(union flow_key), 0xfee1900d);
    hash &= qconf->bucket_mask;
    f = find_flow(qconf, &key, hash);
    if (NULL == f) {
        if (unlikely(rte_mempool_get(qconf->mempool, (void **)&f) != 0))
            rte_exit(EXIT_FAILURE, "can't alloc flow from mempool\n");

        f->key = key;
        FLOW_HASH_LIST_ADD_TAIL(f, qconf->buckets[hash]);
        qconf->flow_count++;
    }
}

static void print_flow_table(const struct flow **buckets)
{
    /** @todo XXX */
}

struct lcore_params
{
    uint16_t port_id;
    uint16_t queue_id;
    unsigned lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2}, {0, 1, 2}, {0, 2, 2}, {1, 0, 2}, {1, 1, 2},
    {1, 2, 2}, {2, 0, 2}, {3, 0, 3}, {3, 1, 3},
};

static const int port_tx_table[] = {
    1, 0, 3, 2, 5, 4, 7, 6,
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

// clang-format off
// 用于82599网卡, XL710无效
static uint8_t RSS_INTEL_KEY[40] =
{
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};
// clang-format on

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS,
            .split_hdr_size = 0,
        },
#ifdef NIC_82599
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = RSS_INTEL_KEY,
                    .rss_key_len = 40,
                    .rss_hf = ETH_RSS_IPV4 | ETH_RSS_UDP | ETH_RSS_TCP,
                },
        },
#endif
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];


static int check_lcore_params(void)
{
    uint8_t queue, lcore;
    uint16_t i;
    unsigned socket_id;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("invalid queue number: %hhu\n", queue);
            return -1;
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
            return -1;
        }
        if ((socket_id = rte_lcore_to_socket_id(lcore) != 0) &&
            (numa_on == 0)) {
            printf("warning: lcore %hhu is on socket %d with numa off \n",
                   lcore, socket_id);
        }
    }
    return 0;
}

static int check_port_config(void)
{
    uint16_t port_id, i;

    for (i = 0; i < nb_lcore_params; ++i) {
        port_id = lcore_params[i].port_id;
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            printf("port %u is not enabled in port mask\n", port_id);
            return -1;
        }
    }
    return 0;
}

static uint16_t get_port_n_rx_queues(uint16_t port_id)
{
    uint16_t queue = 0;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port_id) {
            if (lcore_params[i].queue_id == queue)
                queue = lcore_params[i].queue_id + 1;
            else
                rte_exit(EXIT_FAILURE,
                         "queue id of the port %d must be"
                         " in sequence and must start with 0, queue_id: %u\n",
                         lcore_params[i].port_id, queue);
        }
    }

    return queue;
}

static int init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    unsigned lcore_id;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore_id = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore_id].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore_id: %u\n",
                   (unsigned)nb_rx_queue + 1, (unsigned)lcore_id);
            return -1;
        } else {
            lcore_conf[lcore_id].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            lcore_conf[lcore_id].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            lcore_conf[lcore_id].n_rx_queue++;
        }
    }
    return 0;
}

static void init_l2fwd_main(int socket_id)
{
    struct lcore_conf *qconf;
    unsigned lcore_id, flow_count, bucket_count;
    char name[32];

    mask_v4 = (rte_xmm_t){
        .u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS}};

    flow_count = flow_per_lcore;
    bucket_count = rte_align32pow2(flow_count * flow_bucket_ratio);

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];

        snprintf(name, 32, "flow_table_%u", lcore_id);
        qconf->buckets = (struct flow **)rte_zmalloc_socket(
            name, bucket_count * sizeof(struct flow *), RTE_CACHE_LINE_SIZE,
            socket_id);
        if (NULL == qconf->buckets)
            rte_exit(EXIT_FAILURE,
                     "create ipv4 flow buckets failed on lcore %u\n", lcore_id);

        snprintf(name, 32, "flow_mempool_%u", lcore_id);
        qconf->mempool = rte_mempool_create(
            name, flow_count, sizeof(struct flow), 0, 0, NULL, NULL, NULL, NULL,
            socket_id, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
        if (NULL == qconf->mempool)
            rte_exit(EXIT_FAILURE,
                     "create ipv4 flow mempool failed on lcore %u\n", lcore_id);

        qconf->bucket_count = bucket_count;
        qconf->bucket_mask = qconf->bucket_count - 1;
        qconf->flow_count = 0;
    }
}

/* display usage */
static void print_usage(const char *prgname)
{
    printf(
        "%s [EAL options] --"
        " -p PORTMASK"
        " [-P]"
        " --config (port,queue,lcore)[,(port,queue,lcore)]"
        " [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
        " [--enable-jumbo [--max-pkt-len PKTLEN]]"
        " [--no-numa]"
        " [--ipv6]"
        " [--flow-per-lcore N]"
        " [--flow-bucket-ratio N]"
        " [--parse-ptype]\n\n"

        "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
        "  -P : Enable promiscuous mode\n"
        "  --config (port,queue,lcore): Rx queue configuration\n"
        "  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
        "  --max-pkt-len: Under the premise of enabling jumbo,\n"
        "                 maximum packet length in decimal (64-9600)\n"
        "  --no-numa: Disable numa awareness\n"
        "  --ipv6: Set if running ipv6 packets\n"
        "  --flow-per-lcore: Set flow count per lcore, DEFAULT 1024*1024\n"
        "  --flow-bucket-ratio: Set flow bucket ratio, DEFAULT 2\n"
        "  --parse-ptype: Set to use software to analyze packet type\n\n",
        prgname);
}

#if 0
static int parse_max_pkt_len(const char *pktlen)
{
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}
#endif

static int parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static int parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames
    {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;

    nb_lcore_params = 0;

    while ((p = strchr(p0, '(')) != NULL) {
        ++p;
        if ((p0 = strchr(p, ')')) == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                   nb_lcore_params);
            return -1;
        }
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

static void parse_eth_dest(const char *optarg)
{
    uint16_t port_id;
    char *port_end;
    uint8_t c, *dest, peer_addr[6];

    errno = 0;
    port_id = strtoul(optarg, &port_end, 10);
    if (errno != 0 || port_end == optarg || *port_end++ != ',')
        rte_exit(EXIT_FAILURE, "Invalid eth-dest: %s", optarg);
    if (port_id >= RTE_MAX_ETHPORTS)
        rte_exit(EXIT_FAILURE, "eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
                 port_id, RTE_MAX_ETHPORTS);

    if (cmdline_parse_etheraddr(NULL, port_end, &peer_addr, sizeof(peer_addr)) <
        0)
        rte_exit(EXIT_FAILURE, "Invalid ethernet address: %s\n", port_end);
    dest = (uint8_t *)&dest_eth_addr[port_id];
    for (c = 0; c < 6; c++)
        dest[c] = peer_addr[c];
    *(uint64_t *)(val_eth + port_id) = dest_eth_addr[port_id];
}

#define MAX_JUMBO_PKT_LEN 9600
#define MEMPOOL_CACHE_SIZE 256

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_FLOW_PER_LCORE "flow-per-lcore"
#define CMD_LINE_OPT_FLOW_BUCKET_RATIO "flow-bucket-ratio"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF                                                  \
    RTE_MAX((nb_ports * nb_rx_queue * RTE_TEST_RX_DESC_DEFAULT + \
             nb_ports * nb_lcores * MAX_PKT_BURST +              \
             nb_ports * n_tx_queue * RTE_TEST_TX_DESC_DEFAULT +  \
             nb_lcores * MEMPOOL_CACHE_SIZE),                    \
            (unsigned)8192)

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {CMD_LINE_OPT_CONFIG, 1, 0, 0},
        {CMD_LINE_OPT_ETH_DEST, 1, 0, 0},
        {CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
        {CMD_LINE_OPT_IPV6, 0, 0, 0},
        {CMD_LINE_OPT_FLOW_PER_LCORE, 1, 0, 0},
        {CMD_LINE_OPT_FLOW_BUCKET_RATIO, 1, 0, 0},
        {CMD_LINE_OPT_PARSE_PTYPE, 0, 0, 0},
        {NULL, 0, 0, 0},
    };

    char *end = NULL;
    unsigned long ul_val;

    argvopt = argv;

    /* Error or normal output strings. */
    const char *str1 = "L3FWD: Invalid portmask";
    const char *str2 = "L3FWD: Promiscuous mode selected";
    // const char *str3 = "L3FWD: Exact match selected";
    // const char *str4 = "L3FWD: Longest-prefix match selected";
    const char *str5 = "L3FWD: Invalid config";
    const char *str6 = "L3FWD: NUMA is disabled";
    const char *str7 = "L3FWD: IPV6 is specified";
    // const char *str8 =
    //     "L3FWD: Jumbo frame is enabled - disabling simple TX path";
    // const char *str9 = "L3FWD: Invalid packet length";
    // const char *str10 = "L3FWD: Set jumbo frame max packet len to ";
    // const char *str11 = "L3FWD: Invalid hash entry number";
    // const char *str12 =
    //    "L3FWD: LPM and EM are mutually exclusive, select only one";
    // const char *str13 = "L3FWD: LPM or EM none selected, default LPM on";

    while ((opt = getopt_long(argc, argvopt, "p:PLE", lgopts, &option_index)) !=
           EOF) {
        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("%s\n", str1);
                print_usage(prgname);
                return -1;
            }
            break;
        case 'P':
            printf("%s\n", str2);
            promiscuous_on = 1;
            break;

        /* long options */
        case 0:
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG,
                         sizeof(CMD_LINE_OPT_CONFIG))) {
                ret = parse_config(optarg);
                if (ret) {
                    printf("%s\n", str5);
                    print_usage(prgname);
                    return -1;
                }
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ETH_DEST,
                         sizeof(CMD_LINE_OPT_ETH_DEST))) {
                parse_eth_dest(optarg);
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
                         sizeof(CMD_LINE_OPT_NO_NUMA))) {
                printf("%s\n", str6);
                numa_on = 0;
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_IPV6,
                         sizeof(CMD_LINE_OPT_IPV6))) {
                printf("%sn", str7);
                ipv6 = 1;
            }

#if 0
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ENABLE_JUMBO,
                         sizeof(CMD_LINE_OPT_ENABLE_JUMBO))) {
                struct option lenopts = {"max-pkt-len", required_argument, 0,
                                         0};

                printf("%s\n", str8);
                port_conf.rxmode.jumbo_frame = 1;

                /*
                 * if no max-pkt-len set, use the default
                 * value ETHER_MAX_LEN.
                 */
                if (0 ==
                    getopt_long(argc, argvopt, "", &lenopts, &option_index)) {
                    ret = parse_max_pkt_len(optarg);
                    if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)) {
                        printf("%s\n", str9);
                        print_usage(prgname);
                        return -1;
                    }
                    port_conf.rxmode.max_rx_pkt_len = ret;
                }
                printf("%s %u\n", str10,
                       (unsigned int)port_conf.rxmode.max_rx_pkt_len);
            }
#endif

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_FLOW_PER_LCORE,
                         sizeof(CMD_LINE_OPT_FLOW_PER_LCORE))) {
                /* parse decimal string */
                ul_val = strtoul(optarg, &end, 10);
                if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0') ||
                    ul_val == 0) {
                    printf("flow-per-lcore %lu invalid\n", ul_val);
                    return -1;
                }
                flow_per_lcore = ul_val;
            }

            if (!strncmp(lgopts[option_index].name,
                         CMD_LINE_OPT_FLOW_BUCKET_RATIO,
                         sizeof(CMD_LINE_OPT_FLOW_BUCKET_RATIO))) {
                /* parse decimal string */
                ul_val = strtoul(optarg, &end, 10);
                if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0') ||
                    ul_val == 0) {
                    printf("flow-bucket-ratio %lu invalid\n", ul_val);
                    return -1;
                }
                flow_bucket_ratio = ul_val;
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_PARSE_PTYPE,
                         sizeof(CMD_LINE_OPT_PARSE_PTYPE))) {
                printf("soft parse-ptype is enabled\n");
                parse_ptype = 1;
            }

            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 0; /* reset getopt lib */
    return ret;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static int init_mem(unsigned nb_mbuf)
{
    // struct lcore_conf *qconf;
    unsigned socket_id;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socket_id = rte_lcore_to_socket_id(lcore_id);
        else
            socket_id = 0;

        if (socket_id >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %u of lcore %u is out of range %d\n",
                     socket_id, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[socket_id] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%u", socket_id);
            pktmbuf_pool[socket_id] =
                rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
            if (pktmbuf_pool[socket_id] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %u\n",
                         socket_id);
            else
                printf("Allocated mbuf pool on socket %u\n", socket_id);
        }
    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
    int ret;
    uint16_t port_id, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

    printf("Checking link status...\n");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(port_id)
        {
            if (force_quit)
                return;
            if ((port_mask & (1 << port_id)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(port_id, &link);
            if (ret < 0) {
                all_ports_up = 0;
                if (print_flag == 1)
                    printf("Port %u link get failed: %s\n", port_id,
                           rte_strerror(-ret));
                continue;
            }
            /* print link status if flag set */
            if (print_flag == 1) {
                rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
                                    &link);
                printf("Port %d %s\n", port_id, link_status_text);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
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

static int dump_port_info(void)
{
    int ret = 0;
    uint16_t port_id, mtu = 0;
    struct rte_eth_dev_info dev_info;
    int socket_id = 0;
    char buff[32];

#define NL "\r\n"

    RTE_ETH_FOREACH_DEV(port_id)
    {
        if ((enabled_port_mask & (1 << port_id)) == 0)
            continue;
        printf("port %u\n", port_id);

        /*dev_info*/
        memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
        rte_eth_dev_info_get(port_id, &dev_info);
        printf("\tPCI_addr: %s" NL, dev_info.device->name);

        /*mac*/
        struct rte_ether_addr mac_addr;
        memset(&mac_addr, 0, sizeof(struct rte_ether_addr));
        rte_eth_macaddr_get(port_id, &mac_addr);
        rte_ether_format_addr(buff, sizeof(buff), &mac_addr);
        printf("\tMAC_addr: %s" NL, buff);

        /*socket_id*/
        printf("\tSocket: ");
        socket_id = rte_eth_dev_socket_id(port_id);
        if (socket_id < 0)
            printf("<error>");
        else
            printf("%d", socket_id);

        /*link*/
        struct rte_eth_link eth_link;
        memset(&eth_link, 0, sizeof(struct rte_eth_link));
        rte_eth_link_get_nowait(port_id, &eth_link);

        printf("\tSpeed: %u  Duplex: %s  AutoNeg: %s  Status: %s" NL,
               eth_link.link_speed, eth_link.link_duplex == 0 ? "half" : "full",
               eth_link.link_autoneg == 0 ? "fixed" : "auto",
               eth_link.link_status == 0 ? "down" : "up");

        /*promiscuous*/
        printf("\tPromiscuous: ");
        ret = rte_eth_promiscuous_get(port_id);
        if (1 == ret)
            printf("enabled");
        else if (0 == ret)
            printf("disabled");
        else
            printf("unknown");

        /*mtu*/
        mtu = 0;
        ret = rte_eth_dev_get_mtu(port_id, &mtu);
        if (ret == 0) {
            printf(" mtu %d" NL, mtu);
        } else {
            printf(" get mtu error:%d" NL, ret);
        }

        printf("\tmin_rx_bufsize %u  max_rx_pktlen %u" NL,
               dev_info.min_rx_bufsize, dev_info.max_rx_pktlen);
        printf("\tmax_rx_queues %u  max_tx_queues %u" NL,
               dev_info.max_rx_queues, dev_info.max_tx_queues);

        /*stats*/
        struct rte_eth_stats stats;
        ret = rte_eth_stats_get(port_id, &stats);
        if (ret == 0) {
            printf("\tipackets %lu  opackets %lu  ibytes %lu  obytes %lu" NL,
                   stats.ipackets, stats.opackets, stats.ibytes, stats.obytes);
            printf("\timissed %lu  rx_nombuf %lu  ierrors %lu  oerrors %lu" NL,
                   stats.imissed, stats.rx_nombuf, stats.ierrors,
                   stats.oerrors);
        } else {
            printf("get stat error:%d", ret);
        }
        printf(NL);
    }

    return 0;
}

#if 0
static int
prepare_ptype_parser(uint16_t port_id, uint16_t queue_id)
{
    if (parse_ptype) {
        printf("Port %d: softly parse packet type info\n", port_id);
        if (rte_eth_add_rx_callback(port_id, queue_id,
                        l3fwd_lkp.cb_parse_ptype,
                        NULL))
            return 1;

        printf("Failed to add rx callback: port=%d\n", port_id);
        return 0;
    }

    if (l3fwd_lkp.check_ptype(port_id))
        return 1;

    printf("port %d cannot parse packet type, please add --%s\n",
           port_id, CMD_LINE_OPT_PARSE_PTYPE);
    return 0;
}
#endif


static int worker_loop(__attribute__((unused)) void *arg)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    int i, j, nb_rx;
    uint16_t port_id, queue_id, tx_port_id;
    struct lcore_conf *qconf;
    struct rte_mbuf *m;
#ifdef DRAIN
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
#endif

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {
        port_id = qconf->rx_queue_list[i].port_id;
        queue_id = qconf->rx_queue_list[i].queue_id;
        RTE_LOG(INFO, L2FWD, "lcore: %u port: %hhu rx queue: %hhu\n", lcore_id,
                port_id, queue_id);
    }

    while (!force_quit) {
#ifdef DRAIN
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_tx_port; ++i) {
                port_id = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[port_id].len == 0)
                    continue;
                send_burst(qconf, qconf->tx_mbufs[port_id].len, port_id);
                qconf->tx_mbufs[port_id].len = 0;
            }

            prev_tsc = cur_tsc;
        }
#endif

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            port_id = qconf->rx_queue_list[i].port_id;
            queue_id = qconf->rx_queue_list[i].queue_id;
            tx_port_id = port_tx_table[port_id];
            nb_rx =
                rte_eth_rx_burst(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;
#ifdef STAT
            qconf->rx_pkt_cnt[port_id] += nb_rx;
#endif

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                process_flow_table(qconf, m);
                send_single_packet(qconf, m, tx_port_id);
            }
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    unsigned nb_ports, lcore_id, socket_id;
    uint32_t n_tx_queue, nb_lcores;
    uint16_t port_id, queue_id, nb_rx_queue, queue;

    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        dest_eth_addr[port_id] =
            RTE_ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)port_id << 40);
        *(uint64_t *)(val_eth + port_id) = dest_eth_addr[port_id];
    }

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    if (check_port_config() < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();
    if (nb_lcores % 2)
        rte_exit(EXIT_FAILURE, "lcores count must be even number\n");

    nb_ports = rte_eth_dev_count_avail();

    printf("avail ports: %u, port mask: 0x%x\n", nb_ports, enabled_port_mask);

    /* initialize all ports */
    RTE_ETH_FOREACH_DEV(port_id)
    {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            printf("\nSkipping disabled port %u\n", port_id);
            continue;
        }

        /* init port */
        printf("\nInitializing port %u...\n", port_id);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(port_id);
        n_tx_queue = nb_lcores;
        // n_tx_queue = nb_rx_queue;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Setup queues, nb_rxq: %u, nb_txq: %u...\n", nb_rx_queue,
               n_tx_queue);
        ret = rte_eth_dev_configure(port_id, nb_rx_queue, (uint16_t)n_tx_queue,
                                    &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_configure failed, err: %d, port: %u\n", ret,
                     port_id);

        rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
        print_ethaddr("Address:", &ports_eth_addr[port_id]);
        printf(", ");
        print_ethaddr("Destination:",
                      (const struct rte_ether_addr *)&dest_eth_addr[port_id]);
        printf("\n");

        /*
         * prepare src MACs for each port.
         */
        rte_ether_addr_copy(&ports_eth_addr[port_id],
                            (struct rte_ether_addr *)(val_eth + port_id) + 1);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queue_id = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socket_id = rte_lcore_to_socket_id(lcore_id);
            else
                socket_id = 0;

            printf("txq: %u,%u,%u,%u ", port_id, queue_id, lcore_id, socket_id);
            fflush(stdout);

            rte_eth_dev_info_get(port_id, &dev_info);
            txconf = &dev_info.default_txconf;
            ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id,
                                         txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: err:%d, port: %d\n", ret,
                         port_id);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[port_id] = queue_id;
            queue_id++;

            qconf->tx_port_id[qconf->n_tx_port] = port_id;
            qconf->n_tx_port++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u...\n", lcore_id);
        fflush(stdout);
        /* init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            port_id = qconf->rx_queue_list[queue].port_id;
            queue_id = qconf->rx_queue_list[queue].queue_id;

            if (numa_on)
                socket_id = rte_lcore_to_socket_id(lcore_id);
            else
                socket_id = 0;

            printf("rxq: %u,%u,%u,%u\n", port_id, queue_id, lcore_id,
                   socket_id);
            fflush(stdout);

            ret = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd, socket_id,
                                         NULL, pktmbuf_pool[socket_id]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: err: %d, port: %u\n", ret,
                         port_id);
        }
    }

    printf("\n");

    /* start ports */
    RTE_ETH_FOREACH_DEV(port_id)
    {
        if ((enabled_port_mask & (1 << port_id)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret,
                     port_id);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(port_id);
    }

    init_l2fwd_main(rte_socket_id());
    printf("\n");

#if 0
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            port_id = qconf->rx_queue_list[queue].port_id;
            queue_id = qconf->rx_queue_list[queue].queue_id;
            if (prepare_ptype_parser(port_id, queue_id) == 0)
                rte_exit(EXIT_FAILURE, "ptype check fails\n");
        }
    }
#endif

    check_all_ports_link_status(enabled_port_mask);

    // RTE_LCORE_FOREACH(lcore_id)
    // {
    //     rte_eal_remote_launch(worker_loop, NULL, lcore_id);
    // }
    rte_eal_mp_remote_launch(worker_loop, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();

    dump_port_info();

#ifdef STAT
    printf("=============================================================\n");
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("lcore %u\n", lcore_id);
        RTE_ETH_FOREACH_DEV(port_id)
        {
            if ((enabled_port_mask & (1 << port_id)) == 0)
                continue;
            printf("  port%d rx: %16lu    tx: %16lu\n", port_id,
                   qconf->rx_pkt_cnt[port_id], qconf->tx_pkt_cnt[port_id]);
        }
        printf("  flow count: %u\n", qconf->flow_count);
#ifdef DEBUG
        print_flow_table(qconf->buckets);
#endif
        printf(
            "-------------------------------------------------------------\n");
    }
#endif


    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        rte_mempool_free(qconf->mempool);
        rte_free(qconf->buckets);
    }

    /* stop ports */
    RTE_ETH_FOREACH_DEV(port_id)
    {
        if ((enabled_port_mask & (1 << port_id)) == 0)
            continue;
        printf("Closing port %d...", port_id);
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
        printf(" Done\n");
    }

    printf("Bye...\n");

    return ret;
}
