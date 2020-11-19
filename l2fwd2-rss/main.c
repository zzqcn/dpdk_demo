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

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
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
#include <rte_bus_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_thash.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l2fwd.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;


static int numa_on = 1; /**< NUMA is enabled by default. */
static int parse_ptype; /**< Parse packet type using rx callback, and */
            /**< disabled by default */

/* Global variables. */

volatile bool force_quit;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

/* Used only in exact match mode. */
int ipv6; /**< ipv6 is false by default. */

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

#ifdef STAT
struct port_stat port_stat[RTE_MAX_ETHPORTS];
#endif

struct lcore_params {
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

static const int port_tx_table[] = {
    1, 0, 3, 2, 5, 4, 7, 6,
};

static uint8_t intel_rss_key[40] =
{
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};
static uint8_t intel_rss_key_be[40] = {0};

union flow_key {
    struct {
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

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static rte_xmm_t mask_v4 = (rte_xmm_t){.u32 = { BIT_8_TO_15, ALL_32_BITS,
    ALL_32_BITS, ALL_32_BITS} };

static inline xmm_t
mask_key(void* key, xmm_t mask)
{
    __m128i data = _mm_loadu_si128((__m128i *)(key));
    return _mm_and_si128(data, mask);
}

static void
print_flow_key(const union flow_key* key)
{
    printf("%d.%d.%d.%d\t"
            "%d.%d.%d.%d\t"
            "%u\t%u\t%u\n",
            (key->ip_src) & 0xff,
            (key->ip_src >> 8) & 0xff,
            (key->ip_src >> 16) & 0xff,
            (key->ip_src >> 24),
            (key->ip_dst) & 0xff,
            (key->ip_dst >> 8) & 0xff,
            (key->ip_dst >> 16) & 0xff,
            (key->ip_dst >> 24),
            key->proto,
            rte_be_to_cpu_16(key->port_src),
            rte_be_to_cpu_16(key->port_dst));
}

static uint32_t
calc_rss_hash(const union flow_key* key)
{
    union rte_thash_tuple tuple;

    tuple.v4.src_addr = key->ip_src;
    tuple.v4.dst_addr = key->ip_dst;
    tuple.v4.sport = key->port_src;
    tuple.v4.dport = key->port_dst;
    return rte_softrss((uint32_t*)&tuple, RTE_THASH_V4_L4_LEN, intel_rss_key_be);
}


static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
                sizeof(lcore_params_array_default[0]);

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
            .rss_key = intel_rss_key,
            .rss_hf = ETH_RSS_IP  | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

static int
check_lcore_params(void)
{
    uint8_t queue, lcore;
    uint16_t i;
    int socketid;

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
        if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
            (numa_on == 0)) {
            printf("warning: lcore %hhu is on socket %d with numa off \n",
                lcore, socketid);
        }
    }
    return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
    unsigned portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (portid >= nb_ports) {
            printf("port %u is not present on the board\n", portid);
            return -1;
        }
    }
    return 0;
}

static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port) {
            if (lcore_params[i].queue_id == queue+1)
                queue = lcore_params[i].queue_id;
            else
                rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
                        " in sequence and must start with 0\n",
                        lcore_params[i].port_id);
        }
    }
    return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                (unsigned)nb_rx_queue + 1, (unsigned)lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            lcore_conf[lcore].n_rx_queue++;
        }
    }
    return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
    printf("%s [EAL options] --"
        " -p PORTMASK"
        " [-P]"
        " --config (port,queue,lcore)[,(port,queue,lcore)]"
        " [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
        " [--enable-jumbo [--max-pkt-len PKTLEN]]"
        " [--no-numa]"
        " [--ipv6]"
        " [--parse-ptype]\n\n"

        "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
        "  -P : Enable promiscuous mode\n"
        "  --config (port,queue,lcore): Rx queue configuration\n"
        "  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
        "  --enable-jumbo: Enable jumbo frames\n"
        "  --max-pkt-len: Under the premise of enabling jumbo,\n"
        "                 maximum packet length in decimal (64-9600)\n"
        "  --no-numa: Disable numa awareness\n"
        "  --ipv6: Set if running ipv6 packets\n"
        "  --parse-ptype: Set to use software to analyze packet type\n\n",
        prgname);
}

static int
parse_max_pkt_len(const char *pktlen)
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

static int
parse_portmask(const char *portmask)
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

static int
parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
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

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL)
            return -1;

        size = p0 - p;
        if(size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++){
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

static void
parse_eth_dest(const char *optarg)
{
    uint8_t portid;
    char *port_end;
    uint8_t c, *dest, peer_addr[6];

    errno = 0;
    portid = strtoul(optarg, &port_end, 10);
    if (errno != 0 || port_end == optarg || *port_end++ != ',')
        rte_exit(EXIT_FAILURE,
        "Invalid eth-dest: %s", optarg);
    if (portid >= RTE_MAX_ETHPORTS)
        rte_exit(EXIT_FAILURE,
        "eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
        portid, RTE_MAX_ETHPORTS);

    if (cmdline_parse_etheraddr(NULL, port_end,
        &peer_addr, sizeof(peer_addr)) < 0)
        rte_exit(EXIT_FAILURE,
        "Invalid ethernet address: %s\n",
        port_end);
    dest = (uint8_t *)&dest_eth_addr[portid];
    for (c = 0; c < 6; c++)
        dest[c] = peer_addr[c];
    *(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF RTE_MAX(    \
    (nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +    \
    nb_ports*nb_lcores*MAX_PKT_BURST +            \
    nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +        \
    nb_lcores*MEMPOOL_CACHE_SIZE),                \
    (unsigned)8192)

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
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
        {CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
        {CMD_LINE_OPT_PARSE_PTYPE, 0, 0, 0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    /* Error or normal output strings. */
    const char *str1 = "L3FWD: Invalid portmask";
    const char *str2 = "L3FWD: Promiscuous mode selected";
    //const char *str3 = "L3FWD: Exact match selected";
    //const char *str4 = "L3FWD: Longest-prefix match selected";
    const char *str5 = "L3FWD: Invalid config";
    const char *str6 = "L3FWD: NUMA is disabled";
    const char *str7 = "L3FWD: IPV6 is specified";
    const char *str8 =
        "L3FWD: Jumbo frame is enabled - disabling simple TX path";
    const char *str9 = "L3FWD: Invalid packet length";
    const char *str10 = "L3FWD: Set jumbo frame max packet len to ";
    //const char *str11 = "L3FWD: Invalid hash entry number";
    //const char *str12 =
    //    "L3FWD: LPM and EM are mutually exclusive, select only one";
    //const char *str13 = "L3FWD: LPM or EM none selected, default LPM on";

    while ((opt = getopt_long(argc, argvopt, "p:PLE",
                lgopts, &option_index)) != EOF) {

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
            if (!strncmp(lgopts[option_index].name,
                    CMD_LINE_OPT_CONFIG,
                    sizeof(CMD_LINE_OPT_CONFIG))) {

                ret = parse_config(optarg);
                if (ret) {
                    printf("%s\n", str5);
                    print_usage(prgname);
                    return -1;
                }
            }

            if (!strncmp(lgopts[option_index].name,
                    CMD_LINE_OPT_ETH_DEST,
                    sizeof(CMD_LINE_OPT_ETH_DEST))) {
                    parse_eth_dest(optarg);
            }

            if (!strncmp(lgopts[option_index].name,
                    CMD_LINE_OPT_NO_NUMA,
                    sizeof(CMD_LINE_OPT_NO_NUMA))) {
                printf("%s\n", str6);
                numa_on = 0;
            }

            if (!strncmp(lgopts[option_index].name,
                CMD_LINE_OPT_IPV6,
                sizeof(CMD_LINE_OPT_IPV6))) {
                printf("%sn", str7);
                ipv6 = 1;
            }

            if (!strncmp(lgopts[option_index].name,
                    CMD_LINE_OPT_ENABLE_JUMBO,
                    sizeof(CMD_LINE_OPT_ENABLE_JUMBO))) {
                struct option lenopts = {
                    "max-pkt-len", required_argument, 0, 0
                };

                printf("%s\n", str8);
                port_conf.rxmode.jumbo_frame = 1;

                /*
                 * if no max-pkt-len set, use the default
                 * value ETHER_MAX_LEN.
                 */
                if (0 == getopt_long(argc, argvopt, "",
                        &lenopts, &option_index)) {
                    ret = parse_max_pkt_len(optarg);
                    if ((ret < 64) ||
                        (ret > MAX_JUMBO_PKT_LEN)) {
                        printf("%s\n", str9);
                        print_usage(prgname);
                        return -1;
                    }
                    port_conf.rxmode.max_rx_pkt_len = ret;
                }
                printf("%s %u\n", str10,
                (unsigned int)port_conf.rxmode.max_rx_pkt_len);
            }

            if (!strncmp(lgopts[option_index].name,
                     CMD_LINE_OPT_PARSE_PTYPE,
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
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static int
init_mem(unsigned nb_mbuf)
{
    //struct lcore_conf *qconf;
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE,
                "Socket %d of lcore %u is out of range %d\n",
                socketid, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                    "Cannot init mbuf pool on socket %d\n",
                    socketid);
            else
                printf("Allocated mbuf pool on socket %d\n",
                    socketid);
        }
    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)portid,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                        (uint8_t)portid);
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
            printf("done\n");
        }
    }
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}

static int
dump_port_info(void)
{
    int ret = 0;
    unsigned portIndex, port_cnt;
    uint16_t mtu = 0;
    int promiscuous = 0;
    struct rte_eth_dev_info dev_info;
    int socket_id = 0;
    uint8_t mac[6];;

    const char duplex[4][32] = {"Auto-negotiate duplex", "Half-duplex", "Full-duplex", "Unknown"};
    const char linkStatus[3][32] = {"DOWN", "UP", "Unknown"};
    const char promiscuousStatus[3][32] = {"OFF", "ON", "Unknown"};

#define NL "\r\n"
#define FMT_MAC "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
#define PRINT_MAC(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]


    port_cnt = rte_eth_dev_count();
    for (portIndex = 0; portIndex < port_cnt; portIndex++) {
        if ((enabled_port_mask & (1 << portIndex)) == 0)
            continue;

        printf("port %u\n", portIndex);

        /*socket_id*/
        socket_id = rte_eth_dev_socket_id(portIndex);
        if (socket_id < 0) {
            printf("\tsocketid error %d", socket_id);
        } else {
            printf("\tsocketid %d", socket_id);
        }

        /*mtu*/
        mtu = 0;
        ret = rte_eth_dev_get_mtu(portIndex, &mtu);
        if (ret == 0) {
            printf(" mtu %d" NL, mtu);
        }
        else {
            printf(" get mtu error:%d" NL, ret);
        }

        /*mac*/
        struct ether_addr mac_addr;
        memset(&mac_addr, 0, sizeof(struct ether_addr));
        rte_eth_macaddr_get(portIndex, &mac_addr);
        memcpy(mac, mac_addr.addr_bytes, 6);
        printf("\tether " FMT_MAC NL, PRINT_MAC(mac));

        /*link*/
        struct rte_eth_link eth_link;
        memset(&eth_link, 0, sizeof(struct rte_eth_link));
        rte_eth_link_get_nowait(portIndex, &eth_link);

        printf("\tlinkDuplex %s  linkSpeed %u  linkStatus %s" NL,
            eth_link.link_duplex > 2 ? duplex[3] : duplex[eth_link.link_duplex],
            eth_link.link_speed,
            eth_link.link_status > 2 ? linkStatus[2] : linkStatus[eth_link.link_status]);

        /*promiscuous*/
        promiscuous = 0;
        promiscuous = rte_eth_promiscuous_get(portIndex);
        if (promiscuous < 0 || promiscuous > 2)
        {
            printf("\tpromiscuous :Invalid");
        }
        else
        {
            printf("\tpromiscuous:%s", promiscuousStatus[promiscuous]);
        }

        /*dev_info*/
        memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
        rte_eth_dev_info_get(portIndex, &dev_info);
        printf("\tpci_addr %.4x:%.2x.%.2x.%.1x" NL,
                    dev_info.pci_dev->addr.domain,
                    dev_info.pci_dev->addr.bus,
                    dev_info.pci_dev->addr.devid,
                    dev_info.pci_dev->addr.function);
        printf("\tmin_rx_bufsize %u  max_rx_pktlen %u" NL,
                    dev_info.min_rx_bufsize,
                    dev_info.max_rx_pktlen);
        printf("\tmax_rx_queues %u  max_tx_queues %u" NL,
                    dev_info.max_rx_queues,
                    dev_info.max_tx_queues);

        /*stats*/
        struct rte_eth_stats stats;
        ret = rte_eth_stats_get(portIndex, &stats);
        if (ret == 0)
        {
            printf("\tipackets %lu  opackets %lu  ibytes %lu  obytes %lu" NL,
                stats.ipackets, stats.opackets, stats.ibytes, stats.obytes);
            /** @note 为了适配dpdk16.07.2, 其rte_eth_stats结构体并没有ibadcrc, ibadlen等成员, 
             * 但去掉会影响snmp, 因此做填0处理, zzqcn, 2016.12.07 */
            printf("\timissed %lu  ibadcrc %lu  ibadlen %lu  ierrors  %lu  oerrors %lu" NL,
                stats.imissed, 0ul, 0ul, stats.ierrors, stats.oerrors);
            //stats.imissed,stats.ibadcrc,stats.ibadlen,stats.ierrors,stats.oerrors);
            /** @note 为了适配dpdk16.07.2, 其rte_eth_stats结构体并没有imcasts, fdirmatch, fdirmiss等成员, 
             * 但去掉会影响snmp, 因此做填0处理, zzqcn, 2016.12.07 */
            printf("\timcasts %lu  rx_nombuf %lu  fdirmatch %lu  fdirmiss %lu" NL,
                0ul, stats.rx_nombuf, 0ul, 0ul);
        }
        else
        {
            printf("get stat error:%d", ret);
        }
        printf(NL);
    }

    return 0;
}

#if 0
static int
prepare_ptype_parser(uint8_t portid, uint16_t queueid)
{
    if (parse_ptype) {
        printf("Port %d: softly parse packet type info\n", portid);
        if (rte_eth_add_rx_callback(portid, queueid,
                        l3fwd_lkp.cb_parse_ptype,
                        NULL))
            return 1;

        printf("Failed to add rx callback: port=%d\n", portid);
        return 0;
    }

    if (l3fwd_lkp.check_ptype(portid))
        return 1;

    printf("port %d cannot parse packet type, please add --%s\n",
           portid, CMD_LINE_OPT_PARSE_PTYPE);
    return 0;
}
#endif

static int
main_loop(__attribute__((unused)) void* arg)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    int i, j, nb_rx;
    uint8_t portid, queueid, tx_portid;
    struct lcore_conf *qconf;
    struct rte_mbuf *m;
    union flow_key key;

#ifdef DRAIN
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
        US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
#endif

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {
        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
        RTE_LOG(INFO, L3FWD,
            " -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
            lcore_id, portid, queueid);
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
                portid = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[portid].len == 0)
                    continue;
                send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
                qconf->tx_mbufs[portid].len = 0;
            }

            prev_tsc = cur_tsc;
        }
#endif

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            tx_portid = port_tx_table[portid];
            nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;
#ifdef STAT
            port_stat[portid].rx_pkt_cnt += nb_rx;
            qconf->rx_pkt_cnt[portid] += nb_rx;
#endif

            for(j=0; j<nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void*));
                key.xmm = mask_key(rte_ctrlmbuf_data(m) + 14 + offsetof(
                            struct ipv4_hdr, time_to_live), mask_v4.x);
                print_flow_key(&key);
                printf("nic_hash: %x, soft_hash: %x\n", m->hash.rss, calc_rss_hash(&key));
                send_single_packet(qconf, m, tx_portid);
            }
        }
    }

    return 0;
}

int
main(int argc, char **argv)
{
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    int ret;
    unsigned nb_ports;
    uint16_t queueid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t portid, nb_rx_queue, queue, socketid;

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
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        dest_eth_addr[portid] =
            ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
        *(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
    }

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

    /* Convert RSS key*/
    rte_convert_rss_key((uint32_t *)&intel_rss_key,
            (uint32_t *)&intel_rss_key_be, RTE_DIM(intel_rss_key));

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count();

    if (check_port_config(nb_ports) < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();
    if(nb_lcores % 2)
        rte_exit(EXIT_FAILURE, "lcores count must be even number\n");

    /* initialize all ports */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %d ... ", portid );
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = nb_lcores;
        //n_tx_queue = nb_rx_queue;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
            nb_rx_queue, (unsigned)n_tx_queue );
        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                    (uint16_t)n_tx_queue, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr("\n Address:", &ports_eth_addr[portid]);
        printf(", ");
        print_ethaddr("Destination:",
            (const struct ether_addr *)&dest_eth_addr[portid]);
        printf(", ");

        /*
         * prepare src MACs for each port.
         */
        ether_addr_copy(&ports_eth_addr[portid],
            (struct ether_addr *)(val_eth + portid) + 1);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socketid =
                (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            rte_eth_dev_info_get(portid, &dev_info);
            txconf = &dev_info.default_txconf;
            if (port_conf.rxmode.jumbo_frame)
                txconf->txq_flags = 0;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             socketid, txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "rte_eth_tx_queue_setup: err=%d, "
                    "port=%d\n", ret, portid);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %2u ... ", lcore_id );
        fflush(stdout);
        /* init RX queues */
        for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

            if (numa_on)
                socketid =
                (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    socketid,
                    NULL,
                    pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                "rte_eth_rx_queue_setup: err=%d, port=%d\n",
                ret, portid);
        }
    }

    printf("\n");

    /* start ports */
    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "rte_eth_dev_start: err=%d, port=%d\n",
                ret, portid);

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

#if 0
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            if (prepare_ptype_parser(portid, queueid) == 0)
                rte_exit(EXIT_FAILURE, "ptype check fails\n");
        }
    }
#endif


    check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

    ret = 0;
    /* launch per-lcore init on every lcore */
    //rte_eal_mp_remote_launch(l3fwd_lkp.main_loop, NULL, CALL_MASTER);
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    dump_port_info();

#ifdef STAT
    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("port%d rx: %16lu    tx: %16lu\n",
            portid, port_stat[portid].rx_pkt_cnt, port_stat[portid].tx_pkt_cnt);
    }
    printf("=============================================================\n");
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("lcore %u\n", lcore_id);
        for (portid = 0; portid < nb_ports; portid++) {
            if ((enabled_port_mask & (1 << portid)) == 0)
                continue;
            printf("  port%d rx: %16lu    tx: %16lu\n",
                    portid, qconf->rx_pkt_cnt[portid], qconf->tx_pkt_cnt[portid]);
        }
        printf("-------------------------------------------------------------\n");
    }
#endif

    /* stop ports */
    for (portid = 0; portid < nb_ports; portid++) {
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
