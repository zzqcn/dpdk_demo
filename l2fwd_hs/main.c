/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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

/**
 * @file 
 * @brief l2fwd with simple decode and hyperscan, for performance test.
 * @author zzq
 * @version 1.0
 * @date 2015-10-27
 * 
 * usage: ./l2fwd_hs -c 3 -n 2 -- -p 3 -q 2 --dec --ptn /path/to/ptn.txt
 * note: 
 * 1. the master lcore don't run main_loop (SKIP_MASTER);
 * 2. if using 2 lcore and 2 ports (-c 3 -p 3), the queues/ports every 
 *    lcore recv from must be  2 (-q 2), the unique slave lcore will 
 *    recv from rx0 and rx1;
 *    
 *    if using 3 lcore and 2 ports (-c 7 -p 3), the queues/ports every
 *    lcore recv could be 1 (-q 1 or ignore), slave lcore 0 will recv
 *    from rx0, slave lcore 1 will recv rx1; or -q 2, slave lcore 0
 *    will recv from rx0 and rx1, slave lcore 1 do nothing.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
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
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "public.h"
#include "rubi.h"
#include "ModuleDecode.h"

#include <hs/hs.h>


#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */


/** by zzq, 2015.10.27, for hyperscan test */
#define NB_SOCKETS  8 
#define PTN_MAX     10000
#define PTN_LEN_MAX 64

int g_dec = 0;
int g_hs = 0;
char* g_ptn_file = NULL;
char* g_ptns[PTN_MAX] = {0};
uint32_t g_ids[PTN_MAX] = {0};
uint32_t g_ptn_cnt = 0;
int g_socket_flag[NB_SOCKETS] = {0};
hs_database_t *g_db[NB_SOCKETS];
hs_scratch_t *g_scratch[RTE_MAX_LCORE];
//hs_compile_error_t *g_compileErr;
//hs_error_t hs_err;


static void* my_malloc(size_t n)
{
    return rte_malloc("hyperscan", n, RTE_CACHE_LINE_SIZE);
}


#define IS_SPACE(c)  ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')
static char* trim(char *str)
{
    size_t len;
    char *p, *end;

    p = str;
    if (p == NULL)
        return NULL;

    while(IS_SPACE(*p))
        p++;
    len = strlen(p);
    if (len < 1)
        return str;

    end = p + len - 1;
    while(IS_SPACE(*end))
        end--;
    *(++end) = '\0';

    end = p;
    str = p;
    while(*end != '\0')
        *(p++) = *(end++);
    *p = '\0';

    return str;
}

static int parse_patterns(char* path)
{
    FILE* fp;
    char *s, tmp[PTN_LEN_MAX];
    int i;

    if(NULL == path)
    {
        fprintf(stderr, "invalid pattern file path!\n");
        return -1;
    }

    fp = fopen(path, "r");
    if(NULL == fp)
    {
        fprintf(stderr, "can't open pattern file: %s\n", path);
        return -1;
    }

    for(i=0; i<PTN_MAX; i++)
    {
        g_ptns[i] = (char*)malloc(PTN_LEN_MAX);
        if(g_ptns[i] == NULL)
        {
            fprintf(stderr, "bad alloc for patterns!\n");
            exit(-1);
        }
        g_ptns[i][0] = '\0';
    }
    

    do
    {
        s = fgets(tmp, PTN_LEN_MAX, fp);
        if(s == NULL)
            break;
        trim(tmp);
        if(strlen(tmp) < 1)
            continue;

        tmp[PTN_LEN_MAX-1] = '\0';
        strncpy(g_ptns[g_ptn_cnt], tmp, PTN_LEN_MAX);
        g_ids[g_ptn_cnt] = g_ptn_cnt+1;
        g_ptn_cnt ++; 
    }
    while(g_ptn_cnt < PTN_MAX);

    fclose(fp);

    return 0;
}

int hs_init(void)
{
    int ret;
    hs_error_t hs_err;
    hs_compile_error_t* g_compileErr;
    unsigned lcore_id, socket_id, i;
    size_t db_size = 0, scratch_size = 0;

    ret = parse_patterns(g_ptn_file);
    if(ret != 0)
        return -1;

    // check enabled sockets
    for(lcore_id=0; lcore_id<RTE_MAX_LCORE; lcore_id++)
    {
        if(rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        socket_id = rte_lcore_to_socket_id(lcore_id);
        if(socket_id >= NB_SOCKETS)
        {
            fprintf(stderr, "socket %u of lcore %u is out of range %u\n",
                    socket_id, lcore_id, NB_SOCKETS);
            exit(-1);
        }
        g_socket_flag[socket_id] = 1;
    }

    hs_err = hs_set_allocator(my_malloc, rte_free);
    if(hs_err != HS_SUCCESS)
    {
        fprintf(stderr, "hs_set_allocator failed!\n");
        exit(-1);
    }

    // compile ptns on every socket
    for(i=0; i<NB_SOCKETS; i++)
    {
        if(!g_socket_flag[i])
            continue;
        hs_err = hs_compile_multi(g_ptns, 
                    NULL, // flags array
                    g_ids,
                    g_ptn_cnt,
                    HS_MODE_BLOCK,
                    NULL, // platform
                    &g_db[i],
                    &g_compileErr);

        if (hs_err != HS_SUCCESS) 
        {
            if (g_compileErr->expression < 0) 
            {
                // The error does not refer to a particular expression.
                fprintf(stderr, "HS ERROR on socket %u: %s\n", i, g_compileErr->message);
            } 
            else 
            {
                fprintf(stderr, "HS ERROR on socket %u: Pattern %s failed compilation with error %s\n",
                        i, g_ptns[g_compileErr->expression], g_compileErr->message);
            }
            // As the compileErr pointer points to dynamically allocated memory, if
            // we get an error, we must be sure to release it. This is not
            // necessary when no error is detected.
            hs_free_compile_error(g_compileErr);
            exit(-1);
        }
    }

    // alloc scratch on every lcore
    for(lcore_id=0; lcore_id<RTE_MAX_LCORE; lcore_id++)
    {
        if(rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        socket_id = rte_lcore_to_socket_id(lcore_id);

        if(g_db[socket_id] == NULL)
        {
            fprintf(stderr, "database not compiled on socket %u!\n",
                    socket_id);
            exit(-1);
        }

        hs_err = hs_alloc_scratch(g_db[socket_id], &g_scratch[lcore_id]);
        if (hs_err != HS_SUCCESS) 
        {
            fprintf(stderr, "HS ERROR: could not allocate scratch space");
            exit(-1);
        }
    
        hs_err = hs_database_size(g_db[socket_id], &db_size);
        if (hs_err != HS_SUCCESS)
            fprintf(stderr, "Error getting Hyperscan database size");
        hs_err = hs_scratch_size(g_scratch[lcore_id], &scratch_size);
        if (hs_err != HS_SUCCESS)
            fprintf(stderr, "Error getting Hyperscan sratch size");


        printf("patterns compiled successfully on socket %u lcore %u\n"
               "  database size: %lu, sratch size: %lu\n",
               socket_id, lcore_id, db_size, scratch_size);
    }

    return 0;
}


/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

/* Send the burst of packets on an output interface */
static int
l2fwd_send_burst(struct lcore_queue_conf *qconf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queueid =0;

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
	port_statistics[port].tx += ret;
	if (unlikely(ret < n)) {
		port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static int
l2fwd_send_packet(struct rte_mbuf *m, uint8_t port)
{
	unsigned lcore_id, len;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();

	qconf = &lcore_queue_conf[lcore_id];
	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		l2fwd_send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	struct ether_hdr *eth;
	void *tmp;
	unsigned dst_port;

	dst_port = l2fwd_dst_ports[portid];
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dst_port << 40);

	/* src addr */
	ether_addr_copy(&l2fwd_ports_eth_addr[dst_port], &eth->s_addr);

	l2fwd_send_packet(m, (uint8_t) dst_port);
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id, socket_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    int enable_decode = g_dec;
    int enable_hs = g_hs;
    Packet_t *pPacket;
    hs_error_t hs_err;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];
    socket_id = rte_lcore_to_socket_id(lcore_id);

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (1) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				l2fwd_send_burst(&lcore_queue_conf[lcore_id],
						 qconf->tx_mbufs[portid].len,
						 (uint8_t) portid);
				qconf->tx_mbufs[portid].len = 0;
			}

/** by zzq, 2015.10.28, disable stats show */
#if 0
			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= (uint64_t) timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}
#endif

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) 
            {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));

                if(enable_decode)
                {
                    pPacket = (Packet_t *)m->buf_addr;
                    pPacket->pMBuf = m;
                    pPacket->pData = rte_pktmbuf_mtod(m, unsigned char *);
                    pPacket->unLen = rte_pktmbuf_pkt_len(m);
                    pPacket->pEnd = pPacket->pData + pPacket->unLen;
                    pPacket->unNicPortSrc = portid;
                    //pPacket->enDirection = 1;
                    pPacket->enDirection = DIRECTION_IN;
                    pPacket->unNicPortDst = 1;
                    pPacket->unNicPortGroup = 1;
                    pPacket->ullTimeMS = 1000000;
                    pPacket->nOffloadFlag = 0;
                    pPacket->pCurrent = pPacket->pData;
                    pPacket->pIPOuter = NULL;
                    pPacket->pIPInner = NULL;
                    pPacket->pTcpUdpInner = NULL;
                    void * (* NextDecode)(Packet_t * pPacket) = DecodeEth;
                    while(NextDecode)
                        NextDecode = (void *(*)(Packet_t *))NextDecode(pPacket);
                    if(NULL != pPacket->pTcpUdpInner)
                    {

                        DECODE_IP(pPacket->stIpSrc, pPacket->stIpDst, pPacket->unCtrlProtocol, pPacket->pIPInner);
                        if((IPPROTO_TCP == pPacket->unCtrlProtocol) || (IPPROTO_UDP == pPacket->unCtrlProtocol))
                        {
                            unsigned char * pCurrent = pPacket->pTcpUdpInner;
                            pPacket->usPortSrc = READ_SHORT(pCurrent);
                            pCurrent += 2;
                            pPacket->usPortDst = READ_SHORT(pCurrent);
                        }
                        else
                        {
                            pPacket->usPortSrc = 0;
                            pPacket->usPortDst = 0;
                        }
                        //pPacket->pPayload = pPacket->pCurrent;

                        if(enable_hs)
                        {
                            /** by zzq, 2015.10.28, hyperscan the payload */
                            if(pPacket->unCtrlProtocol == IPPROTO_UDP)
                                pPacket->pPayload = pPacket->pTcpUdpInner + 8; 

                            pPacket->unPayloadLen = pPacket->pEnd - pPacket->pPayload;
                            hs_err = hs_scan(g_db[socket_id],
                                    (const char*)pPacket->pPayload, // data
                                    pPacket->unPayloadLen, // data length
                                    0, // flag
                                    g_scratch[lcore_id],
                                    NULL, // matchCallback
                                    NULL); // user data
                            if (hs_err != HS_SUCCESS) 
                            {
                                fprintf(stderr, "HS: ERROR: Unable to scan packet. Exiting.");
                                exit(-1);
                            }
                        }
                        /** --------------------- */
                    }
                }
                l2fwd_simple_forward(m, portid);
            }
		}
	}
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ] --ptn PTN_FILE\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
           "  --dec: enable simple decoding\n"
           "  --ptn PTN_FILE: pattern file path\n"
           "note: --ptn will enable simple decoding too\n", 
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
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

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
        {"dec", 0, 0, 0},
        {"ptn", 1, 0, 0}, 
		{NULL, 0, 0, 0}
	};

	argvopt = argv;
    g_ptn_file = NULL;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
            if(!strcmp(lgopts[option_index].name, "dec"))
            {
                g_dec = 1;
            }
            else if(!strcmp(lgopts[option_index].name, "ptn"))
            {
                g_dec = 1;
                g_hs = 1;
                g_ptn_file = optarg;
            }
            else
            {
                l2fwd_usage(prgname);
                return -1;
            }
            break;
		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */

    if(g_hs && g_ptn_file == NULL)
    {
        fprintf(stderr, "no pattern file path!\n");
        l2fwd_usage(prgname);
        return -1;
    }

	return ret;
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
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
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
			if (link.link_status == 0) {
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

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	int ret;
	uint8_t nb_ports;
	uint8_t nb_ports_available;
	uint8_t portid, last_port;
	unsigned lcore_id, rx_lcore_id, master_lcore_id;
	unsigned nb_ports_in_mask = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool =
		rte_mempool_create("mbuf_pool", NB_MBUF,
				   MBUF_SIZE, 32,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL,
    // by zzq, 2015.10.27, here rte_socket_id() means this pool don't 
	// support multi-cores optimizing
				   //rte_socket_id(), 0); 
                   SOCKET_ID_ANY, 0);
    
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	printf("mempool size: %d\n",l2fwd_pktmbuf_pool->size);

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

        /** by zzq, 2015.10.27, recv from one port and send to adjacent port,
         * e.g. -> rx0 -> tx1 ->
         *      <- tx0 <- rx1 <-
         */
		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;

		rte_eth_dev_info_get(portid, &dev_info);
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;
	master_lcore_id = rte_get_master_lcore();

	/* Initialize the port/queue configuration of each logical core */
	for (portid = 0; portid < nb_ports; portid++) 
	{
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/** by zzq, 2015.10.27, l2fwd_rx_queue_per_lcore is  l2fwd_rx_port_per_lcore 
		 * actually, because rx/tx queue is hard-coded to 1 */
		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
				rx_lcore_id == master_lcore_id ||
				lcore_queue_conf[rx_lcore_id].n_rx_port == l2fwd_rx_queue_per_lcore) 
		{
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id])
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
	}

	nb_ports_available = nb_ports;


    /** by zzq, 2015.10.27, for C++ compiling */
    //memset(&port_conf, 0, sizeof(struct rte_eth_conf));
    //port_conf.rxmode.split_hdr_size = 0;
    //port_conf.rxmode.header_split   = 0; /**< Header Split disabled */
    //port_conf.rxmode.hw_ip_checksum = 0; /**< IP checksum offload disabled */
    //port_conf.rxmode.hw_vlan_filter = 0; /**< VLAN filtering disabled */
    //port_conf.rxmode.jumbo_frame    = 0; /**< Jumbo Frame Support disabled */
    //port_conf.rxmode.hw_strip_crc   = 0; /**< CRC stripped by hardware */
    //port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    /** ------------------- */

	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", (unsigned) portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);
        /** by zzq, 2015.10.27, here rx & tx queue is hard-coded to 1 */
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

        /** by zzq, 2015.10.27, 2nd param: ONLY 1 rx queue */
		/* init one RX queue */
		fflush(stdout);
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, (unsigned) portid);

        /** by zzq, 2015.10.27, 2nd param: ONLY 1 tx queue */
		/* init one TX queue on each port */
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);


		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);

    if(g_hs)
    {
        if(hs_init() != 0)
        {
            fprintf(stderr, "hyperscan init failed!\n");
            exit(-1);
        }
    }

	/* launch per-lcore init on every lcore */
	//rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
    /** by zzq, 2015.10.27, to use ONLY ONE lcore(thread) intentionally */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, SKIP_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}

