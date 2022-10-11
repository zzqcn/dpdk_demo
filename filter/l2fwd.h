/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef __L2_FWD_H__
#define __L2_FWD_H__

#include <rte_ether.h>
#include <rte_vect.h>

#include "filter.h"

#if !defined(NO_HASH_MULTI_LOOKUP) && defined(RTE_MACHINE_CPUFLAG_NEON)
#  define NO_HASH_MULTI_LOOKUP 1
#endif

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_LCORE 16

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/* Used to mark destination port as 'invalid'. */
#define BAD_PORT ((uint16_t)-1)

#define FWDSTEP 4

/* replace first 12B of the ethernet header. */
#define MASK_ETH 0x3f

struct mbuf_table {
  uint16_t len;
  struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
  uint8_t port_id;
  uint8_t queue_id;
} __rte_cache_aligned;

struct rte_hash;

struct lcore_conf {
  uint16_t n_rx_queue;
  struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
  uint16_t n_tx_port;
  uint16_t tx_port_id[RTE_MAX_ETHPORTS];
  uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
  struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

  struct rte_hash *flow_table;
  uint32_t flow_count;

#ifdef STATS
  uint64_t rx_pkt_cnt[RTE_MAX_ETHPORTS];
  uint64_t tx_pkt_cnt[RTE_MAX_ETHPORTS];
#endif
} __rte_cache_aligned;

extern volatile bool force_quit;

/* ethernet addresses of ports */
extern uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
extern struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
extern uint32_t enabled_port_mask;

/* Used only in exact match mode. */
extern int ipv6; /**< ipv6 is false by default. */

extern xmm_t val_eth[RTE_MAX_ETHPORTS];

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* Send burst of packets on an output interface */
static inline int send_burst(struct lcore_conf *qconf, uint16_t n, uint8_t port) {
  struct rte_mbuf **m_table;
  int ret;
  uint16_t queueid;

  queueid = qconf->tx_queue_id[port];
  m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

  ret = rte_eth_tx_burst(port, queueid, m_table, n);
#ifdef STATS
  qconf->tx_pkt_cnt[port] += ret;
#endif
  if (unlikely(ret < n)) {
    do {
      rte_pktmbuf_free(m_table[ret]);
    } while (++ret < n);
  }

  return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int send_single_packet(struct lcore_conf *qconf, struct rte_mbuf *m, uint8_t port) {
  uint16_t len;

  len = qconf->tx_mbufs[port].len;
  qconf->tx_mbufs[port].m_table[len] = m;
  len++;

  /* enough pkts to be sent */
  if (unlikely(len == MAX_PKT_BURST)) {
    send_burst(qconf, MAX_PKT_BURST, port);
    len = 0;
  }

  qconf->tx_mbufs[port].len = len;
  return 0;
}

#endif
