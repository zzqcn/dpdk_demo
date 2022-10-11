#ifndef __DECODE_H__
#define __DECODE_H__

#include "common.h"

#include <rte_net.h>

/** 3层协议类型 */
enum l3_type {
  L3_TYPE_UNKNOWN = 0,
  L3_TYPE_IPv4,
  L3_TYPE_IPv6,
};

/** 4层协议类型 */
enum l4_type {
  L4_TYPE_UNKNOWN,
  L4_TYPE_TCP,
  L4_TYPE_UDP,
  L4_TYPE_SCTP,
  L4_TYPE_ICMP,
};

enum tunnel_type {
  TUNNEL_TYPE_UNKNOWN = 0,
  TUNNEL_TYPE_IP,
  TUNNEL_TYPE_GRE,
  TUNNEL_TYPE_NVGRE,
  TUNNEL_TYPE_VXLAN,
  TUNNEL_TYPE_GTPU,
};

typedef struct packet {
  struct rte_mbuf *mbuf;

  union {
    uint32_t proto_shortcut;
    struct {
      uint32_t not_support : 1;
      uint32_t has_tunnel : 1;
      uint32_t has_inner_l2 : 1;
      uint32_t has_inner_l3 : 1;
      uint32_t has_inner_l4 : 1;
      uint32_t l3_type : 3;
      uint32_t l4_type : 4;
      uint32_t tunnel_type : 3;
      uint32_t inner_l3_type : 3;
      uint32_t inner_l4_type : 4;
      uint32_t frag : 1;
      uint32_t inner_frag : 1;
    };
  };
  union {
    uint32_t basic_meta;
    struct {
      uint32_t frame_type : 4;
      uint32_t forward_type : 4;
      uint32_t direction : 2;
      uint32_t tx_port : 5;
      uint32_t clone_tx_port : 5;
    };
  };

  union {
    uint64_t proto_offsets;
    struct {
      uint8_t l2_off;
      uint8_t l3_off;
      uint8_t l4_off;
      uint8_t tunnel_off;
      uint8_t inner_l2_off;
      uint8_t inner_l3_off;
      uint8_t inner_l4_off;
    };
  };
} __rte_cache_aligned packet_t;

#define packet_outer_l2_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, 0)
#define packet_inner_l2_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->inner_l2_off)
#define packet_outer_l3_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->l3_off)
#define packet_inner_l3_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->inner_l3_off)
#define packet_outer_l4_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->l4_off)
#define packet_inner_l4_hdr(pkt, t) rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->inner_l4_off)
#define packet_tunnel_hdr(pkt, t)   rte_pktmbuf_mtod_offset((pkt)->mbuf, t, (pkt)->tunnel_off)

static inline const char *l4_name(unsigned type) {
  switch (type) {
  case L4_TYPE_TCP:
    return "TCP";
  case L4_TYPE_UDP:
    return "UDP";
  case L4_TYPE_ICMP:
    return "ICMP";
  default:
    return "UNKNOWN";
  }
}

void decode_packet(struct rte_mbuf *m);
void print_packet(const packet_t* pkt);

#endif
