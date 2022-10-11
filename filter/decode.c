#include "decode.h"

void decode_packet(struct rte_mbuf *m) {
  packet_t *pkt;
  uint32_t ptype;
  unsigned off = 0;
  struct rte_net_hdr_lens hdr_lens = {
      .l3_len = 0,
      .l4_len = 0,
      .tunnel_len = 0,
      .inner_l2_len = 0,
      .inner_l3_len = 0,
      .inner_l4_len = 0,
  };

  pkt = m->buf_addr;
  pkt->mbuf = m;

  ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
  if (0 == ptype)
    goto not_support;

  // outer l2
  if (ptype & RTE_PTYPE_L2_MASK) {
    pkt->l2_off = 0;
    off += hdr_lens.l2_len;
  } else
    goto not_support;

  // outer l3
  if (ptype & RTE_PTYPE_L3_MASK) {
    if (RTE_ETH_IS_IPV4_HDR(ptype)) {
      pkt->l3_type = L3_TYPE_IPv4;
    } else if (RTE_ETH_IS_IPV6_HDR(ptype)) {
      pkt->l3_type = L3_TYPE_IPv6;
    } else
      goto not_support;
    pkt->l3_off = off;
    off += hdr_lens.l3_len;
  }

  // outer l4
  if (ptype & RTE_PTYPE_L4_MASK) {
    if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
      pkt->l4_type = L4_TYPE_TCP;
    } else if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP) {
      pkt->l4_type = L4_TYPE_UDP;
    } else if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP) {
      pkt->l4_type = L4_TYPE_ICMP;
    } else if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_FRAG) {
      pkt->frag = 1;
      goto end;
    }
    pkt->l4_off = off;
    off += hdr_lens.l4_len;
  }

  // tunnel
  if ((ptype & RTE_PTYPE_TUNNEL_MASK) && (hdr_lens.tunnel_len > 0)) {
    pkt->has_tunnel = 1;
    pkt->tunnel_off = off;
    off += hdr_lens.tunnel_len;

    if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_IP)
      pkt->tunnel_type = TUNNEL_TYPE_IP;
    else if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_GRE)
      pkt->tunnel_type = TUNNEL_TYPE_GRE;
    else if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_NVGRE)
      pkt->tunnel_type = TUNNEL_TYPE_NVGRE;
    else if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_VXLAN)
      pkt->tunnel_type = TUNNEL_TYPE_VXLAN;
    else if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_GTPU)
      pkt->tunnel_type = TUNNEL_TYPE_GTPU;
    else
      goto end;
  }

  // inner l2
  if (ptype & RTE_PTYPE_INNER_L2_MASK) {
    pkt->has_inner_l2 = 1;
    pkt->inner_l2_off = off;
    off += hdr_lens.inner_l2_len;
  }

  // inner l3
  if (ptype & RTE_PTYPE_INNER_L3_MASK) {
    uint32_t t = ptype & RTE_PTYPE_INNER_L3_MASK;
    if ((t == RTE_PTYPE_INNER_L3_IPV4) || (t == RTE_PTYPE_INNER_L3_IPV4_EXT) ||
        (t == RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN)) {
      pkt->inner_l3_type = L3_TYPE_IPv4;
    } else if ((t == RTE_PTYPE_INNER_L3_IPV6) || (t == RTE_PTYPE_INNER_L3_IPV6_EXT) ||
               (t == RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN)) {
      pkt->inner_l3_type = L3_TYPE_IPv6;
    } else
      goto end;
    pkt->has_inner_l3 = 1;
    pkt->inner_l3_off = off;
    off += hdr_lens.inner_l3_len;
  }

  // inner l4
  if (ptype & RTE_PTYPE_INNER_L4_MASK) {
    if ((ptype & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_TCP) {
      pkt->inner_l4_type = L4_TYPE_TCP;
    } else if ((ptype & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_UDP) {
      pkt->inner_l4_type = L4_TYPE_UDP;
    } else if ((ptype & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_ICMP) {
      pkt->inner_l4_type = L4_TYPE_ICMP;
      // pkt->payload_len -= hdr_lens.inner_l4_len;
    } else if ((ptype & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_FRAG) {
      pkt->inner_frag = 1;
      goto end;
    }
    pkt->has_inner_l4 = 1;
    pkt->inner_l4_off = off;
    off += hdr_lens.inner_l4_len;
  }

end:
  m->packet_type = ptype;
  return;

not_support:
  pkt->not_support = 1;
}

// IPv4地址格式化
/* not defined under linux */
#ifndef NIPQUAD
#  define NIPQUAD_FMT "%u.%u.%u.%u"
#  define NIPQUAD(addr)                                                                       \
    (unsigned)((const unsigned char *)&addr)[0], (unsigned)((const unsigned char *)&addr)[1], \
        (unsigned)((const unsigned char *)&addr)[2], (unsigned)((const unsigned char *)&addr)[3]
#endif

void print_packet(const packet_t *pkt) {
  struct rte_ipv4_hdr *ip_hdr;
  struct rte_tcp_hdr *tcp_hdr;
  struct rte_udp_hdr *udp_hdr;
  rte_be16_t sport = 0, dport = 0;

  if (pkt->l3_type != L3_TYPE_IPv4)
    return;
  ip_hdr = packet_outer_l3_hdr(pkt, struct rte_ipv4_hdr *);

  if (pkt->l4_type == L4_TYPE_TCP) {
    tcp_hdr = packet_outer_l4_hdr(pkt, struct rte_tcp_hdr *);
    sport = tcp_hdr->src_port;
    dport = tcp_hdr->dst_port;
  } else if (pkt->l4_type == L4_TYPE_UDP) {
    udp_hdr = packet_outer_l4_hdr(pkt, struct rte_udp_hdr *);
    sport = udp_hdr->src_port;
    dport = udp_hdr->dst_port;
  }

  printf(">" NIPQUAD_FMT ":%u\t" NIPQUAD_FMT ":%u\t%s\tLen:%u\t", NIPQUAD(ip_hdr->src_addr),
         rte_be_to_cpu_16(sport), NIPQUAD(ip_hdr->dst_addr), rte_be_to_cpu_16(dport),
         l4_name(pkt->l4_type), pkt->mbuf->data_len);
}
