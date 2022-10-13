/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <rte_acl.h>

#include "filter.h"

static filter_rule_context_t *g_filter_ctx;

static void show_single_rule(const filter_rule_t *rule) {
  char buf[128];
  uint32_t n32;

  printf("%u priority:%d pattern{", rule->id, rule->priority);
  if (rule->has_acl) {
    if (rule->has_saddr) {
      n32 = htonl(rule->saddr);
      printf("saddr:%s/%u ", inet_ntop(AF_INET, &n32, buf, INET_ADDRSTRLEN), rule->saddr_mask);
    }
    if (rule->has_daddr) {
      n32 = htonl(rule->daddr);
      printf("daddr:%s/%u ", inet_ntop(AF_INET, &n32, buf, INET_ADDRSTRLEN), rule->daddr_mask);
    }
    if (rule->has_sport) {
      printf("sport:%u ", rule->sport);
    }
    if (rule->has_dport) {
      printf("dport:%u ", rule->dport);
    }
    if (rule->has_proto) {
      if (rule->proto == IPPROTO_TCP)
        printf("proto:tcp ");
      else if (rule->proto == IPPROTO_UDP)
        printf("proto:udp ");
      else
        printf("proto:%u ", rule->proto);
    }
  }
  if (rule->has_pktlen) {
    printf("pktlen:%u ", rule->pkt_len);
  }

  printf("\b} action:");
  switch (rule->action.type) {
  case FILTER_ACTION_DROP:
    printf("drop");
    break;
  case FILTER_ACTION_FORWARD:
    printf("forward/%hu", rule->action.port_id);
    break;
  case FILTER_ACTION_MARK:
    printf("mark/%u", rule->action.mark);
    break;
  case FILTER_ACTION_DISPATCH:
    printf("dispatch/%u", rule->action.lcore_id);
    break;
  default:
    printf("invalid");
    break;
  }
  printf("\n");
}

static void show_rules(filter_rule_context_t *rctx) {
  filter_rule_t *rule;

  TAILQ_FOREACH(rule, &rctx->rule_list, next) {
    show_single_rule(rule);
  }
}

static filter_rule_t *new_rule(void) {
  filter_rule_t *rule = rte_zmalloc("filter_rule", sizeof(filter_rule_t), 0);
  return rule;
}

static void free_rule(filter_rule_t *rule) {
  if (NULL == rule)
    return;
  rte_free(rule);
}

static const filter_rule_t *get_rule_by_id(const filter_rule_context_t *rctx, uint32_t id) {
  // rule id从1开始, 0代表没有匹配, 所以rule_map需要多分配一个
  if (id > rctx->rule_count)
    return NULL;
  return rctx->rule_map[id];
}

static int add_rule(filter_rule_context_t *rctx, filter_rule_t *rule) {
  if (rctx->rule_count >= FILTER_RULE_MAX) {
    return -1;
  }

  rule->id = ++rctx->rule_count;
  TAILQ_INSERT_TAIL(&rctx->rule_list, rule, next);
  rctx->rule_map[rule->id] = rule;

  return 0;
}

static int filter_init(void) {
  g_filter_ctx = rte_zmalloc("filter_ctx", sizeof(filter_rule_context_t), 0);
  if (NULL == g_filter_ctx) {
    return -1;
  }
  TAILQ_INIT(&g_filter_ctx->rule_list);

  return 0;
}

enum {
  FIELDv4_PROTO = 0,
  FIELDv4_SADDR,
  FIELDv4_DADDR,
  FIELDv4_SPORT,
  FIELDv4_DPORT,
};

enum {
  INPUTv4_PROTO = 0,
  INPUTv4_SADDR,
  INPUTv4_DADDR,
  INPUTv4_PORTS,
};

const struct rte_acl_field_def acl_defs_v4[] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = FIELDv4_PROTO,
        .input_index = INPUTv4_PROTO,
        .offset = 0,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = FIELDv4_SADDR,
        .input_index = INPUTv4_SADDR,
        .offset =
            offsetof(struct rte_ipv4_hdr, src_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = FIELDv4_DADDR,
        .input_index = INPUTv4_DADDR,
        .offset =
            offsetof(struct rte_ipv4_hdr, dst_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = FIELDv4_SPORT,
        .input_index = INPUTv4_PORTS,
        .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = FIELDv4_DPORT,
        .input_index = INPUTv4_PORTS,
        .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id) +
                  sizeof(uint16_t),
    },
};

RTE_ACL_RULE_DEF(ipv4_rule, RTE_DIM(acl_defs_v4));

static void convert_rule(filter_rule_t *rule, struct ipv4_rule *r4) {
  r4->data.userdata = rule->id;
  r4->data.category_mask = 1;
  r4->data.priority = rule->priority;

  if (rule->has_proto) {
    r4->field[FIELDv4_PROTO].value.u8 = rule->proto;
    r4->field[FIELDv4_PROTO].mask_range.u8 = 0xff;
  }
  if (rule->has_saddr) {
    r4->field[FIELDv4_SADDR].value.u32 = rule->saddr;
    r4->field[FIELDv4_SADDR].mask_range.u32 = rule->saddr_mask;
  }
  if (rule->has_daddr) {
    r4->field[FIELDv4_DADDR].value.u32 = rule->daddr;
    r4->field[FIELDv4_DADDR].mask_range.u32 = rule->daddr_mask;
  }
  if (rule->has_sport) {
    r4->field[FIELDv4_SPORT].value.u16 = rule->sport;
    r4->field[FIELDv4_SPORT].mask_range.u16 = 0xffff;
  }
  /** @warning 不指定端口时这里也是不能去掉的, 必须置0 */
  else {
    r4->field[FIELDv4_SPORT].value.u16 = 0;
    r4->field[FIELDv4_SPORT].mask_range.u16 = 0xffff;
  }
  if (rule->has_dport) {
    r4->field[FIELDv4_DPORT].value.u16 = rule->dport;
    r4->field[FIELDv4_DPORT].mask_range.u16 = 0xffff;
  }
  /** @warning 不指定端口时这里也是不能去掉的, 必须置0 */
  else {
    r4->field[FIELDv4_DPORT].value.u16 = 0;
    r4->field[FIELDv4_DPORT].mask_range.u16 = 0xffff;
  }
}

static int filter_apply(filter_rule_context_t *rctx) {
  int ret;
  struct rte_acl_config cfg;
  filter_rule_t *rule;
  struct ipv4_rule *ipv4_rules = NULL, *r4;
  unsigned v4_cnt;

  struct rte_acl_param param_v4 = {
      .name = "filter_acl",
      .socket_id = SOCKET_ID_ANY,
      .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(acl_defs_v4)),
      .max_rule_num = FILTER_RULE_MAX,
  };

  v4_cnt = 0;
  TAILQ_FOREACH(rule, &rctx->rule_list, next) {
    if (rule->has_acl) {
      v4_cnt++;
    }
  }

  if (v4_cnt > 0) {
    ipv4_rules = rte_zmalloc("acl_rules_v4", sizeof(struct ipv4_rule) * v4_cnt, 0);
    if (NULL == ipv4_rules) {
      RTE_LOG(ERR, FILTER, "alloc ipv4 rules failed\n");
      goto fail;
    }
  }

  v4_cnt = 0;
  TAILQ_FOREACH(rule, &rctx->rule_list, next) {
    if (rule->has_acl) {
      r4 = ipv4_rules + v4_cnt;
      convert_rule(rule, r4);
      v4_cnt++;
    }
  }

  if (v4_cnt > 0) {
    rctx->acl_ctx = rte_acl_create(&param_v4);
    if (NULL == rctx->acl_ctx) {
      RTE_LOG(ERR, FILTER, "create v4 acl context failed\n");
      goto fail;
    }

    ret = rte_acl_add_rules(rctx->acl_ctx, (const struct rte_acl_rule *)ipv4_rules, v4_cnt);
    if (ret != 0) {
      RTE_LOG(ERR, FILTER, "add v4 acl rule failed\n");
      goto fail;
    }

    cfg.num_categories = 1;
    cfg.num_fields = RTE_DIM(acl_defs_v4);
    cfg.max_size = 0;
    memcpy(cfg.defs, acl_defs_v4, sizeof(acl_defs_v4));

    ret = rte_acl_build(rctx->acl_ctx, &cfg);
    if (ret != 0) {
      RTE_LOG(ERR, FILTER, "build v4 acl context failed\n");
      goto fail;
    }

#ifdef DEBUG
    RTE_LOG(DEBUG, FILTER, "ACL ctx internal info:\n");
    rte_acl_dump(rctx->acl_ctx);
#endif
    rte_free(ipv4_rules);
  }
  rctx->rule_count = v4_cnt;

  return 0;

fail:
  if (ipv4_rules != NULL) {
    rte_free(ipv4_rules);
  }
  if (rctx->acl_ctx != NULL) {
    rte_acl_free(rctx->acl_ctx);
    rctx->acl_ctx = NULL;
  }

  return -1;
}

#define COMMENT_LEAD_CHAR ('#')

enum {
  CB_FLD_SRC_ADDR,
  CB_FLD_DST_ADDR,
  CB_FLD_SRC_PORT,
  CB_FLD_DST_PORT,
  CB_FLD_PROTO,
  CB_FLD_PKTLEN,
  CB_FLD_ACTION,
  CB_FLD_PRIORITY,
  CB_FLD_NUM,
};

static int get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim, char dlm) {
  unsigned long val;
  char *end;

  errno = 0;
  val = strtoul(*in, &end, base);
  if (errno != 0 || end[0] != dlm || val > lim)
    return -EINVAL;
  *fd = (uint32_t)val;
  *in = end + 1;
  return 0;
}

static int parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len) {
  uint32_t a, b, c, d, m;

  if (get_cb_field(&in, &a, 0, UINT8_MAX, '.'))
    return -EINVAL;
  if (get_cb_field(&in, &b, 0, UINT8_MAX, '.'))
    return -EINVAL;
  if (get_cb_field(&in, &c, 0, UINT8_MAX, '.'))
    return -EINVAL;
  if (get_cb_field(&in, &d, 0, UINT8_MAX, '/'))
    return -EINVAL;
  if (get_cb_field(&in, &m, 0, sizeof(uint32_t) * CHAR_BIT, 0))
    return -EINVAL;

  addr[0] = RTE_IPV4(a, b, c, d);
  mask_len[0] = m;
  return 0;
}

static int parse_action(char *in, filter_action_t *action) {
  char *p;
  unsigned long val;

  p = strchr(in, '/');
  if (NULL == p)
    return -EINVAL;

  errno = 0;
  val = strtoul(p + 1, NULL, 10);
  if (errno != 0 || val > UINT32_MAX)
    return -EINVAL;

  if (!strncasecmp("drop", in, 4)) {
    action->type = FILTER_ACTION_DROP;
  } else if (!strncasecmp("mark", in, 4)) {
    action->type = FILTER_ACTION_MARK;
    action->mark = (uint32_t)val;
  } else if (!strncasecmp("forward", in, 7)) {
    action->type = FILTER_ACTION_FORWARD;
    if (val > RTE_MAX_ETHPORTS)
      return -EINVAL;
    action->port_id = (uint16_t)val;
  } else if (!strncasecmp("dispatch", in, 8)) {
    action->type = FILTER_ACTION_DISPATCH;
    if (val > RTE_MAX_LCORE)
      return -EINVAL;
    action->lcore_id = (uint16_t)val;
  } else {
    return -EINVAL;
  }

  return 0;
}

static int parse_ipv4_rule(char *str, filter_rule_t *rule) {
  int i, ret;
  char *s, *sp, *in[CB_FLD_NUM];
  static const char *dlm = " \t\n";
  int dim = CB_FLD_NUM;
  uint32_t temp;

  s = str;
  for (i = 0; i != dim; i++, s = NULL) {
    in[i] = strtok_r(s, dlm, &sp);
    if (in[i] == NULL)
      return -EINVAL;
  }

  ret = parse_ipv4_net(in[CB_FLD_SRC_ADDR], &rule->saddr, &rule->saddr_mask);
  if (ret != 0) {
    RTE_LOG(ERR, FILTER, "failed to read source address/mask: %s\n", in[CB_FLD_SRC_ADDR]);
    return ret;
  }
  if (rule->saddr != 0)
    rule->has_saddr = 1;

  ret = parse_ipv4_net(in[CB_FLD_DST_ADDR], &rule->daddr, &rule->daddr_mask);
  if (ret != 0) {
    RTE_LOG(ERR, FILTER, "failed to read destination address/mask: %s\n", in[CB_FLD_DST_ADDR]);
    return ret;
  }
  if (rule->daddr != 0)
    rule->has_daddr = 1;

  if (get_cb_field(&in[CB_FLD_SRC_PORT], &temp, 0, UINT16_MAX, 0))
    return -EINVAL;
  rule->sport = (uint16_t)temp;
  if (rule->sport != 0)
    rule->has_sport = 1;

  if (get_cb_field(&in[CB_FLD_DST_PORT], &temp, 0, UINT16_MAX, 0))
    return -EINVAL;
  rule->dport = (uint16_t)temp;
  if (rule->dport != 0)
    rule->has_dport = 1;

  if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, 0))
    return -EINVAL;
  rule->proto = (uint8_t)temp;
  if (rule->proto != 0)
    rule->has_proto = 1;

  if (get_cb_field(&in[CB_FLD_PKTLEN], &temp, 0, UINT16_MAX, 0))
    return -EINVAL;
  rule->pkt_len = (uint16_t)temp;
  if (rule->pkt_len != 0)
    rule->has_pktlen = 1;

  if (rule->has_saddr || rule->has_daddr || rule->has_sport || rule->has_dport || rule->has_proto)
    rule->has_acl = 1;

  ret = parse_action(in[CB_FLD_ACTION], &rule->action);
  if (ret != 0) {
    RTE_LOG(ERR, FILTER, "failed to read action: %s\n", in[CB_FLD_ACTION]);
    return ret;
  }

  if (get_cb_field(&in[CB_FLD_PRIORITY], &temp, 0, UINT16_MAX, 0))
    return -EINVAL;
  rule->priority = (uint16_t)temp;
  if (rule->priority > FILTER_PRIORITY_MAX)
    ret = -EINVAL;

  return ret;
}

/* Bypass comment and empty lines */
static inline int is_bypass_line(char *buff) {
  int i = 0;

  /* comment line */
  if (buff[0] == COMMENT_LEAD_CHAR)
    return 1;
  /* empty line */
  while (buff[i] != '\0') {
    if (!isspace(buff[i]))
      return 0;
    i++;
  }
  return 1;
}

// static uint32_t convert_depth_to_bitmask(uint32_t depth_val) {
//   uint32_t bitmask = 0;
//   int i, j;

//   for (i = depth_val, j = 0; i > 0; i--, j++)
//     bitmask |= (1 << (31 - j));
//   return bitmask;
// }

/* Reads file and calls the add_classify_rule function. 8< */
// static int add_rules(const char *rule_path, struct flow_classifier *cls_app) {
int filter_load_rules(const char *rule_path) {
  int ret;
  FILE *fh;
  char buff[LINE_MAX];
  unsigned i = 0;
  unsigned total_num = 0;
  filter_rule_t *rule;

  fh = fopen(rule_path, "rb");
  if (fh == NULL)
    rte_exit(EXIT_FAILURE, "fopen rule file %s failed\n", rule_path);

  ret = fseek(fh, 0, SEEK_SET);
  if (ret)
    rte_exit(EXIT_FAILURE, "fseek %d failed\n", ret);

  ret = filter_init();
  if (ret != 0)
    rte_exit(EXIT_FAILURE, "Init filter failed\n");

  i = 0;
  while (fgets(buff, LINE_MAX, fh) != NULL) {
    i++;

    if (is_bypass_line(buff))
      continue;

    if (total_num >= FILTER_RULE_MAX - 1) {
      RTE_LOG(WARNING, FILTER, "classify rule capacity %d reached\n", total_num);
      break;
    }

    rule = new_rule();
    if (NULL == rule)
      return -1;

    if (parse_ipv4_rule(buff, rule) != 0)
      rte_exit(EXIT_FAILURE, "%s Line %u: parse rules error\n", rule_path, i);

    add_rule(g_filter_ctx, rule);
    total_num++;
  }

  fclose(fh);

#ifdef DEBUG
  RTE_LOG(DEBUG, FILTER, "Parsed %u rules\n", total_num);
  show_rules(g_filter_ctx);
#endif

  ret = filter_apply(g_filter_ctx);
  if (ret != 0) {
    rte_exit(EXIT_FAILURE, "Build filter rules failed\n");
  }
  RTE_LOG(INFO, FILTER, "Build filter rules OK\n");

  return 0;
}

static void show_action(const packet_t *pkt, const filter_rule_t *rule) {

  if (pkt->l3_type != L3_TYPE_IPv4) {
    printf(">not ipv4 packet\n");
    return;
  }

  print_packet(pkt);

  printf("Rule:%u\t", rule->id);
  switch (rule->action.type) {
  case FILTER_ACTION_DROP:
    printf("drop\n");
    break;
  case FILTER_ACTION_FORWARD:
    printf("forword/%u\n", rule->action.port_id);
    break;
  case FILTER_ACTION_MARK:
    printf("mark/%u\n", rule->action.mark);
    break;
  case FILTER_ACTION_DISPATCH:
    printf("dispatch/%u\n", rule->action.lcore_id);
    break;
  default:
    break;
  }
}

#define OFF_IPv42PROTO (offsetof(struct rte_ipv4_hdr, next_proto_id))
// #define OFF_IPv62PROTO (offsetof(struct rte_ipv6_hdr, proto))
// #define OFF_IPv42TTL   (offsetof(struct rte_ipv4_hdr, time_to_live))
// #define OFF_IPv62TTL   (offsetof(struct rte_ipv6_hdr, hop_limits))

int filter_process(packet_t *pkt) {
  int ret = 0;
  uint32_t results[1] = {0};
  filter_rule_context_t *rctx;
  const filter_rule_t *rule = NULL;
  int action_type = FILTER_ACTION_BYPASS;
  const uint8_t *data = NULL;
  int l3_type = pkt->l3_type;
  int l4_type = pkt->l4_type;

  // stage1: 基本协议判断
  if (l3_type != L3_TYPE_IPv4) {
    // dont' care
    return 0;
  }
  switch (l4_type) {
  case L4_TYPE_TCP:
  case L4_TYPE_UDP:
    break;
  default:
    // dont' care
    return 0;
  }

  rctx = g_filter_ctx;

  // stage2: ACL, 包括ip地址, 端口, TTL, 协议
  if (rctx->rule_count < 1)
    goto action;
  if (NULL == rctx->acl_ctx)
    goto action;

  data = packet_outer_l3_hdr(pkt, const uint8_t *) + OFF_IPv42PROTO;
  ret = rte_acl_classify(rctx->acl_ctx, &data, results, 1, 1);
  if (ret != 0 || 0 == results[0]) {
    goto action;
  }

  rule = get_rule_by_id(rctx, results[0]);

  // stage3: 报文总长度
  // pktlen:
  if (rule->has_pktlen) {
    if (pkt->mbuf->pkt_len == rule->pkt_len) {
      action_type = rule->action.type;
    } else {
      rule = NULL;
      action_type = FILTER_ACTION_BYPASS;
    }
  } else {
    action_type = rule->action.type;
  }

action:
  if (NULL == rule || FILTER_ACTION_BYPASS == action_type)
    goto end;

  show_action(pkt, rule);

end:
  return 0;
}
