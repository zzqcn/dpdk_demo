#ifndef __FILTER_H__
#define __FILTER_H__

#include "common.h"
#include "decode.h"

#define FILTER_RULE_MAX     1024
#define FILTER_PRIORITY_MAX UINT16_MAX

enum filter_action_type {
  FILTER_ACTION_BYPASS = 0,
  FILTER_ACTION_DROP,     /**< 丢弃 */
  FILTER_ACTION_FORWARD,  /**< 直接转发, 不进worker */
  FILTER_ACTION_MARK,     /**< 打标记 */
  FILTER_ACTION_DISPATCH, /**< 发送到指定worker, 通过lcore id指定 */
};

typedef struct filter_action {
  int type;
  union {
    uint32_t mark;
    uint16_t port_id;
    uint16_t lcore_id;
  };
} filter_action_t;

typedef struct filter_rule {
  uint32_t id;

  // patterns
  rte_le32_t saddr;
  rte_le32_t daddr;
  rte_le32_t saddr_mask;
  rte_le32_t daddr_mask;
  rte_le16_t sport;
  rte_le16_t dport;
  uint8_t proto;
  uint32_t pkt_len;

  union {
    uint32_t flags;
    struct {
      uint32_t has_saddr : 1;
      uint32_t has_daddr : 1;
      uint32_t has_sport : 1;
      uint32_t has_dport : 1;
      uint32_t has_proto : 1;
      uint32_t has_pktlen : 1;
      uint32_t has_acl : 1;
    };
  };

  // action
  filter_action_t action;

  // priority
  int32_t priority;

  TAILQ_ENTRY(filter_rule) next;
} filter_rule_t;

TAILQ_HEAD(filter_rule_list, filter_rule);
typedef struct filter_rule_list filter_rule_list_t;

typedef struct filter_rule_context {
  uint32_t rule_count;
  filter_rule_list_t rule_list;
  // rule id从1开始, 0代表没有匹配, 所以rule_map需要多分配一个
  filter_rule_t *rule_map[FILTER_RULE_MAX + 1];

  struct rte_acl_ctx *acl_ctx;
} filter_rule_context_t;

int filter_load_rules(const char *rule_path);
int filter_process(packet_t *pkt);

#endif
