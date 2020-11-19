#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "public_api.h"

enum
{
    FLOW_NEXT_DROP,
    FLOW_NEXT_MAX
};

struct flow_node_ctx
{
    uint16_t next;
};

int config_flow_node(struct flow_node_config *cfg)
{
    return 0;
}

static int flow_node_init(const struct rte_graph *graph, struct rte_node *node)
{
    struct flow_node_ctx **p = (struct flow_node_ctx **)node->ctx;
    struct flow_node_ctx *ctx;

    *p = malloc(sizeof(struct flow_node_ctx));
    ctx = *p;

    ctx->next = FLOW_NEXT_DROP;

    RTE_SET_USED(graph);

    return 0;
}

static __rte_always_inline uint16_t flow_node_process(struct rte_graph *graph,
                                                      struct rte_node *node,
                                                      void **objs,
                                                      uint16_t cnt)
{
    int ret;
    struct flow_node_ctx **p = (struct flow_node_ctx **)node->ctx;
    struct flow_node_ctx *ctx = *p;
    uint16_t next_index;

    next_index = ctx->next;
    /* Enqueue to next node */
    rte_node_next_stream_move(graph, node, next_index);

    return cnt;
}

static struct rte_node_register flow_node_base = {
    .name = "flow",
    .init = flow_node_init,
    .process = flow_node_process,

    .nb_edges = FLOW_NEXT_MAX,
    .next_nodes =
        {
            [FLOW_NEXT_DROP] = "drop",
        },
};

struct rte_node_register *flow_node_get(void)
{
    return &flow_node_base;
}

RTE_NODE_REGISTER(flow_node_base);
