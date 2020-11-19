#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "public_api.h"

enum
{
    DEQUEUE_NEXT_FLOW,
    DEQUEUE_NEXT_MAX
};

struct dequeue_node_main
{
    struct rte_ring *pkt_queues[2];
};

static struct dequeue_node_main g_dequeue_node_main;
static int g_idx = 0;

struct dequeue_node_ctx
{
    struct rte_ring *pkt_queue;
    uint16_t next;
};


int config_dequeue_node(struct dequeue_node_config *cfg)
{
    g_dequeue_node_main.pkt_queues[0] = cfg->pkt_queues[0];
    g_dequeue_node_main.pkt_queues[1] = cfg->pkt_queues[1];

    return 0;
}

static int
dequeue_node_init(const struct rte_graph *graph, struct rte_node *node)
{
    struct dequeue_node_ctx *ctx = (struct dequeue_node_ctx *)node->ctx;

    ctx->pkt_queue = g_dequeue_node_main.pkt_queues[g_idx % 2];
    g_idx++;
    ctx->next = DEQUEUE_NEXT_FLOW;

    RTE_SET_USED(graph);

    return 0;
}

static __rte_always_inline uint16_t dequeue_node_process(
    struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
    struct dequeue_node_ctx *ctx = (struct dequeue_node_ctx *)node->ctx;
    struct rte_ring *r = ctx->pkt_queue;
    uint16_t n_pkts = 0;
    uint16_t next_index, count;

    RTE_SET_USED(objs);
    RTE_SET_USED(cnt);

    next_index = ctx->next;

    count = rte_ring_dequeue_burst(r, node->objs, RTE_GRAPH_BURST_SIZE, NULL);

    if (!count)
        return 0;

    
    node->idx = count;
    /* Enqueue to next node */
    rte_node_next_stream_move(graph, node, next_index);

    return count;
}

static struct rte_node_register dequeue_node_base = {
    .name = "dequeue",
    .flags = RTE_NODE_SOURCE_F,

    .init = dequeue_node_init,
    .process = dequeue_node_process,

    .nb_edges = DEQUEUE_NEXT_MAX,
    .next_nodes =
        {
            [DEQUEUE_NEXT_FLOW] = "flow",
        },
};

struct rte_node_register *dequeue_node_get(void)
{
    return &dequeue_node_base;
}

RTE_NODE_REGISTER(dequeue_node_base);
