#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include "public_api.h"

struct dispatch_node_ctx
{
    struct rte_ring *pkt_queues[2];
    uint64_t err_count;
};

static struct dispatch_node_ctx g_dispatch_node_ctxs[2];

int config_dispatch_node(struct dispatch_node_config *cfg)
{
    g_dispatch_node_ctxs->pkt_queues[0] = cfg->pkt_queues[0];
    g_dispatch_node_ctxs->pkt_queues[1] = cfg->pkt_queues[1];

    return 0;
}

static int
dispatch_node_init(const struct rte_graph *graph, struct rte_node *node)
{
    struct dispatch_node_ctx **p = (struct dispatch_node_ctx **)node->ctx;
    struct dispatch_node_ctx *ctx;

    *p = malloc(sizeof(struct dispatch_node_ctx));
    ctx = *p;

    ctx->pkt_queues[0] = g_dispatch_node_ctxs->pkt_queues[0];
    ctx->pkt_queues[1] = g_dispatch_node_ctxs->pkt_queues[1];
    ctx->err_count = 0;

    printf("dispatch_node: init\n");

    RTE_SET_USED(graph);

    return 0;
}

static __rte_always_inline uint16_t dispatch_node_process(
    struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
    int ret;
    struct dispatch_node_ctx **p = (struct dispatch_node_ctx **)node->ctx;
    struct dispatch_node_ctx *ctx = *p;
    struct rte_mbuf *m;
    uint16_t i;

    for (i = 0; i < cnt; i++) {
        m = (struct rte_mbuf *)objs[i];
        if (m->hash.rss % 2)
            ret = rte_ring_enqueue(ctx->pkt_queues[0], m);
        else
            ret = rte_ring_enqueue(ctx->pkt_queues[1], m);

        if (ret != 0) {
            rte_pktmbuf_free(m);
            ctx->err_count++;
        }
    }

    return cnt;
}

static struct rte_node_register dispatch_node_base = {
    .name = "dispatch",
    .init = dispatch_node_init,
    .process = dispatch_node_process,
};

struct rte_node_register *dispatch_node_get(void)
{
    return &dispatch_node_base;
}

RTE_NODE_REGISTER(dispatch_node_base);
