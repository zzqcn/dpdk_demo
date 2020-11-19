#ifndef __GRAPH_NODE_PUBLIC_API_H__
#define __GRAPH_NODE_PUBLIC_API_H__

#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_ring;


struct rx_node_config
{
    uint16_t port_id;
    uint16_t queue_id;
};

struct dispatch_node_config
{
    struct rte_ring* pkt_queues[2];
};

struct dequeue_node_config
{
    struct rte_ring* pkt_queues[2];
};

struct flow_node_config
{
    uint32_t max_entry;
};


int config_rx_node(struct rx_node_config* cfg);
int config_dispatch_node(struct dispatch_node_config* cfg);
int config_dequeue_node(struct dequeue_node_config* cfg);
int config_flow_node(struct flow_node_config* cfg);

#ifdef __cplusplus
}
#endif

#endif
