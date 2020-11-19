
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#define RAW_MEMPOOL

#define MBUF_COUNT  (1024-1)
#define PRIV_SIZE   16
// ETH_MAX_len = 1518
// ETH_MTU = ETH_MAX_LEN - ETH_HDR_LEN - ETHER_CRC_LEN = 1518 - 14 - 4 = 1500
#define MBUF_DATAROOM_SIZE (RTE_PKTMBUF_HEADROOM + ETHER_MAX_LEN)
#define MBUF_SIZE   (sizeof(struct rte_mbuf) + PRIV_SIZE + MBUF_DATAROOM_SIZE)
#define CACHE_SIZE  32


static void mbuf_dump(struct rte_mbuf* m)
{
    printf("RTE_PKTMBUF_HEADROOM: %u\n", RTE_PKTMBUF_HEADROOM);
    printf("sizeof(mbuf): %lu\n", sizeof(struct rte_mbuf));
    printf("m: %p\n", m);
    printf("m->refcnt: %u\n", m->refcnt);
    printf("m->buf_addr: %p\n", m->buf_addr);
    printf("m->data_off: %u\n", m->data_off);
    printf("m->buf_len: %u\n", m->buf_len);
    printf("m->pkt_len: %u\n", m->pkt_len);
    printf("m->data_len: %u\n", m->data_len);
    printf("m->nb_segs: %u\n", m->nb_segs);
    printf("m->next: %p\n", m->next);
    printf("m->buf_addr+m->data_off: %p\n", (char*)m->buf_addr+m->data_off);
    printf("rte_pktmbuf_mtod(m): %p\n", rte_pktmbuf_mtod(m, char*));
    printf("rte_pktmbuf_data_len(m): %u\n", rte_pktmbuf_data_len(m));
    printf("rte_pktmbuf_pkt_len(m): %u\n", rte_pktmbuf_pkt_len(m)); 
    printf("rte_pktmbuf_headroom(m): %u\n", rte_pktmbuf_headroom(m));
    printf("rte_pktmbuf_tailroom(m): %u\n", rte_pktmbuf_tailroom(m));
    printf("rte_pktmbuf_data_room_size(mpool): %u\n", 
                rte_pktmbuf_data_room_size(m->pool));
    printf("rte_pktmbuf_priv_size(mpool): %u\n\n",
                rte_pktmbuf_priv_size(m->pool));
}

static int mbuf_demo(void)
{
    struct rte_mempool* mpool;
    struct rte_mbuf *m, *m2, *m3;
    struct rte_mempool_objsz objsz;
    uint32_t mbuf_size;

#ifdef RAW_MEMPOOL
    struct rte_pktmbuf_pool_private priv;
    priv.mbuf_data_room_size = MBUF_DATAROOM_SIZE;
    priv.mbuf_priv_size = PRIV_SIZE;

    mpool = rte_mempool_create("test_pool",
                               MBUF_COUNT,
                               MBUF_SIZE,
                               CACHE_SIZE,
                               sizeof(struct rte_pktmbuf_pool_private),
                               rte_pktmbuf_pool_init,
                               &priv,
                               rte_pktmbuf_init,
                               NULL,
                               SOCKET_ID_ANY,
                               MEMPOOL_F_SC_GET);
#else
    mpool = rte_pktmbuf_pool_create("test_pool",
                                    MBUF_COUNT,
                                    CACHE_SIZE,
                                    PRIV_SIZE,
                                    MBUF_DATAROOM_SIZE,
                                    SOCKET_ID_ANY);
#endif
    if(NULL == mpool)
        return -1;
    
    mbuf_size = rte_mempool_calc_obj_size(MBUF_SIZE, 0, &objsz);
    printf("mbuf_size: %u\n", mbuf_size);
    printf("elt_size: %u, header_size: %u, trailer_size: %u, total_size: %u\n",
        objsz.elt_size, objsz.header_size, objsz.trailer_size, objsz.total_size);

    m = rte_pktmbuf_alloc(mpool);
    rte_pktmbuf_append(m, 1000);
    mbuf_dump(m);

    m2 = rte_pktmbuf_alloc(mpool);
    rte_pktmbuf_append(m2, 500);
    mbuf_dump(m2);

    rte_pktmbuf_chain(m, m2);
    mbuf_dump(m);

    printf("mempool count before free: %u\n", rte_mempool_avail_count(mpool));
    rte_pktmbuf_free(m);
    printf("mempool count after free: %u\n\n", rte_mempool_avail_count(mpool));

    m = rte_pktmbuf_alloc(mpool);
    rte_pktmbuf_append(m, 1000);
    mbuf_dump(m);
    m2 = rte_pktmbuf_clone(m, mpool);
    mbuf_dump(m2);
    m3 = rte_pktmbuf_clone(m, mpool);
    mbuf_dump(m3);

    printf("mempool count before free: %u\n", rte_mempool_avail_count(mpool));
    printf("m->refcnt: %u\n", m->refcnt);
    rte_pktmbuf_free(m);
    printf("mempool count after free: %u\n", rte_mempool_avail_count(mpool));
    printf("m->refcnt: %u\n", m->refcnt);
    rte_pktmbuf_free(m3);
    printf("mempool count after free: %u\n", rte_mempool_avail_count(mpool));
    printf("m->refcnt: %u\n", m->refcnt);
    rte_pktmbuf_free(m2);
    printf("mempool count after free: %u\n", rte_mempool_avail_count(mpool));
    printf("m->refcnt: %u\n", m->refcnt);
    rte_pktmbuf_free(m);
    printf("mempool count after free: %u\n", rte_mempool_avail_count(mpool));
    printf("m->refcnt: %u\n", m->refcnt);
    
    return 0;
}



int
main(int argc, char **argv)
{
    int ret;
    //unsigned lcore_id;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    /* call on every slave lcore */
    //RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    //    rte_eal_remote_launch(lcore_hello, NULL, lcore_id);:
    //}

    mbuf_demo();

    rte_eal_mp_wait_lcore();
    return 0;
}

