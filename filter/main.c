/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <sys/queue.h>
#include <sys/types.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_net.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_ring.h>
#include <rte_string_fns.h>

// #include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "decode.h"
#include "filter.h"
#include "l2fwd.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 32

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
// static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* Ports set in promiscuous mode off by default. */
static int opt_promiscuous_on;
static int opt_numa_on = 1; /**< NUMA is enabled by default. */
const char *opt_rule_path;

/* Global variables. */

volatile bool force_quit;

/* mask of enabled ports */
uint32_t enabled_port_mask;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct l2fwd_main_ctx {
  unsigned master_lcore_id;
} l2fwd_main;

struct lcore_params {
  uint16_t port_id;
  uint16_t queue_id;
  unsigned lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 1},
    {0, 1, 2},
    {1, 0, 1},
    {1, 1, 2},
};

static const int port_tx_table[] = {
    1,
    0,
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS,
            .split_hdr_size = 0,
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

static int check_lcore_params(void) {
  uint8_t queue, lcore;
  uint16_t i;
  unsigned socket_id;

  for (i = 0; i < nb_lcore_params; ++i) {
    queue = lcore_params[i].queue_id;
    if (queue >= MAX_RX_QUEUE_PER_PORT) {
      printf("invalid queue number: %hhu\n", queue);
      return -1;
    }
    lcore = lcore_params[i].lcore_id;
    if (!rte_lcore_is_enabled(lcore)) {
      printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
      return -1;
    }
    if ((socket_id = rte_lcore_to_socket_id(lcore) != 0) && (opt_numa_on == 0)) {
      printf("warning: lcore %hhu is on socket %d with numa off \n", lcore, socket_id);
    }
  }
  return 0;
}

static int check_port_config(void) {
  uint16_t port_id, i;

  for (i = 0; i < nb_lcore_params; ++i) {
    port_id = lcore_params[i].port_id;
    if ((enabled_port_mask & (1 << port_id)) == 0) {
      printf("port %u is not enabled in port mask\n", port_id);
      return -1;
    }
  }
  return 0;
}

static uint16_t get_port_n_rx_queues(uint16_t port_id) {
  uint16_t queue = 0;
  uint16_t i;

  for (i = 0; i < nb_lcore_params; ++i) {
    if (lcore_params[i].port_id == port_id) {
      if (lcore_params[i].queue_id == queue)
        queue = lcore_params[i].queue_id + 1;
      else
        rte_exit(EXIT_FAILURE,
                 "queue id of the port %d must be"
                 " in sequence and must start with 0, queue_id: %u\n",
                 lcore_params[i].port_id, queue);
    }
  }

  return queue;
}

static int init_lcore_rx_queues(void) {
  uint16_t i, nb_rx_queue;
  unsigned lcore_id;

  for (i = 0; i < nb_lcore_params; ++i) {
    lcore_id = lcore_params[i].lcore_id;
    nb_rx_queue = lcore_conf[lcore_id].n_rx_queue;
    if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
      printf("error: too many queues (%u) for lcore_id: %u\n", (unsigned)nb_rx_queue + 1,
             (unsigned)lcore_id);
      return -1;
    } else {
      lcore_conf[lcore_id].rx_queue_list[nb_rx_queue].port_id = lcore_params[i].port_id;
      lcore_conf[lcore_id].rx_queue_list[nb_rx_queue].queue_id = lcore_params[i].queue_id;
      lcore_conf[lcore_id].n_rx_queue++;
    }
  }
  return 0;
}

static int parse_portmask(const char *portmask) {
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return -1;

  if (pm == 0)
    return -1;

  return pm;
}

static int parse_config(const char *q_arg) {
  char s[256];
  const char *p, *p0 = q_arg;
  char *end;
  enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
  unsigned long int_fld[_NUM_FLD];
  char *str_fld[_NUM_FLD];
  int i;
  unsigned size;

  nb_lcore_params = 0;

  while ((p = strchr(p0, '(')) != NULL) {
    ++p;
    if ((p0 = strchr(p, ')')) == NULL)
      return -1;

    size = p0 - p;
    if (size >= sizeof(s))
      return -1;

    snprintf(s, sizeof(s), "%.*s", size, p);
    if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
      return -1;
    for (i = 0; i < _NUM_FLD; i++) {
      errno = 0;
      int_fld[i] = strtoul(str_fld[i], &end, 0);
      if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
        return -1;
    }
    if (nb_lcore_params >= MAX_LCORE_PARAMS) {
      printf("exceeded max number of lcore params: %hu\n", nb_lcore_params);
      return -1;
    }
    lcore_params_array[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
    lcore_params_array[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
    lcore_params_array[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
    ++nb_lcore_params;
  }
  lcore_params = lcore_params_array;
  return 0;
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256

#define CMD_LINE_OPT_CONFIG  "config"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_RULE    "rule"

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF                                                                         \
  RTE_MAX((nb_ports * RTE_TEST_RX_DESC_DEFAULT + nb_ports * nb_lcores * MAX_PKT_BURST + \
           nb_ports * RTE_TEST_TX_DESC_DEFAULT + nb_lcores * MEMPOOL_CACHE_SIZE),       \
          (unsigned)8192)

/* display usage */
static void print_usage(const char *prgname) {
  printf("%s [EAL options] --"
         "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
         "  -P : Enable promiscuous mode\n"
         "  --config (port,queue,lcore): Rx queue configuration\n"
         "  --no-numa: Disable numa awareness\n"
         "  --rule=FILE: specify the ipv4 rules file.\n\n",
         prgname);
}

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {
      {CMD_LINE_OPT_CONFIG, 1, 0, 0},
      {CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
      {CMD_LINE_OPT_RULE, 1, 0, 0},
      {NULL, 0, 0, 0},
  };

  argvopt = argv;

  /* Error or normal output strings. */
  const char *str1 = "FILTER: Invalid portmask";
  const char *str2 = "FILTER: Promiscuous mode selected";
  const char *str3 = "FILTER: Invalid config";
  const char *str4 = "FILTER: NUMA is disabled";

  while ((opt = getopt_long(argc, argvopt, "p:PLE", lgopts, &option_index)) != EOF) {
    switch (opt) {
    /* portmask */
    case 'p':
      enabled_port_mask = parse_portmask(optarg);
      if (enabled_port_mask == 0) {
        printf("%s\n", str1);
        print_usage(prgname);
        return -1;
      }
      break;
    case 'P':
      printf("%s\n", str2);
      opt_promiscuous_on = 1;
      break;

    /* long options */
    case 0:
      if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG, sizeof(CMD_LINE_OPT_CONFIG))) {
        ret = parse_config(optarg);
        if (ret) {
          printf("%s\n", str3);
          print_usage(prgname);
          return -1;
        }
      }

      if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA, sizeof(CMD_LINE_OPT_NO_NUMA))) {
        printf("%s\n", str4);
        opt_numa_on = 0;
      }

      if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_RULE, sizeof(CMD_LINE_OPT_RULE)))
        opt_rule_path = optarg;

      break;

    default:
      print_usage(prgname);
      return -1;
    }
  }

  if (optind >= 0)
    argv[optind - 1] = prgname;

  ret = optind - 1;
  optind = 0; /* reset getopt lib */

  if (NULL == opt_rule_path) {
    printf("filter rule file NOT specified\n");
    print_usage(prgname);
    return -1;
  }

  return ret;
}

static void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr) {
  char buf[RTE_ETHER_ADDR_FMT_SIZE];
  rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
  printf("%s%s", name, buf);
}

static int init_mem(unsigned nb_mbuf) {
  // struct lcore_conf *qconf;
  unsigned socket_id;
  unsigned lcore_id;
  char s[64];

  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 0)
      continue;

    if (opt_numa_on)
      socket_id = rte_lcore_to_socket_id(lcore_id);
    else
      socket_id = 0;

    if (socket_id >= NB_SOCKETS) {
      rte_exit(EXIT_FAILURE, "Socket %u of lcore %u is out of range %d\n", socket_id, lcore_id,
               NB_SOCKETS);
    }

    if (pktmbuf_pool[socket_id] == NULL) {
      snprintf(s, sizeof(s), "mbuf_pool_%u", socket_id);
      pktmbuf_pool[socket_id] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
                                                        RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
      if (pktmbuf_pool[socket_id] == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %u\n", socket_id);
      else
        printf("Allocated mbuf pool on socket %u\n", socket_id);
    }
  }
  return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */

  int ret;
  uint16_t port_id, count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("Checking link status...\n");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    if (force_quit)
      return;
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(port_id) {
      if (force_quit)
        return;
      if ((port_mask & (1 << port_id)) == 0)
        continue;
      memset(&link, 0, sizeof(link));
      ret = rte_eth_link_get_nowait(port_id, &link);
      if (ret < 0) {
        all_ports_up = 0;
        if (print_flag == 1)
          printf("Port %u link get failed: %s\n", port_id, rte_strerror(-ret));
        continue;
      }
      /* print link status if flag set */
      if (print_flag == 1) {
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        printf("Port %d %s\n", port_id, link_status_text);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == ETH_LINK_DOWN) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1)
      break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("Done\n");
    }
  }
}

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}

static int dump_port_info(void) {
  int ret = 0;
  uint16_t port_id, mtu = 0;
  struct rte_eth_dev_info dev_info;
  int socket_id = 0;
  char buff[32];

  RTE_ETH_FOREACH_DEV(port_id) {
    if ((enabled_port_mask & (1 << port_id)) == 0)
      continue;
    printf("port %u\n", port_id);

    /*dev_info*/
    memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    printf("\tPCI_addr: %s\n", dev_info.device->name);

    /*mac*/
    struct rte_ether_addr mac_addr;
    memset(&mac_addr, 0, sizeof(struct rte_ether_addr));
    rte_eth_macaddr_get(port_id, &mac_addr);
    rte_ether_format_addr(buff, sizeof(buff), &mac_addr);
    printf("\tMAC_addr: %s\n", buff);

    /*socket_id*/
    printf("\tSocket: ");
    socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0)
      printf("<error>");
    else
      printf("%d", socket_id);

    /*link*/
    struct rte_eth_link eth_link;
    memset(&eth_link, 0, sizeof(struct rte_eth_link));
    rte_eth_link_get_nowait(port_id, &eth_link);

    printf("\tSpeed: %u  Duplex: %s  AutoNeg: %s  Status: %s\n", eth_link.link_speed,
           eth_link.link_duplex == 0 ? "half" : "full",
           eth_link.link_autoneg == 0 ? "fixed" : "auto",
           eth_link.link_status == 0 ? "down" : "up");

    /*promiscuous*/
    printf("\tPromiscuous: ");
    ret = rte_eth_promiscuous_get(port_id);
    if (1 == ret)
      printf("enabled");
    else if (0 == ret)
      printf("disabled");
    else
      printf("unknown");

    /*mtu*/
    mtu = 0;
    ret = rte_eth_dev_get_mtu(port_id, &mtu);
    if (ret == 0) {
      printf(" mtu %d\n", mtu);
    } else {
      printf(" get mtu error: %d\n", ret);
    }

    printf("\tmin_rx_bufsize %u  max_rx_pktlen %u\n", dev_info.min_rx_bufsize,
           dev_info.max_rx_pktlen);
    printf("\tmax_rx_queues %u  max_tx_queues %u\n", dev_info.max_rx_queues,
           dev_info.max_tx_queues);

    /*stats*/
    struct rte_eth_stats stats;
    ret = rte_eth_stats_get(port_id, &stats);
    if (ret == 0) {
      printf("\tipackets %lu  opackets %lu  ibytes %lu  obytes %lu\n", stats.ipackets,
             stats.opackets, stats.ibytes, stats.obytes);
      printf("\timissed %lu  rx_nombuf %lu  ierrors %lu  oerrors %lu\n", stats.imissed,
             stats.rx_nombuf, stats.ierrors, stats.oerrors);
    } else {
      printf("get stat error:%d", ret);
    }
    printf("\n");
  }

  return 0;
}

static int worker_loop(__attribute__((unused)) void *arg) {
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  unsigned lcore_id;
  int i, j, nb_rx;
  uint16_t port_id, queue_id, tx_port_id;
  struct lcore_conf *qconf;
  struct rte_mbuf *m;
#ifdef DRAIN
  uint64_t prev_tsc, diff_tsc, cur_tsc;
  const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

  prev_tsc = 0;
#endif

  lcore_id = rte_lcore_id();
  qconf = &lcore_conf[lcore_id];

  if (qconf->n_rx_queue == 0) {
    RTE_LOG(INFO, FILTER, "lcore %u has nothing to do\n", lcore_id);
    return 0;
  }

  RTE_LOG(INFO, FILTER, "entering main loop on lcore %u\n", lcore_id);

  for (i = 0; i < qconf->n_rx_queue; i++) {
    port_id = qconf->rx_queue_list[i].port_id;
    queue_id = qconf->rx_queue_list[i].queue_id;
    RTE_LOG(INFO, FILTER, "lcore: %u port: %hhu rx queue: %hhu\n", lcore_id, port_id, queue_id);
  }

  while (!force_quit) {
#ifdef DRAIN
    cur_tsc = rte_rdtsc();

    /*
     * TX burst queue drain
     */
    diff_tsc = cur_tsc - prev_tsc;
    if (unlikely(diff_tsc > drain_tsc)) {
      for (i = 0; i < qconf->n_tx_port; ++i) {
        port_id = qconf->tx_port_id[i];
        if (qconf->tx_mbufs[port_id].len == 0)
          continue;
        send_burst(qconf, qconf->tx_mbufs[port_id].len, port_id);
        qconf->tx_mbufs[port_id].len = 0;
      }

      prev_tsc = cur_tsc;
    }
#endif

    /*
     * Read packet from RX queues
     */
    for (i = 0; i < qconf->n_rx_queue; ++i) {
      port_id = qconf->rx_queue_list[i].port_id;
      queue_id = qconf->rx_queue_list[i].queue_id;
      tx_port_id = port_tx_table[port_id];
      nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
      if (nb_rx == 0)
        continue;
#ifdef STATS
      qconf->rx_pkt_cnt[port_id] += nb_rx;
#endif

      for (j = 0; j < nb_rx; j++) {
        m = pkts_burst[j];
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        decode_packet(m);
        filter_process((packet_t *)m->buf_addr);
        send_single_packet(qconf, m, tx_port_id);
      }
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  int ret;
  struct lcore_conf *qconf;
  // struct rte_eth_dev_info dev_info;
  // struct rte_eth_txconf *txconf;
  unsigned nb_ports, lcore_id, socket_id;
  uint32_t nb_lcores;
  uint16_t port_id, queue_id, queue;

  if (argc < 2) {
    print_usage(argv[0]);
    return 0;
  }

  rte_log_set_level(RTE_LOGTYPE_FILTER, LOG_LEVEL);

  /* init EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
  argc -= ret;
  argv += ret;

  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* parse application arguments (after the EAL ones) */
  ret = parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid FILTER parameters\n");

  if (check_lcore_params() < 0)
    rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

  ret = init_lcore_rx_queues();
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

  if (check_port_config() < 0)
    rte_exit(EXIT_FAILURE, "check_port_config failed\n");

  nb_lcores = rte_lcore_count();
  // if (nb_lcores % 2)
  //   rte_exit(EXIT_FAILURE, "lcores count must be even number\n");

  nb_ports = rte_eth_dev_count_avail();

  printf("avail ports: %u, port mask: 0x%x\n", nb_ports, enabled_port_mask);

  /* initialize all ports */
  RTE_ETH_FOREACH_DEV(port_id) {
    /* skip ports that are not enabled */
    if ((enabled_port_mask & (1 << port_id)) == 0) {
      printf("Skipping disabled port %u\n", port_id);
      continue;
    }

    /* init port */
    printf("Initializing port %u...\n", port_id);
    fflush(stdout);

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_configure failed, err: %d, port: %u\n", ret, port_id);

    /* init memory */
    ret = init_mem(NB_MBUF);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "init_mem failed\n");

#if 0
    /* init one TX queue per couple (lcore,port) */
    queue_id = 0;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
      if (rte_lcore_is_enabled(lcore_id) == 0)
        continue;

      if (opt_numa_on)
        socket_id = rte_lcore_to_socket_id(lcore_id);
      else
        socket_id = 0;

      printf("txq: %u,%u,%u,%u ", port_id, queue_id, lcore_id, socket_id);
      fflush(stdout);

      rte_eth_dev_info_get(port_id, &dev_info);
      txconf = &dev_info.default_txconf;
      ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id, txconf);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err:%d, port: %d\n", ret, port_id);

      qconf = &lcore_conf[lcore_id];
      qconf->tx_queue_id[port_id] = queue_id;
      queue_id++;

      qconf->tx_port_id[qconf->n_tx_port] = port_id;
      qconf->n_tx_port++;
    }
    printf("\n");
#endif
  }

  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 0)
      continue;
    qconf = &lcore_conf[lcore_id];
    printf("Initializing rx queues on lcore %u...\n", lcore_id);
    fflush(stdout);
    /* init RX queues */
    for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
      port_id = qconf->rx_queue_list[queue].port_id;
      queue_id = qconf->rx_queue_list[queue].queue_id;

      if (opt_numa_on)
        socket_id = rte_lcore_to_socket_id(lcore_id);
      else
        socket_id = 0;

      printf("rxq: %u,%u,%u,%u\n", port_id, queue_id, lcore_id, socket_id);
      fflush(stdout);

      ret = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd, socket_id, NULL,
                                   pktmbuf_pool[socket_id]);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err: %d, port: %u\n", ret, port_id);
    }
  }

  if (filter_load_rules(opt_rule_path)) {
    rte_exit(EXIT_FAILURE, "Failed to add rules from %s\n", opt_rule_path);
  }

  /* start ports */
  RTE_ETH_FOREACH_DEV(port_id) {
    if ((enabled_port_mask & (1 << port_id)) == 0) {
      continue;
    }
    /* Start device */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, port_id);

    /*
     * If enabled, put device in promiscuous mode.
     * This allows IO forwarding mode to forward packets
     * to itself through 2 cross-connected  ports of the
     * target machine.
     */
    if (opt_promiscuous_on)
      rte_eth_promiscuous_enable(port_id);
  }
  printf("\n");

  check_all_ports_link_status(enabled_port_mask);

  rte_eal_mp_remote_launch(worker_loop, NULL, CALL_MAIN);
  rte_eal_mp_wait_lcore();

  dump_port_info();

#ifdef STATS
  printf("=============================================================\n");
  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 0)
      continue;
    qconf = &lcore_conf[lcore_id];
    printf("lcore %u\n", lcore_id);
    RTE_ETH_FOREACH_DEV(port_id) {
      if ((enabled_port_mask & (1 << port_id)) == 0)
        continue;
      printf("  port%d rx: %16lu    tx: %16lu\n", port_id, qconf->rx_pkt_cnt[port_id],
             qconf->tx_pkt_cnt[port_id]);
    }
    printf("-------------------------------------------------------------\n");
  }
#endif

  /* stop ports */
  RTE_ETH_FOREACH_DEV(port_id) {
    if ((enabled_port_mask & (1 << port_id)) == 0)
      continue;
    printf("Closing port %d...", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    printf(" Done\n");
  }

  rte_eal_cleanup();

  printf("Bye...\n");

  return ret;
}
