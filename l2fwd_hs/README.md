## intro

l2fwd with simple protocol decoding and pattern matching by hyperscan.

This demo is used for testing throughput performance with different-scale
hyperscan databases with 1 lcore(work thread).

## dependencies

1. modify headroom of m_buf;
2. hyperscan.

## compile

```
// link to static library
LDFLAGS += -lhs -lstdc++ -lm
```

## run

```
./l2fwd -c 3 -n 2 -- -p 3 -q 2 --ptn /path/to/ptn.txt

-p PORTMASK: hexadecimal bitmask of ports to configure
-q NQ: number of queue (=ports) per lcore (default is 1)
-T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)
--dec: enable simple decoding
--ptn PTN_FILE: pattern file path
note: --ptn will enable simple decoding too
```
