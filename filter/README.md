>基于 DPDK 21.11

# filter

不同于 rte_flow, 此示例使用基于 DPDK ACL 实现基于软件的流量过滤. rte_flow 需要利用网卡能力, 不同网卡支持的能力不同.

为了能在受限环境运行, 本示例在编写时刻意降低了硬件要求, 不需要多个 CPU 核, 也不需要实际网卡, 使用 DPDK 虚拟设备功能(vdev)即可把 pcap 文件做为报文输入源.

限于篇幅, 此说明文件不涉及太多原理, 详见[我的语雀文章](https://www.yuque.com/zzqcn/dpdk/slw9r2).

## 程序结构

程序由几个部分组成:

- decode 简单解析报文, 仅支持简单 Ether 封装
- filter 过滤规则解析, 编译和运行时匹配
- l2fwd 简单二层转发
- main DPDK 主程序, 负责初始化 EAL, 内存, 网卡, 启动程序等

另有两个文件
- ``rules.txt`` 过滤规则文件
- ``genpkt.py`` 用于生成测试报文(基于 Scapy).

因为仅演示原理, 代码做了以下简化:

- 仅支持 IPv4 规则
- 只基于外层 IP/端口进行匹配
- 匹配规则后并没有真正执行动作, 只是打印出来

运行时报文路径:

```
-->[decode]-->[filter(match->action)] -> [l2fwd]
```

## 编译

此示例基于 DPDK 21.11 并使用 meson 编译系统, 请在编译前安装相关依赖项.

```bash
$cd filter_dir
$meson build
$ninja -C build # 或 cd build; ninja
```

## 运行

参数说明:

- `--vdev` 使用 libpcap PMD 的虚拟网卡, 参考 [ Libpcap and Ring Based Poll Mode Drivers](https://doc.dpdk.org/guides/nics/pcap_ring.html). 语法`--vdev 'net_pcap0,stream_opt0=..,stream_opt1=..'`, 其中
  - net_pcapX: 设备名, `X` 必须是数字或字母
  - stream_opt: 此设备的多个流选项, 如 `rx_pcap=/path/to/file.pcap`, `rx_iface=eth0`
- `--config` 网卡队列与 CPU 核心, 语法`(port_id,queue_id,lcore_id)`, 其中
  - port_id: 网卡编号
  - queue_id: 网卡队列编号
  - lcore_id: CPU 核编号
- `--rule` 过滤规则文件路径, 规则文件语法见下文

**注意:** 所有参数的值都不能带有空白字符(如空格).

其他参数含义参考 DPDK EAL 参数.

```bash
$./filter -l 0 -n 4 --vdev 'net_pcap0,rx_pcap=../test.pcap' -- -p 0x1 --config '(0,0,0)' --rule '../rules.txt'
```

程序启动后加载过滤规则文件, 并打印其中的规则, 如
```
FILTER: Parsed 2 rules
1 priority:100 pattern{saddr:1.2.3.4/32 sport:12345 proto:tcp} action:drop
2 priority:99 pattern{saddr:5.6.7.8/24 pktlen:53} action:mark/8
```

运行过程中, 会打印出命中过滤规则的报文, 包括报文基本信息, 命中的规则和执行的动作, 如
```
>1.2.3.4:12345	8.8.8.8:80	TCP	Len:82	Rule:1	drop
>5.6.7.8:7777	9.9.9.9:23	UDP	Len:53	Rule:2	mark/8
```

## 过滤规则语法

每条规则由 ID, pattern, action, 优先级 3 大部分构成. 

- ID 是由规则在文件中出现的顺序自动编号的, 从 1 开始
- pattern 包括 IP 源地址/目的地址, 源端口/目的端口, 协议号, 报文长度
- action 是规则命中后执行的动作, 包括 drop, mark, forward, dispatch 四种, 除 drop 外, 其他 action 都有参数
  - drop 丢弃报文
  - mark 给报文打标记, 参数为要打的标记值
  - forward 将报文直接从指定网口转发, 参数为发送网口号
  - dispatch 将报文分发到指定 CPU 核处理, 参数为 CPU 核编号

pattern 中不关心的字段, 在满足字段格式的情况下写 0 即可, 如``0.0.0.0/0``.

规则文件语法示例:
```
# file format:
# src_ip/masklen dst_ip/masklen src_port dst_port proto pkt_len action/arg priority
#
# If you don't care any field, just set it to 0.

1.2.3.4/32  0.0.0.0/0   12345 0 6 0   drop/0  100
5.6.7.8/24  0.0.0.0/0   0     0 0 53  mark/8  99
```
