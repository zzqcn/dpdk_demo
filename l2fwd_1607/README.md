
>基于 DPDK 16.07

# l2fwd

使用以 DPDK 官方示例 l2fwd 和 l3fwd 为基础修改的代码.

主要特点如下:

* 线程收到包之后不做任何处理直接转发, 没有查找路由表操作
* 与 l3fwd 一样, 支持 `(port,queue,lcore)` 配置
* 转发算法简单, 从 port 0 收的报文从 port 1 发送, 从 port 1 收的报文从 port 0 发送, 依此类推
* 测试完成后, 按 `Ctrl+C` 结束程序, 退出前显示各 port 及各 lcore 的收发包统计数据(内部)
* 退出前会显示各 port 统计信息, 比如可通过观察 imissed 来获取丢包数

在测试前需要确定 CPU 核的绑定设置. 目前测试使用的服务器, 它的 10G 网卡在 socket 1,
而 CPU 核的布局如下:
```
          Socket 0        Socket 1 
          --------        -------- 
    Core 0 [0, 12]         [6, 18] 
    Core 1 [1, 13]         [7, 19] 
    Core 2 [2, 14]         [8, 20] 
    Core 3 [3, 15]         [9, 21] 
    Core 4 [4, 16]         [10, 22]
    Core 5 [5, 17]         [11, 23]
```

因此最好使用 socket 1 上的核心, 且尽量不使用同一物理核心的另一个 lcore. 比如要使用 4 个
lcore, 可使用 7, 8, 9, 10 号lcore:

```bash
$./l2fwd2 -l 7,8,9,10 -n 4 -- -p 0x3 --config="(0,0,7),(0,1,8),(1,0,9),(1,1,10)"
```

如果只用了一个仪表口向设备上的网卡0发送流量, 而设备上的网卡1短接, 那么还需要加上
`-P` 参数打开混杂模式:

```bash
$./l2fwd2 -l 7,8 -n 4 -- -p 0x3 -P --config="(0,0,7),(1,0,8)"  
$./l2fwd2 -l 7,8,9,10 -n 4 -- -p 0x3 -P --config="(0,0,7),(0,1,8),(1,0,9),(1,1,10)"
$./l2fwd2 -l 6,7,8,9,10,11  -n 4 -- -p 0x3 -P --config="(0,0,6),(0,1,7),(0,2,8),(1,0,9),(1,1,10),(1,2,11)"
```

编译选项: 在 *l2fwd.h* 里打开 `STAT` 宏定义会进行报文收发统计; 打开 `DRAIN` 宏定义会定期 flush 发送队列.
