NUMA malloc性能比较
-------------------

在Linux默认内存分配策略下, 比较在各lcore上调用malloc, 和在主线程上调用malloc分配运行时所需\
内存之间的性能差异. 当在主线程调用malloc时, 系统默认会在主线程所在NUMA节点分配内存, 而在lcore\
上分配内存则在此lcore所在NUMA节点分配内存. 当各运行时lcore与主线程不在同一NUMA节点时, 性能\
可能会有差异.

以链表式hash流表来进行演示. 测试时应让master lcore(id最小的lcore)与其他lcore不在一个NUMA节点.
线程循环会在所有lcores上运行(CALL_MASTER).


link hash流表
-------------

使用挂链式hash表创建了简单流表, 只进行insert/lookup操作,
观察其性能并输出流表数等统计数据.

在Makefile加上-DDEBUG后, 会在强制结束(Ctrl+C)程序后在/tmp目录输出流表信息, 文件\
名格式是 link_flow_<lcore_id>.txt,  比如::

    lcore  8                                                                                                  
    flow cnt: 65536                                                                 
    bucket cnt: 1048576, bucket mask: fffff                                         
                                                                                    
           2       2                                                                
           4       2                                                                
           8       1                                                                
          11       1                                                                
          13       1                                                                
          18       1                                                                
          36       1                                                                
          64       1                                                                
          70       1                                                                
          73       1                                                                
          7e       1    
          ...

主要信息下的2列分别是哈希桶编号(其实也是hash值)及落在此桶中的流数目. 观察此文件\
可以调试程序, 同时检查哈希是否均匀.


l2fwd2
-------

使用以dpdk官方示例l2fwd和l3fwd为基础修改的代码l2fwd2. 源码:
https://github.com/zzqcn/dpdk_demo/tree/main/l2fwd2

主要特点如下:

* 线程收到包之后不做任何处理直接转发, 没有查找路由表操作
* 与l3fwd一样, 支持lcore,port,queue配置
* 转发算法简单, 从port0收的报文从port1发送, 从port1收的报文从port0发送, 依此类推
* 测试完成后, 按Ctrl+C结束程序, 退出前显示各port及各lcore的收发包统计数据(内部)
* 退出前会显示各port统计信息, 比如可通过观察imissed来获取丢包数

在测试前需要确定cpu核的绑定设置. 目前测试使用的服务器, 它的10G网卡在socket 1, 而CPU核的布局如下::

            Socket 0        Socket 1 
            --------        -------- 
    Core 0 [0, 12]         [6, 18] 
    Core 1 [1, 13]         [7, 19] 
    Core 2 [2, 14]         [8, 20] 
    Core 3 [3, 15]         [9, 21] 
    Core 4 [4, 16]         [10, 22]
    Core 5 [5, 17]         [11, 23]

因此最好使用socket 1上的核心, 且尽量不使用同一物理核心的另一个lcore. 比如要使用4个\
lcore, 可使用7, 8, 9, 10号lcore.

运行命令::

    ./l2fwd2 -c 0x780 -n 4 -- -p 0x3 --config="(0,0,7),(0,1,8),(1,0,9),(1,1,10)"

如果只用了一个仪表口向设备上的网卡0发送流量, 而设备上的网卡1短接, 那么还需要加上\
-P参数打开混杂模式::

    ./l2fwd2 -c 0x180 -n 4 -- -p 0x3 -P --config="(0,0,7),(1,0,8)"  
    ./l2fwd2 -c 0x780 -n 4 -- -p 0x3 -P --config="(0,0,7),(0,1,8),(1,0,9),(1,1,10)"
    ./l2fwd2 -c 0xfc0 -n 4 -- -p 0x3 -P --config="(0,0,6),(0,1,7),(0,2,8),(1,0,9),(1,1,10),(1,2,11)"


编译选项: 在l2fwd.h里打开STAT宏定义会进行报文收发统计; 打开DRAIN宏定义会定期flush发送队列.

