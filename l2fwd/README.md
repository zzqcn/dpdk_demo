usage:
###
    ./l2fwd -c 3 -n 2 -- -p 3 -q 2

note: 
###
 1. the master lcore don't run main\_loop (SKIP\_MASTER);
 2. if using 2 lcore and 2 ports (-c 3 -p 3), the queues/ports every 
    lcore recv from must be  2 (-q 2), the unique slave lcore will 
    recv from rx0 and rx1;
    
    if using 3 lcore and 2 ports (-c 7 -p 3), the queues/ports every
    lcore recv could be 1 (-q 1 or ignore), slave lcore 0 will recv
    from rx0, slave lcore 1 will recv rx1; or -q 2, slave lcore 0
    will recv from rx0 and rx1, slave lcore 1 do nothing.

