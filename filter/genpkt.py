#! /usr/bin/env python3

from scapy.all import *

pkts = []

pkt = Ether()/IP(version=4,src="1.2.3.4",dst="8.8.8.8")/TCP(sport=12345,dport=80)/"GET /index.html HTTP/1.0\r\n\r\n"
pkts.append(pkt);
pkt = Ether()/IP(version=4,src="5.6.7.8",dst="9.9.9.9")/UDP(sport=7777,dport=23)/"hello world"
pkts.append(pkt);

wrpcap("test.pcap", pkts)
