# Design Proposal for YFW

### 0. Packet Recording

Install `tcpdump` with homebrew on OS X

```
brew install tcpdump
```

The version of tcpdump and libpcap on my system
```
tcpdump --version

# output of the script:
tcpdump version 4.6.2
libpcap version 1.5.3 - Apple version 47
OpenSSL 1.0.1j 15 Oct 2014
```

Record packages to `dump.pcap`

```
sudo tcpdump -i en0 -w dump.pcap
```

Send ARP requrests by `arping`

```
brew install arping

arping -c 1 192.168.1.1
arping -c 1 216.58.221.100    # IP Address of google.com
```

And you can find the sample that I recorded from [Here](./testcase/sample.pcap)

### 1. Filter Out incoming ARP packets [[filter.c](./src/filter.c)]

**Requirement**: Filter out all incomming ARP packets

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. [Justify if this packet is an ARP packet](./src/filter.c#L95). If true, go next, else go STEP(2).
4. [Justify if this packet is an incoming packet](./src/filter.c#L97). If true, go next, else go STEP(2).
5. if the conditions of (3) and (4) are matched, drop this packet, or store the data of this packet into `filtered.pcap`. Then jump to STEP(2)
6. DONE

####Result

```
...$ make
...$ ./filter testcase/dump.pcap 
Drop an incoming ARP packet!
Drop an incoming ARP packet!
```

### 2. Filter Out outgoing DNS queries [[filter.c](./src/filter.c)]

**Requirement**: Filter out all outgoing DNS queries. Because you are replaying packets, this operation won’t affect future packets.

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. [Justify if the protocol of this packet is UDP](./src/filter.c#L103). If true, go next, else go STEP(2).
4. [Justify if this packet is a DNS query](./src/filter.c#L106-110). If true, go next, else go STEP(2).
5. if the conditions of (3) and (4) are matched, drop this packet, or store the data of this packet into `filtered.pcap`. Then jump to STEP(2)
6. DONE

####Result

```
...$ make
...$ ./filter testcase/dump.pcap 
Drop an outgoing DNS packet through UDP!
Drop an outgoing DNS packet through UDP!
Drop an outgoing DNS packet through UDP!
```

### 3. Limit the number of outgoing TCP connection [[tcpLimit.c](./src/tcpLimit.c)]

**Requirement**: Limit the number of outgoing TCP connections to 5. When the number of TCP connections reaches 5, drop TCP packets of future connections. When a connection terminates, one more connection is allowed to establish. You need to accurately deal with different type of TCP packets at different stages.

**Hint**: The last rule is a little difficult. Your firewall need track the establishment and termination of TCP connections and dynamically decide whether to drop packets or forward packets.

####STEPS
1. Read packets from `dump.pcap`
2. Let connection number = 0
3. If next packet exists, parse the header of it, or jump to STEP(9).
4. Justify if the protocol of this packet is TCP. If true, go next, else go STEP(3).
5. if the packet contains flag_SYN and connection number < 5, [establish a new TCP connection](./src/tcpLimit.c#L108-124) for this packet and let connection number += 1, then go STEP(8); else if connection number >= 5, go STEP(3).
6. if the packet contains flag_FIN, [close the TCP connection](./src/tcpLimit.c#L125-139) for this packet and let connection number -= 1, then go STEP(8);
7. Justify if a connection has been established for this packet. If true, go STEP(8), else go STEP(3).
8. Store the data of this packet into `filtered.pcap`. Then jump to STEP(3)
9. DONE

####Result

```
...$ make
...$ ./tcpLimit testcase/dump.pcap
Connection 0: SYN_SEND          Remote IP: 115.239.210.27   Port: 20480
Connection 0: ESTABLISHED       Remote IP: 115.239.210.27   Port: 20480
Connection 1: SYN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 2: SYN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 3: SYN_SEND          Remote IP: 115.239.211.112  Port: 47873
Connection 4: SYN_SEND          Remote IP: 58.215.118.33    Port: 47873
Connection 1: ESTABLISHED       Remote IP: 115.239.210.27   Port: 47873
Connection 2: ESTABLISHED       Remote IP: 115.239.210.27   Port: 47873
Connection 3: ESTABLISHED       Remote IP: 115.239.211.112  Port: 47873
Connection 4: ESTABLISHED       Remote IP: 58.215.118.33    Port: 47873
Connection 1: FIN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 1: CLOSED            Remote IP: 115.239.210.27   Port: 47873
Connection 1: SYN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 1: ESTABLISHED       Remote IP: 115.239.210.27   Port: 47873
Connection 3: FIN_SEND          Remote IP: 115.239.211.112  Port: 47873
Connection 1: FIN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 2: FIN_SEND          Remote IP: 115.239.210.27   Port: 47873
Connection 4: FIN_SEND          Remote IP: 58.215.118.33    Port: 47873
Connection 1: CLOSED            Remote IP: 115.239.210.27   Port: 47873
Connection 4: CLOSED            Remote IP: 58.215.118.33    Port: 47873
Connection 1: SYN_SEND          Remote IP: 61.135.169.120   Port: 19203
Connection 4: SYN_SEND          Remote IP: 61.135.169.120   Port: 19203
Connection 3: CLOSED            Remote IP: 115.239.211.112  Port: 47873
Connection 3: SYN_SEND          Remote IP: 101.227.66.158   Port: 20480
Connection 3: ESTABLISHED       Remote IP: 101.227.66.158   Port: 20480
Connection 3: FIN_SEND          Remote IP: 101.227.66.158   Port: 20480
Connection 3: CLOSED            Remote IP: 101.227.66.158   Port: 20480
Connection 3: SYN_SEND          Remote IP: 101.226.178.140  Port: 20480
Connection 3: ESTABLISHED       Remote IP: 101.226.178.140  Port: 20480
Connection 3: FIN_SEND          Remote IP: 101.226.178.140  Port: 20480
Connection 3: CLOSED            Remote IP: 101.226.178.140  Port: 20480
Connection 3: SYN_SEND          Remote IP: 115.239.211.112  Port: 47873
Connection 3: ESTABLISHED       Remote IP: 115.239.211.112  Port: 47873
Connection 0: FIN_SEND          Remote IP: 115.239.210.27   Port: 20480
Connection 3: FIN_SEND          Remote IP: 115.239.211.112  Port: 47873
Connection 3: CLOSED            Remote IP: 115.239.211.112  Port: 47873
```

### Reference

- Tcpdump
  - [Tcpdump usage examples](http://www.rationallyparanoid.com/articles/tcpdump.html)
  - [TCPDUMP - The Easy tutorial](http://openmaniak.com/tcpdump.php)
  - [TCPDUMP/libpcap homepage](http://www.tcpdump.org/)
- libpcap
  - [libpcap-tutorial.pdf](http://eecs.wsu.edu/~sshaikot/docs/lbpcap/libpcap-tutorial.pdf)
  - [libpcap-tutorial](http://yuba.stanford.edu/~casado/pcap/section2.html)
  - [Packet Reading with libpcap](http://systhread.net/texts/200805lpcap1.php)
  - [libpcap Haking](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)
  - [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- PF_RING
  - [PF_RING HOME](http://www.ntop.org/products/packet-capture/pf_ring/)
- Realization
  - [arphdr](http://lxr.free-electrons.com/source/include/uapi/linux/if_arp.h#L141)
  - [ARP Message Format](http://www.tcpipguide.com/free/t_ARPMessageFormat.htm)
  - [netinet/ip.h](http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html)
  - [netinet/tcp.h](http://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/tcp.h.html)
- DNS queries
  - [Identifying DNS packets](http://stackoverflow.com/questions/7565300/identifying-dns-packets)
  - [RFC 1035](http://tools.ietf.org/html/rfc1035)
