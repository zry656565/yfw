# Design Proposal for YFW

### 1. Filter Out incoming ARP packets

**Requirement**: Filter out all incomming ARP packets

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. Justify if this packet is an ARP packet. If true, go next, else go STEP(2).
4. Justify if this packet is an incoming packet. If true, go next, else go STEP(2).
5. if the conditions of (3) and (4) are matched, drop this packet, or store the data of this packet into `filtered.pcap`. Then jump to STEP(2)
6. DONE

####Result

```
...$ make
...$ ./filter testcase/dump.pcap 
Drop an incoming ARP packet!
Drop an incoming ARP packet!
```

### 2. Filter Out outgoing DNS queries

**Requirement**: Filter out all outgoing DNS queries. Because you are replaying packets, this operation won’t affect future packets.

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. Justify if the protocol of this packet is TCP/UDP. If true, go next, else go STEP(2).
4. Justify if this packet is a DNS query(destination port is 53). If true, go next, else go STEP(2).
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

### 3. Limit the number of outgoing TCP connection

**Requirement**: Limit the number of outgoing TCP connections to 5. When the number of TCP connections reaches 5, drop TCP packets of future connections. When a connection terminates, one more connection is allowed to establish. You need to accurately deal with different type of TCP packets at different stages.

**Hint**: The last rule is a little difficult. Your firewall need track the establishment and termination of TCP connections and dynamically decide whether to drop packets or forward packets.

####STEPS
1. Read packets from `dump.pcap`
2. Let connection number = 0
3. If next packet exists, parse the header of it, or jump to STEP(9).
4. Justify if the protocol of this packet is TCP. If true, go next, else go STEP(3).
5. Justify if a connection has been established for this packet. If true, go STEP(7), else if TCP connection has reach 5, then drop this packet, else go next.
6. Establish a new TCP connection for this packet and let connection number += 1
7. Justify if this packet is the last one of the connection, if so, then let connection number -= 1.
8. Store the data of this packet into `filtered.pcap`. Then jump to STEP(3)
9. DONE

####Result

```
...$ make
...$ ./tcpLimit testcase/dump.pcap
```
