# Design Proposal for YFW

### 1. Filter Out incoming ARP packets

**Requirement**: Filter out all incomming ARP packets

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. Justify if this packet is an ARP packet. If true, go next. Else go STEP(2).
4. Justify if this packet is an incoming packet. If true, go next. Else go STEP(2).
5. if the conditions of (3) and (4) are matched, drop this packet, or store the data of this packet into `filtered.pcap`. Then jump to STEP(2)
6. DONE

[Realization](./src/filterARP.c)


### 2. Filter Out outgoing DNS queries

**Requirement**: Filter out all outgoing DNS queries. Because you are replaying packets, this operation won’t affect future packets.

####STEPS
1. Read packets from `dump.pcap`
2. if next packet exists, parse the header of it, or jump to STEP(6).
3. Justify if this packet is a DNS query. If true, go next. Else go STEP(2).
4. Justify if this packet is an outgoing packet. If true, go next. Else go STEP(2).
5. if the conditions of (3) and (4) are matched, drop this packet, or store the data of this packet into `filtered.pcap`. Then jump to STEP(2)
6. DONE

### 3. Limit the number of outgoing TCP connection

**Requirement**: Limit the number of outgoing TCP connections to 5. When the number of TCP connections reaches 5, drop TCP packets of future connections. When a connection terminates, one more connection is allowed to establish. You need to accurately deal with different type of TCP packets at different stages.

**Hint**: The last rule is a little difficult. Your firewall need track the establishment and termination of TCP connections and dynamically decide whether to drop packets or forward packets.