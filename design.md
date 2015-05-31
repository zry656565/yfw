# Design Proposal for YFW

### 1. Filter Out incoming ARP packets

####STEPS
1). Read packets from `dump.pcap`
2). Parse packets header
3). Justify if this packet is an ARP packet
4). Justify if this packet is an incoming packet
5). if the conditions of 3) and 4) are matched, drop this packet. Or store the data of this packet into `filtered.pcap`


### 2. Filter Out outgoing DNS queries

####STEPS
1). Read packets from `dump.pcap`
2). Parse packets header
3). Justify if this packet is a DNS query
4). Justify if this packet is an outgoing packet
5). if the conditions of 3) and 4) are matched, drop this packet. Or store the data of this packet into `filtered.pcap`

### 3. Limit the number of outgoing TCP connection