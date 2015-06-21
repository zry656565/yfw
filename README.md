# YFW
Yet another emulated Firewall powered by tcpdump & libpcap

### Packet Recording

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

### Implement Firewall

[Design Proposal](./design.md)


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