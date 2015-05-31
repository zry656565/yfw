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

And you can find the sample that I recorded from [Here](https://raw.githubusercontent.com/zry656565/yfw/master/sample.pcap)

### Implement Firewall

[Design Proposal](https://github.com/zry656565/yfw/blob/master/design.md)


### Reference

- Tcpdump
  - [Tcpdump usage examples](http://www.rationallyparanoid.com/articles/tcpdump.html)
  - [TCPDUMP - The Easy tutorial](http://openmaniak.com/tcpdump.php)
  - [TCPDUMP/libpcap homepage](http://www.tcpdump.org/)
- libpcap
  - [libpcap-tutorial.pdf](http://eecs.wsu.edu/~sshaikot/docs/lbpcap/libpcap-tutorial.pdf)
  - [Packet Reading with libpcap](http://systhread.net/texts/200805lpcap1.php)
  - [libpcap Haking](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)
  - [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- PF_RING
  - [PF_RING HOME](http://www.ntop.org/products/packet-capture/pf_ring/)