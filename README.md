# YFW
Yet another Firewall powered by tcpdump & libpcap

## Packet Recording

Install `tcpdump` with homebrew on OS X

```
brew install tcpdump
```

Record packages to `dump.pcap`

```
sudo tcpdump -i en0 >> dump.pcap
```

And you can find the sample that I recorded from [Here](https://raw.githubusercontent.com/zry656565/yfw/master/dump.pcap)

## Reference

- Tcpdump
  - [Tcpdump usage examples](http://www.rationallyparanoid.com/articles/tcpdump.html)
  - [TCPDUMP - The Easy tutorial](http://openmaniak.com/tcpdump.php)
  - [TCPDUMP homepage](http://www.tcpdump.org/)
- libpcap
  - [libpcap-tutorial.pdf](http://eecs.wsu.edu/~sshaikot/docs/lbpcap/libpcap-tutorial.pdf)
- PF_RING
  - [PF_RING HOME](http://www.ntop.org/products/packet-capture/pf_ring/)