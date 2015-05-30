# YFW
Yet another Firewall powered by tcpdump & libpcap

# Packet Recording

Install `tcpdump` with homebrew on OS X

```
brew install tcpdump
```

Record packages to `dump.pcap`

```
sudo tcpdump -i en0 >> dump.pcap
```

And you can find the sample that I recorded from [Here](https://raw.githubusercontent.com/zry656565/yfw/master/dump.pcap)