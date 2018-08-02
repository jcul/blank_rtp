Simple program to fill all RTP media payload data in a pcap with 0xff to protect privacy.

Depends on libpcap.

To build just clone or download zip and run make.

Usage: ./blank_rtp in.pcap out.pcap

```
git clone https://github.com/jcul/blank_rtp
cd blank_rtp
make
./blank_rtp rtp.pcap blanked_rtp.pcap
```

Note: The checks on the RTP are weak as the RTP protocol does not have easily 
identifyable headers so it could easily mistake some other UDP protocol as RTP,
so it would be better to run on a pcap that has just RTP and merge later.
SIP with RTP should be safe as SIP is ascii.
