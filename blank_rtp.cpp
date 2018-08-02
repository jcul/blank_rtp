
#include <fstream>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

u_char data[65535];

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    const size_t udp_offset = sizeof(ethhdr) + sizeof(iphdr);
    const size_t rtp_offset = udp_offset + sizeof(udphdr);
    const size_t rtp_hdr_len = 12;
    const size_t all_hdrs_len = rtp_offset + rtp_hdr_len;

    const ethhdr *eth = reinterpret_cast<const ethhdr *>(bytes);
    const iphdr *ip = reinterpret_cast<const iphdr *>(bytes + sizeof(ethhdr));
    const udphdr *udp = reinterpret_cast<const udphdr *>(bytes + udp_offset);
    const u_char *rtp = bytes + rtp_offset;

    if (h->caplen >= rtp_offset) {
        if (ntohs(eth->h_proto) == ETH_P_IP && ip->protocol == IPPROTO_UDP) {
            int rtp_len = ntohs(udp->len) - 8;
            if (rtp_len >= rtp_hdr_len && h->caplen >= (rtp_offset + rtp_len)) {
                if ((rtp[0] & 0xC0) == 0x80) {
                    if (sizeof(data) < h->caplen) {
                        std::cerr << "internal buffer is too small to fit packet" << std::endl;
                        abort();
                    }
                    memcpy(data, bytes, all_hdrs_len);
                    bytes = data;
                }
            }
        }
    }
    pcap_dump(user, h, bytes);
}

int main(int c, char **v)
{
    if (c != 3) {
        std::cerr << "Usage: " << v[0] << " in.pcap out.pcap" << std::endl;
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *in = pcap_open_offline(v[1], errbuf);
    if (!in) {
        std::cerr << errbuf << std::endl;
        return -2;
    }
    if (std::ifstream(v[2]).good()) {
        std::cerr << v[2] << " exists - not overwriting" << std::endl;
        return -3;
    }
    pcap_dumper_t *out = pcap_dump_open(in, v[2]);
    if (!out) {
        std::cerr << "Unable to open output pcap " << v[2] << std::endl;
    }
    memset(data, 0xff, sizeof(data));
    pcap_loop(in, 0, packet_handler, reinterpret_cast<u_char *>(out));
    pcap_close(in);
    pcap_dump_close(out);
    return 0;
}
