#ifndef CAPPACKET_H
#define CAPPACKET_H 1


extern void parse_wlanframe( unsigned char *user_args, const struct pcap_pkthdr *cap_header,
        const unsigned char *packet);

extern void decode_wlanframe(const unsigned char *header_start);

#endif
