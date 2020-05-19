#ifndef CAPPACKET_H
#define CAPPACKET_H 1


extern void parse_wlanframe( u_char *user_args, const struct pcap_pkthdr *cap_header,
        const u_char *packet);

extern void decode_wlanframe(const struct u_char *header_start);

#endif
