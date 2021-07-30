#ifndef INCLUDES_HACKING_NETWORK_H
#define INCLUDES_HACKING_NETWORK_H 1

#define ETHER_ADDR_LEN 6 
#define ETHER_HDR_LEN 14
/*
 * TODO: Mayor alert, compiler tries to align structs to 4-byte boundaries
 * so DO NOT EXPECT structs to have the right size  always!!!!!!
 * use __attribute__((packet)) and other tricks like unions to get the right sizes
 * */
/* This function accepts a socket FD and a ptr to the null terminated
 * string to send. the function will make sure all the bytes of the
 * string are sent. Returns 1 on successs and 0 on failure.
 */

struct ether_hdr{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
    unsigned char ether_src_addr[ETHER_ADDR_LEN]; // Source MAC address
    unsigned short ether_type; // Type of Ethernet packet 
};

struct ip_hdr{
    unsigned char ip_version_and_header_length; // Version and header 
    unsigned char ip_tos; // Type of service
    unsigned short ip_len; // Total length 
    unsigned short ip_id;  // Identification Number 
    unsigned short ip_frag_offset;  // Fragment offset and Flags 
    unsigned char ip_ttl; // Time to live 
    unsigned char ip_type; // Protocol Type
    unsigned short ip_checksum; // Checksum 
    unsigned int ip_src_addr;  // Source IP address 
    unsigned int ip_dest_addr;  // destination IP address 
};

struct tcp_hdr {
    unsigned short tcp_src_port;    // Source TCP port
    unsigned short tcp_dest_port;    // Destination TCP port 
    unsigned int tcp_seq;    // TCP sequence number 
    unsigned int tcp_ack;    // TCP acknowledgement number 
    unsigned char reserved:4;    // 4 bits from the 6 bits of reserved space 
    unsigned char tcp_offset:4;    // TCP data offset for little-endian host 
    unsigned char tcp_flags;    // TCP flags (and 2 bits from reserved space) 
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;  // TCP window size
    unsigned short tcp_checksum;  // TCP checksum 
    unsigned short tcp_urgent;  // TCP urgent pointer 
};
/**
 * RadioTap header for this particular Wifi ADAPTER ONLY.
 * This header should be 36 bytes long.
 * DEPENDS ON THE CHIP'S VENDOR
 */
struct radiotap_hdr{
    /*unsigned char placeholder[36];some problem with unsigned char type, says unknown */
    /*TODO: Review and study its fields*/
    unsigned char placeholder[36];

};
/**
 * @brief struct for the frame control field of a wlan mac frame(802.11)
 */
struct frame_control{
    unsigned short protocol:2;
    unsigned short type:2;
    unsigned short sub_type:4;
    unsigned short to_ds:1;
    unsigned short from_ds:1;
    unsigned short more_frag:1;
    unsigned short retry:1;
    unsigned short power_mgmt:1;
    unsigned short more_data:1;
    unsigned short protected_frame:1;
    unsigned short order:1;
};
/*
 * Some considerations:
 * this is the part of the mac 802.11 header that is common to all 
 * type and sub-type combinations that the 802.11 can have. 
 * TODO: To my current understanding only framecon and the last FCS
 * field are present in all kinds of 802.11 headers, so may need
 * to modify this or just discar wlan_hdr altogether
 */
struct wlan_hdr{
    struct frame_control framecon; // This one should be replaced by a type of the struct above
    unsigned short duration;
    unsigned char ra[ETHER_ADDR_LEN];
};
/*Originally used: */
/*
struct wlan_hdr{
    struct frame_control framecon; // This one should be replaced by a type of the struct above
    unsigned short duration;
    unsigned char ra[ETHER_ADDR_LEN]; // Reciever Address 
    unsigned char ta[ETHER_ADDR_LEN]; // Transmitter Address 
    unsigned char da[ETHER_ADDR_LEN]; // Destination Address 
    unsigned short seq_control;
    unsigned char sa[ETHER_ADDR_LEN]; // Source Address 
};
*/

/*
 * @brief Specific header for a type:ma subtype:beacon wlan frame.
 *      is quite similar to the wlan_hdr.
 *  frame body starts after ht_control and starts with the SSID and (if present)
 *  has a maximun length of 32 bytes.
 */
struct beacon_hdr{
    struct frame_control framecon; // This one should be replaced by a type of the struct above
    unsigned short duration;
    unsigned char ra[ETHER_ADDR_LEN]; // Reciever Address 
    unsigned char ta[ETHER_ADDR_LEN]; // Transmitter Address 
    unsigned char da[ETHER_ADDR_LEN]; // Destination Address 
    unsigned short seq_control;
    unsigned char timestamp[8];
    unsigned short binter; // beacon interval
    unsigned short capinfo; // capability info, 36 bytes up to here
    /*TODO:I am forcing this padding in order to get the right aligment for ssid
     *Correct after or find out what the f* is going on
     * */
    unsigned short padding; // Seems like access points add 2 non-printable characters
    /*To the SSID, hence the need for this padding? */
    /*the ssid might start with \0\n both of which i am not taking into account*/
    unsigned char ssid;
} __attribute__((packed));

int send_string(int sockfd, unsigned char *buffer);
int recv_line(int sockfd, unsigned char *dest_buffer);

#endif
