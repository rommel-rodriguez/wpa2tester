/** @file cappacket.c */
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hacking.h"
#include "hacking-network.h" 
#include "cappacket.h" 

int is_printable(const char *my_char);
/**
 * @brief returns the mac address stored in an array in
 * hexadecimal format AND WITH EASY TO READ NOTATION.
 * @param mac_array. Pointer to the array. 
 */
char *format_mac(unsigned char *mac_array){
    char mac_hex[17];
    char *start;
    start = mac_hex;
    for(int i = 1; i < 6; i++){
        sprintf(start, "%02x", mac_array[i]); 
        if(i != 5)
            sprintf(start + 2, ":"); 
        start = start + 3;
    }
    return mac_hex;
}


/**
 * @brief returns the mac address stored in an array in
 * hexadecimal format AND WITH EASY TO READ NOTATION.
 * @param mac_array. Pointer to the array. 
 */
void print_mac(unsigned char *mac_array){
    printf("%02x", mac_array[0]);
    for(int i = 1; i < 6; i++)
        printf(":%02x", mac_array[i]);
    printf("\n");
}

/**
 * @brief Just Prints the first shunk of the frame for analysis.
 */
void print_packet_eager(const unsigned char *frame){
    for(int i = 0; i < 20; i++ ){
        int k = 0;
        for(unsigned char *byte=frame+(i*16); ; byte=byte+1){
            if(k >=16){
                printf("\n");
                break;
            }
            printf("%02x", (int)*byte);
            k = k + 1;
        } 
    }
}

void print_frame_info(const struct frame_control *mac_header){
    printf("###### Frame Control ###### \n");
    printf("Protocol: \n");
    printf("%1x\n", mac_header->protocol);
    printf("Type: \n");
    printf("%1x\n", mac_header->type);
    printf("Subtype: \n");
    printf("%1x\n", mac_header->sub_type);
    /* Update Send this to be printed for a more specific type/subtype of wlan header
    printf("###### ADDRESSES ###### \n");
    printf("ra: \n");
    print_mac(mac_header->ra);
    printf("ta: \n");
    print_mac(mac_header->ta);
    printf("da: \n");
    print_mac(mac_header->da);
    */
}
/**
 * @brief Parses just the mac frame of the wifi header.
 * @param header_start start of wlan frame.
 */
void decode_wlanframe(const unsigned char *header_start){
    /*TODO: I have no idea what there is in those first 36 bytes. DO SOMETHING!! */
    struct frame_control *mac_header;
    int radiotap_offset = sizeof(struct radiotap_hdr);
    unsigned char *main_header_start= header_start + radiotap_offset;
    printf("beacon header size: %d\n",sizeof(struct beacon_hdr));
    printf("frame control size: %d\n",sizeof(struct frame_control));
    // printf("radiotap offset: %d\n",radiotap_offset);
    // unsigned char *spointer = header_start + radiotap_offset;
    unsigned char *spointer = header_start + 36;
    char decoration[30];
    char ssid[30] = "";
    memset(decoration, '$', 30); 
    printf("%30s NEW FRAME %30s\n", decoration, decoration); 

    /* 
     * TODO: Have to add 36 here because of the radiotap header. 
     * here because of the radiotap header.
     * mac_header is just the generic frame_control, common to all 802.11
     * kind of frames.
     * */
    mac_header = (struct frame_control *)(main_header_start);

    print_frame_info(mac_header);
    //spointer = (unsigned char *)mac_header;
    if((int)(mac_header->type) == 0 
            && (int)(mac_header->sub_type) == 8) { // If packet is type beacon frame.
        printf("Beacon Frame\n");
        /*Now that we know this is a beacon header cast it to a more complete definition*/
        struct beacon_hdr *bcn_head = (struct beacon_hdr *)(main_header_start);
        printf("Size of beacon header: %d\n", sizeof(struct beacon_hdr));
        // printf("SSID: ");
        int flag = 0;
        /* TODO: I am missing 2 bytes somewhere!!!!
         * correct and delete start_ssid+=2
         * */
        printf("###> first char: %c\n", bcn_head->ssid);
        char *start_ssid =(unsigned char*) &(bcn_head->ssid); // OR is it char *?
        // char *start_ssid =(unsigned char*) (mac_header )+ sizeof(struct beacon_hdr); // OR is it char *?
        // start_ssid +=2; 
        char *end_ssid = start_ssid; // OR is it char *?

        /*TODO:This Loop is not doing what i want*/
        int k;
        for( ;is_printable(end_ssid)==1;end_ssid++) 
            k+1;
        int ssid_len = (int)(end_ssid-start_ssid);
        printf("ssid_start:%p\n",start_ssid);
        printf("ssid_end:%p\n",end_ssid);
        /*TODO:Seems like the bug is here, ssid_start is not printable, i am not doing
         *something right, offset +2 works, i am missing something somewhere
         * */
        // printf("Firs char:%c\n",*(start_ssid+2));
        printf("Firs char:%c\n",*(start_ssid));
        printf("ssidlen:%d\n",ssid_len);
        strncpy(ssid, start_ssid, ssid_len);
        /*
        char *end_ssid;
        for(int i = 0; i < 32; i++){
            end_ssid =  (char *)(spointer + sizeof(struct beacon_hdr) -1 + i);

            if(is_printable(end_ssid) == 1){
                flag = 1;
                printf("%c", *(end_ssid));
                strncat(ssid, end_ssid, 1);
            }
            if((flag == 1) && (is_printable(end_ssid) == 0)){
            fprintf(stdout,"\nFound non Printable at position: %p\n", end_ssid);  
            break;
            }
        }
        */
        printf("\n");
        printf("SSID variable value: %s\n", ssid); // ssid must be cleansed or it will accumulate for ALL iterations of this function.

    }

}


/**
 * @brief callback function for pcap_loop.
 * @param user_args custom user arguments from the pcap_loop function. 
 * @param cap_header libpcap metadata header about the packet.
 * @param packet pointer to the captured packet
 */
void parse_wlanframe( unsigned char *user_args, const struct pcap_pkthdr *cap_header, 
        const unsigned char *packet){
    printf("Total Length of the packet: %d\n", cap_header->len);
    decode_wlanframe(packet);
}


int is_printable(const char *my_char){
    int dec_value = (int)(*my_char);
    if( dec_value >=32 && dec_value <= 255) {
        return 1;
    }
    return 0;
}
