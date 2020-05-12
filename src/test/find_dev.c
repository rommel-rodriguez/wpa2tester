#include <allheads.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hacking.h"
#include "hacking-network.h" 

void pcap_fatal(const char *, const char *);
void decode_ethernet(const u_char *);
void decode_ip(const u_char *);
u_int decode_tcp(const u_char *);

int main(){
    pcap_if_t *alldevsp , *device;
 
    char errbuf[PCAP_ERRBUF_SIZE] , *devname , devs[100][100];
    char *first_device;
    int count = 1 , n;

    first_device = pcap_lookupdev(errbuf);
    printf("First Device %s\n", first_device);
    //First get the list of available devices
    printf("Finding available devices ... ");

    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    
}

void pcap_fatal(const char *failed_in, const char *errbuf){
    printf("Fatal Error in %s\n", failed_in, errbuf);
    exit(1);
}
