#include <allheads.h>
#include <pcap.h>
#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <ctype.h>
#include "hacking.h"
#include "hacking-network.h" 

char *mon_pattern = ".*mon.*";

char *get_monitor(){
    GRegex *start_regex = g_regex_new(mon_pattern, 0, 0, NULL);
    pcap_if_t *alldevsp , *device;
 
    char errbuf[PCAP_ERRBUF_SIZE] , *devname , devs[100][100];
    char *first_device;
    int count = 1 , n;

    first_device = pcap_lookupdev(errbuf); // pcap_lookupdev returns a pointer to the first 
                                           // character of a string containing the name of the
                                           // first network interface found int the system.
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
    gint mstart=0, mend=0;
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        GMatchInfo *start_info;

        printf("%d. %s - %s\n" , count , device->name , device->description);

        g_regex_match(start_regex, (gchar *)device->name, 0, &start_info);
        g_match_info_fetch_pos(start_info, 0, &mstart, &mend);
        g_match_info_free(start_info);
        if(mend != 0){
            printf("=========>Found monitor: %s<===========\n",device->name); 
            return device->name;
        }
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    return NULL;
}

/** function get_monitorable_device
 * Needs to have root permission to work properly  and return 
 *  the right device, else it returns the first device it finds.
 *  */
pcap_t *get_monitorable_device(){
    pcap_t *pcap_handle;
    pcap_if_t *alldevsp , *device;
 
    char errbuf[PCAP_ERRBUF_SIZE] , *devname , devs[100][100];
    char *first_device;
    int count = 1, n;

    first_device = pcap_lookupdev(errbuf); // pcap_lookupdev returns a pointer to the first 
                                           // character of a string containing the name of the
                                           // first network interface found int the system.
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
        pcap_handle = pcap_create(device->name, errbuf); // Creates the device without activating it

        if(pcap_handle != NULL && pcap_can_set_rfmon(pcap_handle)){
            printf("=========>Found monitor capable interface: %s<===========\n",device->name); 
            return pcap_handle;
        }
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    return NULL;
}

int activate_monitor(pcap_t *device_handle){
    pcap_set_rfmon(device_handle, 1);
    pcap_set_snaplen(device_handle, 2048); /* Snapshot length */
    pcap_set_timeout(device_handle, 1000); /* Timeout in milliseconds */
    return pcap_activate(device_handle); /* Returns 0 on success without warnings, negative on error.
    /* handle is ready for use with pcap_next() or pcap_loop() */
}
