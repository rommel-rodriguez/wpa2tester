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
#include "monitor.h" 
#include "cappacket.h"

void pcap_fatal(const char *, const char *);
void decode_ethernet(const unsigned char *);
void decode_ip(const unsigned char *);
u_int decode_tcp(const unsigned char *);
void parse_arguments(int argc, char *argv[]);


int main(int argc, char *argv[]){
    //printf("All arguments:\n%s\n", argv[1]);
    //parse_arguments(argc, argv);
    pcap_t *device_handle;
    if ((device_handle = get_monitorable_device()) != NULL){
        printf("Main: Found monitorable device \n"); 
        printf("Attempting to set device to monitor mode...\n");
        if(activate_monitor(device_handle) >= 0){
            printf("Monitor mode enabled.\n");
            pcap_loop(device_handle, 100, parse_wlanframe, NULL);
        }else
            printf("Could NOT activate monitor mode.\n");

    }else{
        exit(1); 
    }
}

void pcap_fatal(const char *failed_in, const char *errbuf){
    printf("Fatal Error in %s:%s\n", failed_in, errbuf);
    exit(1);
}

void parse_arguments(int argc, char *argv[]){
    printf("Testing Inside:\n%s\n", argv[3]);
    int c;
    opterr = 0;
    char cvalue[100];
    while ((c = getopt(argc, argv, "abc:")) != 1)
        switch (c){
            case 'a': fprintf(stdout, "Option Selected is %c\n", c);
                      break;
            case 'b': fprintf(stdout, "Option Selected is %c\n", optopt);
                      break;
            case 'c': strcpy(cvalue,  optarg);
                      printf("C has Value %s\n", cvalue);
                      break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                        fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                        fprintf (stderr,
                                "Unknown option character `\\x%x'.\n",
                                optopt);
                        return ;
                        break;
            default:
                printf("No Option passed, Terminating the program\n");
                abort ();
        }
}
