/***************************************************
* file:     filterARP.c
* Author:   Jerry Zou
*****************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#define TRUE 1
#define FALSE 0

int main(int argc, char **argv)
{
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    //check command line arguments
    if (argc < 2) { 
        fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
        exit(1); 
    }

    /*==================
     * STEP I
     * Read the pcap file
     *==================*/
    descr = pcap_open_offline(argv[1],errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }
    
    /*==================
     * STEP II
     * if next packet exist, parse the header of it, or jump to STEP VI
     *==================*/
    while((packet = pcap_next(descr, &hdr)) != NULL) {
        /* lets start with the ether header... */
        eptr = (struct ether_header *) packet;

        /*==================
         * STEP III
         * Justify if this packet is an ARP packet
         *==================*/
        int flag = TRUE;
        if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
            printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                    ntohs(eptr->ether_type),
                    ntohs(eptr->ether_type));
            /*==================
             * STEP IV
             * Justify if this packet is an incoming packet
             *==================*/


            

        }

        /*==================
         * STEP V
         * if the conditions of (3) and (4) are matched, drop this packet,
         * or store the data of this packet into filtered.pcap
         *==================*/
        if (flag == TRUE) {

        } else {
            
        }
    }
    
    return 0;
}