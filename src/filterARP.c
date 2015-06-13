/***************************************************
* file:     filterARP.c
* Author:   Jerry Zou
*****************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#define DEBUG 1

#define TRUE 1
#define FALSE 0

#define ETHER_HEADER_LEN 14

int main(int argc, char **argv)
{
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    pcap_dumper_t* filtered;
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

    if(descr == NULL) {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }

    filtered = pcap_dump_open(descr, "output/filtere.pcap");

    if(filtered == NULL) {
        printf("Error: pcap_dump_open() - filtered.pcap\n");
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
#ifdef DEBUG
            printf("Ethernet type hex:%x is an ARP packet\n",
                    ntohs(eptr->ether_type));
#endif
            /*==================
             * STEP IV
             * Justify if this packet is an incoming packet
            *==================*/
            struct arphdr* arp_header = (struct arphdr *) (packet + ETHER_HEADER_LEN);
            if (ntohs(arp_header->ar_op) == ARPOP_REPLY) {
#ifdef DEBUG
                printf("Incoming ARP packet!\n");
#endif
                flag = FALSE;
            }
        }

        /*==================
         * STEP V
         * if the conditions of (3) and (4) are matched, drop this packet,
         * or store the data of this packet into filtered.pcap
        *==================*/
        if (flag == TRUE) {
            pcap_dump(filtered, &hdr, packet);
        }
    }

    /*==================
     * STEP VI
     * DONE
    *==================*/
    pcap_close(descr);
    pcap_dump_close(filtered);

    return 0;
}