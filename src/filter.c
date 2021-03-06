/***************************************************
* file:     filter.c
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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define TRUE   1
#define FALSE  0

#define ETHER_HEADER_LEN  14
#define UDP_HEADER_LEN    8
#define DNS_PORT          53

struct dnshdr {
    u_short id;
    u_short flags;
#define FLAG_QR       1
#define FLAG_OPCODE   30
#define FLAG_AA       32
#define FLAG_TC       64
#define FLAG_RD       128
#define FLAG_RA       256
#define FLAG_Z        3584
#define FLAG_RCODE    61440
    u_short qd_count;
    u_short an_count;
    u_short ns_count;
    u_short ar_count;
};



int main(int argc, char **argv)
{
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    pcap_dumper_t *filtered;
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

    filtered = pcap_dump_open(descr, "output/filtered.pcap");

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

        int flag = TRUE;
        /*==================
         * STEP III - IV
         * Justify if this packet is an incoming ARP packet / outgoing DNS query
        *==================*/
        if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
            struct arphdr *arp_header = (struct arphdr *) (packet + ETHER_HEADER_LEN);
            if (ntohs(arp_header->ar_op) == ARPOP_REPLY) {
                printf("Drop an incoming ARP packet!\n");
                flag = FALSE;
            }
        } else if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *) (packet + ETHER_HEADER_LEN);
            if (ip_header->ip_p == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *) (packet + ETHER_HEADER_LEN + ip_header->ip_hl * 4);
                struct dnshdr *dns_header = (struct dnshdr *) (packet + ETHER_HEADER_LEN + ip_header->ip_hl * 4 + UDP_HEADER_LEN);
                if ((ntohs(dns_header->flags) & FLAG_QR) == 0
                      && ntohs(dns_header->an_count) == 0
                      && ntohs(dns_header->ns_count) == 0
                      && (ntohs(dns_header->flags) & FLAG_Z) == 0
                      && (ntohs(dns_header->flags) & FLAG_RCODE) == 0) {
                    printf("Drop an outgoing DNS packet through UDP! Target Port:%d \n", ntohs(udp_header->uh_dport));
                    flag = FALSE;
                }
            }
        }

        /*==================
         * STEP V
         * if the conditions of (3) and (4) are matched, drop this packet,
         * or store the data of this packet into filtered.pcap
        *==================*/
        if (flag) {
            pcap_dump((u_char *)filtered, &hdr, packet);
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