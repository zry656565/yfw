/***************************************************
* file:     tcpLimit.c
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
#include <string.h>

#define TRUE   1
#define FALSE  0

#define ETHER_HEADER_LEN    14

// TCP Connection Status
typedef enum {CLOSED, SYN_WAIT, ESTABLISHED, FIN_WAIT} con_status;

#define MAX_TCP_CONNECTION  5

char connectionNum = 0;

struct connection {
    con_status status;
    char local_ip[16];
    char remote_ip[16];
    u_short local_port;
    u_short remote_port;
    tcp_seq seq;
} connectionList[MAX_TCP_CONNECTION];

struct connection *findNextFree();

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

    for (int j = 0; j < MAX_TCP_CONNECTION; j++) {
        connectionList[j].status = CLOSED;
    }

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
     * STEP III
     * If next packet exists, parse the header of it, or jump to STEP(IX)
    *==================*/
    while((packet = pcap_next(descr, &hdr)) != NULL) {
        /* lets start with the ether header... */
        eptr = (struct ether_header *) packet;

        int flag = TRUE;
        if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *) (packet + ETHER_HEADER_LEN);
            char ip_src[16], ip_dst[16];
            strcpy(ip_src, inet_ntoa(ip_header->ip_src));
            strcpy(ip_dst, inet_ntoa(ip_header->ip_dst));

            if (ip_header->ip_p == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETHER_HEADER_LEN + ip_header->ip_hl * 4);
                uint32_t seq = ntohl(tcp_header->th_seq);
                uint32_t ack = ntohl(tcp_header->th_ack);
                char flag_syn = tcp_header->th_flags & TH_SYN;
                char flag_fin = tcp_header->th_flags & TH_FIN;
                char flag_ack = tcp_header->th_flags & TH_ACK;

                
                if (flag_syn && !flag_ack) {
                    // first of three handshakings for SYN
                    if (connectionNum < MAX_TCP_CONNECTION) {
                        int index = -1;
                        struct connection *conn = findNextFree(&index);
                        connectionNum++;
                        conn->status = SYN_WAIT;
                        conn->seq = seq;
                        strcpy(conn->local_ip, ip_src);
                        strcpy(conn->remote_ip, ip_dst);
                        conn->local_port = tcp_header->th_sport;
                        conn->remote_port = tcp_header->th_dport;
                        printf("Connection %d: SYN_SEND        \tRemote IP: %s \tPort: %u\n", index, conn->remote_ip, conn->remote_port);
                    } else {
                        //connection number reach `MAX_TCP_CONNECTION`, cannot create a new connection
                        flag = FALSE;
                    }
                } else if (flag_syn && flag_ack) {
                    // second of three handshakings for SYN
                    int find = FALSE;
                    struct connection *conn;
                    for (int j = 0; j < MAX_TCP_CONNECTION && !find; j++) {
                        conn = &connectionList[j];
                        if (conn->status == SYN_WAIT && ack == conn->seq + 1) {
                            conn->status = ESTABLISHED;
                            find = TRUE;
                            printf("Connection %d: ESTABLISHED \tRemote IP: %s\tPort: %u\n", j, conn->remote_ip, conn->remote_port);
                        }
                    }
                    if (!find) {
                        flag = FALSE;
                    }
                } else if (flag_fin) {
                    // fin for closing the connection
                    int find = FALSE;
                    struct connection *conn;
                    for (int j = 0; j < MAX_TCP_CONNECTION && !find; j++) {
                        conn = &connectionList[j];
                        // first of four handshakings for FIN
                        if (conn->status == ESTABLISHED
                              && (!strcmp(conn->remote_ip, ip_dst) && conn->remote_port == tcp_header->th_dport)) {
                            conn->status = FIN_WAIT;
                            find = TRUE;
                            printf("Connection %d: FIN_SEND    \tRemote IP: %s\tPort: %u\n", j, conn->remote_ip, conn->remote_port);
                        }
                        // third of four handshakings for FIN
                        else if (conn->status == FIN_WAIT
                              && (!strcmp(conn->remote_ip, ip_src) && conn->remote_port == tcp_header->th_sport)) {
                            conn->status = CLOSED;
                            connectionNum--;
                            find = TRUE;
                            printf("Connection %d: CLOSED      \tRemote IP: %s\tPort: %u\n", j, conn->remote_ip, conn->remote_port);
                        }
                    }
                    if (!find) {
                        flag = FALSE;
                    }
                } else {
                    int find = FALSE;
                    struct connection *conn;
                    for (int j = 0; j < MAX_TCP_CONNECTION && !find; j++) {
                        conn = &connectionList[j];
                        // if this packet belongs to an existed connection.
                        if ((!strcmp(conn->remote_ip, ip_src) && conn->remote_port == tcp_header->th_sport)
                                || (!strcmp(conn->remote_ip, ip_dst) && conn->remote_port == tcp_header->th_dport)) {
                            find = TRUE;
                        }
                    }
                    if (!find) {
                        flag = FALSE;
                    }
                }
            }
        }

        if (flag) {
            pcap_dump((u_char *)filtered, &hdr, packet);
        }
    }

    pcap_close(descr);
    pcap_dump_close(filtered);

    return 0;
}

struct connection *findNextFree(int *index) {
    for (int i = 0; i < MAX_TCP_CONNECTION; i++) {
        if (connectionList[i].status == CLOSED) {
            *index = i;
            return &connectionList[i];
        }
    }
    return (struct connection *)NULL;
}