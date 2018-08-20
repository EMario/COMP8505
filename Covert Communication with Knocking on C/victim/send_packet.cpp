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

#include "headers.h"

struct tcp_pseudo_header{
  //    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

struct udp_pseudo_header{
  //    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr,int nbytes){
	//    Generic checksum calculation function
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;

  return(answer);
}

void forgepacket(char src_host[],char dst_host[],int dst_port,char* payload, int ipid, int flag[]){
  //TCP packet builder
  char datagram[4096] , source_ip[32] , *data , *pseudogram;
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  struct iphdr *iph = (struct iphdr *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
  struct sockaddr_in sin;
  struct tcp_pseudo_header psh;
  int psize;
  int one = 1;
  const int *val = &one;

  if(s == -1){
  //socket creation failed, may be because of non-root privileges
    perror("Failed to create socket");
    exit(1);
  }
  //Datagram to represent the packet

  //zero out the packet buffer
  memset (datagram, 0, 4096);

  //Data part
  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  strcpy(data , payload);

  //some address resolution
  strcpy(source_ip , src_host);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(dst_port);
  sin.sin_addr.s_addr = inet_addr (dst_host);

  //Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
  iph->id = (ipid); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;
  //Ip checksum
  iph->check = csum ((unsigned short *) datagram, iph->tot_len);

  //TCP Header
  tcph->source = htons (1+(int)(10000.0*rand()/(RAND_MAX+1.0))); //We don't care about the source
  tcph->dest = sin.sin_port;
  tcph->seq = 1+(int)(10000.0*rand()/(RAND_MAX+1.0));
  tcph->ack_seq = 0;
  tcph->doff = 5;  //tcp header size
  tcph->fin=flag[0];
  tcph->syn=flag[1];
  tcph->rst=flag[2];
  tcph->psh=flag[3];
  tcph->ack=flag[4];
  tcph->urg=flag[5];
  tcph->window = htons (5840); /* maximum allowed window size */
  tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;

  //Now the TCP checksum
  psh.source_address = inet_addr( source_ip );
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

  psize = sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr) + strlen(data);
  pseudogram = (char*)malloc(psize);

  memcpy(pseudogram , (char*) &psh , sizeof (struct tcp_pseudo_header));
  memcpy(pseudogram + sizeof(struct tcp_pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));

  tcph->check = csum( (unsigned short*) pseudogram , psize);

  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
    perror("Error setting IP_HDRINCL");
    exit(0);
  }
  if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
    perror("sendto failed");
  }

}

void forgedatagram(char src_host[],char dst_host[],int dst_port,char* payload, int ipid, int flag[]){
  //UDP packet builder
  char datagram[4096] , source_ip[32] , *data , *pseudogram;
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  struct iphdr *iph = (struct iphdr *) datagram;
  struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
  struct sockaddr_in sin;
  struct udp_pseudo_header psh;
  int psize;
  int one = 1;
  const int *val = &one;

  if(s == -1){
  //socket creation failed, may be because of non-root privileges
    perror("Failed to create socket");
    exit(1);
  }

  //zero out the packet buffer
  memset (datagram, 0, 4096);

  //Data part
  data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(data , payload);

  //some address resolution
  strcpy(source_ip , src_host);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(dst_port);
  sin.sin_addr.s_addr = inet_addr (dst_host);

  //Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
  iph->id = (ipid); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;
  //Ip checksum
  iph->check = csum ((unsigned short *) datagram, iph->tot_len);

  //UDP Header
  udph->source = htons (1+(int)(10000.0*rand()/(RAND_MAX+1.0)));
  udph->dest = sin.sin_port;
  udph->len = htons(8 + strlen(data));
  udph->check = 0; //leave checksum 0 now, filled later by pseudo header

  //Now the TCP checksum
  psh.source_address = inet_addr( source_ip );
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_UDP;
  psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

  psize = sizeof(struct tcp_pseudo_header) + sizeof(struct udphdr) + strlen(data);
  pseudogram = (char*)malloc(psize);

  memcpy(pseudogram , (char*) &psh , sizeof (struct udp_pseudo_header));
  memcpy(pseudogram + sizeof(struct udp_pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

  udph->check = csum( (unsigned short*) pseudogram , psize);

  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
    perror("Error setting IP_HDRINCL");
    exit(0);
  }
  if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
    perror("sendto failed");
  }

}
