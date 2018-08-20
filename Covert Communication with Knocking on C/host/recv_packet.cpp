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
#include <stdlib.h>
#include "headers.h"
#include <stdio.h>
using std::string;
using std::cout;
using std::endl;

struct recv_tcp
{
   struct iphdr ip;
   struct tcphdr tcp;
   char buffer[10000];
} recv_tcp;

void recv_packet(){
  int recv_socket;
  struct recv_tcp recv_pkt;
  int i=0,j;
  char buf[5000],filename[20],data[5000];
  char c;
  char * pch;
  int first=0;
  FILE *f;
  while(1) /* read packet loop */
  {
    /* Open socket for reading */
    recv_socket = socket(AF_INET, SOCK_RAW, 6);
    if(recv_socket < 0)
    {
       perror("receive socket cannot be open. Are you root?");
       exit(1);
    }
   /* Listen for return packet on a passive socket */
   read(recv_socket, (struct recv_tcp *)&recv_pkt, 9999);
   c = (char)((recv_pkt.ip.id+'0')-10);
   buf[i]=c;
   i++;
   if(recv_pkt.buffer[0]=='1'){ //Writes into a file data gotten from the socket
     j=0;
     do{
       filename [j]=buf[j];
       j++;
     }while (buf[j]!='|');
     j++;
     f=fopen(buf,"w");
     if (f == NULL){
        printf("Error opening file!\n");
        exit(1);
     }
     while (j<i-1){
       fprintf(f,"%c",buf[j]);
       j++;
     }
     fclose(f);
     memset(buf,0,sizeof(buf));
     /*for (j=0;j<i;j++){
       cout << buf[j];

     }
     pch = strtok (buf,"|");
     cout << pch << endl;
     f=fopen(pch,"w");
     while (pch != NULL){
       pch = strtok (NULL, "|");
       fprintf (f,pch);
     }
     fclose(f);
     memset(buf,0,sizeof(buf));*/
   }
   /*if(recv_pkt.buffer[0]=='1'){
     for (j=0;j<i;j++){
       cout << buf[j];
     }
     i=0;
     memset(buf,0,sizeof(buf));
   }*/
    close(recv_socket); /* close the socket so we don't hose the kernel */
   }/* end while() read packet loop */
}
