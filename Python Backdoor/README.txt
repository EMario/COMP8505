//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
		 	   Assignment #3
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
		   	     Backdoor
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
		 	  Mario Enriquez
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
		    	      README
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

Requirements:
	-Python 2.X
	-Scapy 2.X.X

**********
sniffer.py
**********
Simple backdoor program, backdoor program name is sniffer.
Requires cyphermod.py and maskname.py in the same folder.
To run:

python sniffer.py (mask_name) (interface) (filter) (dstport) (key)

maskname: name to mask the process
interface: from which interface we're going to get the messages
filter: libcap filter to catch the packets directed to the backdoor
dstport: port to send the message back
key: use to encrypt packets

**********
command.py
**********
Backdoor master, can issue commands to the backdoor and the backdoor 
will execute them.
To run:

python command.py (dest_ip) (protocol) (dest_port) (rec_port) (key)

dest_ip: ip to send the packet to
protocol: protocol to use to send packets
dstport: port to send the message
rec_port: port to receive the message back
key: use to encrypt packets

******
Issues
******
First time running, executes and freezes. Exiting and runnign again 
seem to solve the issue
