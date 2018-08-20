##
##  Author:   Mario Enriquez,   A00909441
##  Class:    COMP_8505
##  Title:    Final Assignment, Covert Communication
##	Makefile
##
covert: send_packet.o headers.o exfilt.o
	g++ -o covert covert.cpp send_packet.o headers.o exfilt.o -lpcap -lpthread

clean:
	rm -f *.o core covert

send_packet.o:
	g++ -c send_packet.cpp

headers.o:
	g++ -c headers.cpp

exfilt.o:
	g++ -c exfilt.cpp
