##
##  Author:   Mario Enriquez,   A00909441
##  Class:    COMP_8505
##  Title:    Final Assignment, Covert Communication
##	Makefile
##
covert: send_packet.o headers.o recv_packet.o
	g++ -o covert covert.cpp recv_packet.o send_packet.o headers.o -lpcap -lpthread

clean:
	rm -f *.o core covert

send_packet.o:
	g++ -c send_packet.cpp

headers.o:
	g++ -c headers.cpp

recv_packet.o:
	g++ -c recv_packet.cpp
