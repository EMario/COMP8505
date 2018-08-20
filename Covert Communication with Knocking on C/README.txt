RRRRRRRRRRRRRRRRR   EEEEEEEEEEEEEEEEEEEEEE               AAA               DDDDDDDDDDDDD        MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE
R::::::::::::::::R  E::::::::::::::::::::E              A:::A              D::::::::::::DDD     M:::::::M             M:::::::ME::::::::::::::::::::E
R::::::RRRRRR:::::R E::::::::::::::::::::E             A:::::A             D:::::::::::::::DD   M::::::::M           M::::::::ME::::::::::::::::::::E
RR:::::R     R:::::REE::::::EEEEEEEEE::::E            A:::::::A            DDD:::::DDDDD:::::D  M:::::::::M         M:::::::::MEE::::::EEEEEEEEE::::E
  R::::R     R:::::R  E:::::E       EEEEEE           A:::::::::A             D:::::D    D:::::D M::::::::::M       M::::::::::M  E:::::E       EEEEEE
  R::::R     R:::::R  E:::::E                       A:::::A:::::A            D:::::D     D:::::DM:::::::::::M     M:::::::::::M  E:::::E             
  R::::RRRRRR:::::R   E::::::EEEEEEEEEE            A:::::A A:::::A           D:::::D     D:::::DM:::::::M::::M   M::::M:::::::M  E::::::EEEEEEEEEE   
  R:::::::::::::RR    E:::::::::::::::E           A:::::A   A:::::A          D:::::D     D:::::DM::::::M M::::M M::::M M::::::M  E:::::::::::::::E   
  R::::RRRRRR:::::R   E:::::::::::::::E          A:::::A     A:::::A         D:::::D     D:::::DM::::::M  M::::M::::M  M::::::M  E:::::::::::::::E   
  R::::R     R:::::R  E::::::EEEEEEEEEE         A:::::AAAAAAAAA:::::A        D:::::D     D:::::DM::::::M   M:::::::M   M::::::M  E::::::EEEEEEEEEE   
  R::::R     R:::::R  E:::::E                  A:::::::::::::::::::::A       D:::::D     D:::::DM::::::M    M:::::M    M::::::M  E:::::E             
  R::::R     R:::::R  E:::::E       EEEEEE    A:::::AAAAAAAAAAAAA:::::A      D:::::D    D:::::D M::::::M     MMMMM     M::::::M  E:::::E       EEEEEE
RR:::::R     R:::::REE::::::EEEEEEEE:::::E   A:::::A             A:::::A   DDD:::::DDDDD:::::D  M::::::M               M::::::MEE::::::EEEEEEEE:::::E
R::::::R     R:::::RE::::::::::::::::::::E  A:::::A               A:::::A  D:::::::::::::::DD   M::::::M               M::::::ME::::::::::::::::::::E
R::::::R     R:::::RE::::::::::::::::::::E A:::::A                 A:::::A D::::::::::::DDD     M::::::M               M::::::ME::::::::::::::::::::E
RRRRRRRR     RRRRRRREEEEEEEEEEEEEEEEEEEEEEAAAAAAA                   AAAAAAADDDDDDDDDDDDD        MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE
                                                                                                                                                     

To run the victim machine:

	-extract all the files within the victim's directory
	-On Linux execute the command:
				$make  covert
	-Run the command:
				$./covert

For configuration, the following fields are required with the value type:
protocol (tcp/udp)
src_host (ip)
dst_host (ip)
ip_id 	 (int)
password (int)
exf_dir  (directory)
dst_port (int)
src_port (int)
knock_1  (int)
knock_2  (int)
knock_3  (int)
tcp_port (int)

To run the host machine:

	-extract all the files within the host's directory
	-On Linux execute the command:
				$make  covert
	-Run the command:
				$./covert
				
For configuration, the following fields are required with the value type:
protocol (tcp/udp)
src_host (ip)
dst_host (ip)
ip_id 	 (int)
password (int)
dst_port (int)
src_port (int)
knock_1  (int)
knock_2  (int)
knock_3  (int)
tcp_port (int)
	