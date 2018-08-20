#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Mario Enriquez, 2016. COMP 8505 Assignment 3
#
# Encrypts and decrypts a text in AES mode based on a key
#

from Crypto.Cipher import AES
import base64

def encode(key,text): #encrypts the text in AES and then BASE 64
  cipher = AES.new(key,AES.MODE_ECB)
  encode = base64.b64encode(cipher.encrypt(text))
  return encode

def decode(key,text): #decodes the AES text in base 64 and then decrypts
  cipher = AES.new(key,AES.MODE_ECB)
  decode = cipher.decrypt(base64.b64decode(text))
  return decode
