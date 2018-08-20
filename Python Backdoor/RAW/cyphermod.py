from Crypto.Cipher import AES
import base64

def encode(key,text):
  cipher = AES.new(key,AES.MODE_ECB)
  encode = base64.b64encode(cipher.encrypt(text))
  return encode

def decode(key,text):
  cipher = AES.new(key,AES.MODE_ECB)
  decode = cipher.decrypt(base64.b64decode(text))
  return decode
