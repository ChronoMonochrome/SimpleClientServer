from sys import version as python_version
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
if python_version.startswith('3'):
	pad = lambda s: s + bytes((BS - len(s) % BS) * chr(BS - len(s) % BS), "u8")
	unpad = lambda s: s[:-ord(s[len(s)-1:])]
else:
	pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
	unpad = lambda s: s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)) 

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[ :16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:] ))


