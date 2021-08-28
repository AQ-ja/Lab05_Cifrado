import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode
from itertools import chain


data = b"secret"
key = get_random_bytes(16)

cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(data)

nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')

try:
    print(nonce)
    nonce = b64decode(nonce)
    ct = b64decode(ct)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    print("The message was: ", pt.decode('utf-8'))
except (ValueError, KeyError):
    print("Incorrect decryption")
