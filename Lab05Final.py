from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode
from itertools import chain

fdatos = open("lab.txt", "r")
xdatos = []


lineas = fdatos.readlines()
with open("lab.txt") as fname:
    lineas = fname.readlines()
    for linea in lineas:

        xdatos.append(linea.replace("\n", "").split(" "))


fdatos.close()
flatten_list = list(chain.from_iterable(xdatos))
listEncript = []
listDec = []
for i in range(len(flatten_list)):

    data = flatten_list[i]
    data = str.encode(data)
    key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)

    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    listEncript.append(ct)

    try:

        nonce = b64decode(nonce)
        ct = b64decode(ct)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct).decode('utf-8')
        listDec.append(pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")

f = open("lab.enc", "w+")
for i in range(len(listEncript)):
    f.write(str(listEncript[i]))
f.close()

fdec = open("lab.dec", "w+")
for i in range(len(listDec)):
    fdec.write(str(listDec[i]))
fdec.close()
