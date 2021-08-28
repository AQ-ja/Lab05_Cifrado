# import pyAesCrypt
# password = "please-use-a-long-and-random-password"
# # encrypt
# pyAesCrypt.encryptFile("data.txt", "data.txt.aes", password)
# # decrypt
# pyAesCrypt.decryptFile("data.txt.aes", "dataout.txt", password)
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
print(flatten_list)
print(flatten_list[0])
f = open("labtw.enc", "a+")
for i in range(len(flatten_list)):
    f.write(str(flatten_list[i]))
f.close()
