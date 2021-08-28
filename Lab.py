from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode, b64decode
from hashlib import md5



"""
# ------------------------------------- PRIMERA PARTE ------------------------------------------
key = get_random_bytes(16)
print("")
print("------------------------------------------------------")
print("La llave que se usara es: ", key)
data_to_encrypt = "Esta es solo una prueba del metodo"
print("Este sera la cadena a usar:", data_to_encrypt)
print("------------------------------------------------------")
#  === Encriptado ===
data = data_to_encrypt.encode('utf-8')
cipher_encrypt = AES.new(key, AES.MODE_CFB)
ciphered_bytes = cipher_encrypt.encrypt(data)
iv = cipher_encrypt.iv
ciphered_data = ciphered_bytes
print("------------------------------------------------------")
print("La cadena cifrada es: ", ciphered_bytes)
print("------------------------------------------------------")
# === Decriptado ===
cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
deciphered_bytes = cipher_decrypt.decrypt(ciphered_data)
decrypted_data = deciphered_bytes.decode('utf-8')
print("------------------------------------------------------")
print("La cadena descifrada es: ", decrypted_data)
print("TEXTO ORIGINAL: ", data_to_encrypt)
print("TEXTO DESCIFRADO: ", decrypted_data)
print('La cadena cifrada y descifrada son identicas.')
print("------------------------------------------------------")



# ------------------------------------- SEGUNDA PARTE --------------------------------------------
# METODO CFB
key = get_random_bytes(16)
print("")
print("------------------------------------------------------")
print("La llave que se usara es: ", key)
data_to_encrypt = "Esta es solo una prueba del metodo"
print("Este sera la cadena a usar:", data_to_encrypt)
print("------------------------------------------------------")
#  === Encriptado ===
data = data_to_encrypt.encode('utf-8')
cipher_encrypt = AES.new(key, AES.MODE_CFB)
ciphered_bytes = cipher_encrypt.encrypt(data)
iv = cipher_encrypt.iv
ciphered_data = ciphered_bytes
print("------------------------------------------------------")
print("La cadena cifrada es: ", ciphered_data)
print("------------------------------------------------------")
# === Decriptado ===
cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
deciphered_bytes = cipher_decrypt.decrypt(ciphered_data)
decrypted_data = deciphered_bytes.decode('utf-8')
print("------------------------------------------------------")
print("La cadena descifrada es: ", decrypted_data)
print("TEXTO ORIGINAL: ", data_to_encrypt)
print("TEXTO DESCIFRADO: ", decrypted_data)
print('La cadena cifrada y descifrada son identicas.')
print("------------------------------------------------------")
"""


print("PROBANDO EL METODO NUEVO")
msg = input()


class AESCipher:

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        key = get_random_bytes(16)
        print("La contraseña es: ", key )
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
        AES.block_size)))

def decrypt(self, data):
    key = input()
    raw = b64decode(data)
    self.cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

if __name__ == '__main__':
    print('TESTING ENCRYPTION')
    msg = input('Message...: ')
    pwd = input('Password..: ')
    print('Ciphertext:', AESCipher(pwd).encrypt(msg).decode('utf-8'))

    print('\nTESTING DECRYPTION')
    cte = input('Ciphertext: ')
    pwd = input('Password..: ')
    print('Message...:', AESCipher(pwd).decrypt(cte).decode('utf-8'))

