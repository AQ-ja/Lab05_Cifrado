from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

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
# === Encriptado ===
key = get_random_bytes(16)
print("------------------------------------------------------")
print("La llave que se usara es: ", key)
data_to_encrypt = "Esta es solo una prueba del metodo CFB!"
print("La cadena a utilizar es: ", data_to_encrypt)
data = data_to_encrypt.encode("utf-8")
cipher = AES.new(key, AES.MODE_CFB)
ciphered_data = cipher.encrypt(data)
iv = cipher.iv 
print("------------------------------------------------------")
print("La cadena cifrada es: ", cipher)
print("------------------------------------------------------")

# === Decriptado ===
cipher = AES.new(key, AES.MODE_CFB, iv=iv)
original_data = cipher.decrypt(ciphered_data)
decrypted_data = original_data.decode("utf-8")
print("------------------------------------------------------")
print("La cadena descifrada es: ", decrypted_data)
print("TEXTO ORIGINAL: ", original_data)
print("TEXTO DESCIFRADO: ", decrypted_data)
print('La cadena cifrada y descifrada son identicas.')
print("------------------------------------------------------")