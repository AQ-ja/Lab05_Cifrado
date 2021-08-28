from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode

# ------------------------------------- PRIMERA PARTE --------------------------------------------
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
print("La cadena cifrada es: ", data)
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
print(" CFB ")
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



# METODO CBC
# _____________________________________ Encriptado _______________________________________________
key2 = get_random_bytes(16)
print(" CBC ")
print("---------------------------------------------------------------------------------------")
print("La llave que se usara sera: ", key2)
data2encryp = "Prueba para el laboratorio!" # Must be a bytes object
print("Esta sera la cadena a usar: ", data2encryp)

# === Encriptado ===
dat = data2encryp.encode("utf-8")
c_encry = AES.new(key2, AES.MODE_CBC)
ciph_data = c_encry.encrypt(pad(dat, AES.block_size)) # Pad the input data and then encrypt
iv2 = c_encry.iv
ciph_byes = ciph_data
print("------------------------------------------------------")
print("La cadena cifrada es: ", ciph_data)
print("------------------------------------------------------")




# === Decriptado ===
ciph_data = AES.new(key2, AES.MODE_CBC, iv2=iv2)  # Setup cipher
original_data = unpad(ciph_data.decrypt(ciphered_data), AES.block_size) # Decrypt and then up-pad the result
print(original_data)


"""

# METODO EAX
# _____________________________________________ Encriptado ____________________________________________________
output_file = 'encrypted.bin'
data = b'Your data....'
key = b'YOUR KEY'

cipher = AES.new(key, AES.MODE_EAX) # EAX mode
ciphered_data, tag = cipher.encrypt_and_digest(data) # Encrypt and digest to get the ciphered data and tag

file_out = open(output_file, "wb")
file_out.write(cipher.nonce) # Write the nonce to the output file (will be required for decryption - fixed size)
file_out.write(tag) # Write the tag out after (will be required for decryption - fixed size)
file_out.write(ciphered_data)
file_out.close() 

#______________________________________________ Decriptado ______________________________________________________
input_file = 'encrypted.bin' # Input file (encrypted)
key = b'YOUR KEY' # The key you generated (same as what you encrypted with)

file_in = open(input_file, 'rb')
nonce = file_in.read(16) # Read the nonce out - this is 16 bytes long
tag = file_in.read(16) # Read the tag out - this is 16 bytes long
ciphered_data = file_in.read() # Read the rest of the data out
file_in.close()

# Decrypt and verify
cipher = AES.new(key, AES.MODE_EAX, nonce)
original_data = cipher.decrypt_and_verify(ciphered_data, tag) # Decrypt and verify with the tag


print("Bienvenido al Laboratorio No.2\n Que desea hacer: \n")
print(" 1. Ejemplo basico del metodo AES\n 2. Ejemplo basico del metodo AES con CFB\n 3. Ejemplo basico del metodo AES con CBC\n ")
try:
    op = int(input())
    if op > 0 and op < 10:
        if op == 1:
            print("Ha seleccionado la opcion 1\n")
            Parte1()
            
        if op == 2:
            print("Ha seleccionado la opcion 2\n")
            print(CFB_Encryp())
        if op == 3:
            print("Ha seleccionado la opcion 3\n")
          
        if op == 4:
            print("Ha seleccionado la opcion 4\n")
    else:
        print("Gracias por usar el programa")

except ValueError:
    print("Debe de ingresar un numero")

"""




# Referencia:
# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/