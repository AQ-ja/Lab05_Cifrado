from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

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
# === Encriptado ===
output_file = 'PruebaCFB.bin'
data = b'Esta es solo una prueba!'
key = get_random_bytes(16)
key1 = key

cipher = AES.new(key1, AES.MODE_CFB) # CFB mode
ciphered_data = cipher.encrypt(data) # Only need to encrypt the data, no padding required for this mode

file_out = open(output_file, "wb") 
file_out.write(cipher.iv)
file_out.write(ciphered_data)
file_out.close()

# === Decriptado ===
input_file = 'PruebaCFB.bin'
key = key1
file_in = open(input_file, 'rb')
iv = file_in.read(16)
ciphered_data = file_in.read()
print()
file_in.close()

cipher = AES.new(key, AES.MODE_CFB, iv=iv)
original_data = cipher.decrypt(ciphered_data) # No need to un-pad


"""

# METODO CBC
# _____________________________________ Encriptado _______________________________________________
data = b'Esta es una prueba!'  # Must be a bytes object
key = key1 # The key you generated

output_file = 'PruebaCBC.bin' # Output file
# Create cipher object and encrypt the data
cipher = AES.new(key, AES.MODE_CBC) # Create a AES cipher object with the key using the mode CBC
ciphered_data = cipher.encrypt(pad(data, AES.block_size)) # Pad the input data and then encrypt

file_out = open(output_file, "wb") # Open file to write bytes
file_out.write(cipher.iv) # Write the iv to the output file (will be required for decryption)
file_out.write(ciphered_data) # Write the varying length ciphertext to the file (this is the encrypted data)
file_out.close()

# _______________________________________ Decriptado ______________________________________________
input_file = 'PruebaCBC.bin' # Input file
key = key1 # The key used for encryption (do not store/read this from the file)
# Read the data from the file
file_in = open(input_file, 'rb') # Open the file to read bytes
iv = file_in.read(16) # Read the iv out - this is 16 bytes long
ciphered_data = file_in.read() # Read the rest of the data
file_in.close()

cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size) # Decrypt and then up-pad the result




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