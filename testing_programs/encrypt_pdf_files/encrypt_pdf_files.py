'''
    Name: encrypt_pdf_files.py
    Description: Encrypt/Decrypt pdf files using RSA and AES
    Date: 29/11/21
    Authors:
    - Ramírez Fuentes Edgar Alejandro - @EdgarRamirezFuentes
    - Salmerón Contreras María José - @MarySalmeron
    - Rodríguez Melgoza Ivette - @Ivette1111
'''

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

##############################################
# Generating RSA Keys
##############################################

# Generate the RSA keys
key = RSA.generate(2048)

# Getting the private and public keys
private_key = key.export_key()
public_key = key.publickey().export_key()

##############################################
# Encrypting data
##############################################

# Storing the keys in its own file
with open("./keys/private.pem", "wb") as private_key_file:
    private_key_file.write(private_key)

with open("./keys/receiver.pem", "wb") as public_key_file:
    public_key_file.write(public_key)

# Getting the data to be encrypted
with open("./files/Protecting_sentitive_information.pdf", "rb") as file:
    data = file.read()

# Recovering the public key
with open("./keys/receiver.pem") as public_key_file:
    recipient_key = RSA.import_key(public_key_file.read())

session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
enc_session_key = cipher_rsa.encrypt(session_key)

# Storing the encrypted data
with open("./files/encrypted_data.bin", "wb") as encrypted_file:
    [ encrypted_file.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]


##############################################
# Decrypting data
##############################################

# Getting the private key
with open("./keys/private.pem") as private_key_file:   
    private_key = RSA.import_key(private_key_file.read())

# Getting the encrypted data
with open("./files/encrypted_data.bin", "rb") as encrypted_data_file:
    # Getting the necessary data to decrypt the data
    enc_session_key, nonce, tag, ciphertext = \
    [ encrypted_data_file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Write the decrypted data in a new PDF file
with open("./files/decrypted_pdf_file.pdf", "wb") as decrypted_data_file:
    decrypted_data_file.write(data)
