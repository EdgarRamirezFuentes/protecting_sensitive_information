from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def verify_signature(decrypted_document : bytes, sender_public_key : bytes, signature : bytes) -> bool:
    '''
        Veryfy if the original signature is the same than the obtained signature from the decrypted document

        Parameters
        -----------
        decrypted_document : bytes
            It is the decrypted document that will be used to generate a signature

        sender_public_key : bytes
            It is the sender public key that will be used to verify if the obtained signature is the same than the original signature

        signature : bytes
            It is the original signature
        
        Return
        ---------
            True if the signatures match, otherwise False
    '''

    # Getting the sender public key
    key = RSA.import_key(sender_public_key)

    # Hashing the decrypted document
    h = SHA256.new(decrypted_document)

    verifier = pss.new(key)
    try:
        # Compare the hashed decrypted document signature with the original signature
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        # If the signatures are not the same, it returns False
        return False


def decrypt_document(encrypted_document : bytes, receiver_private_key : bytes, sender_public_key : bytes):
    '''
        Decrypt a document using a hybrid encryption scheme. 
        It uses RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key.

        Parameters
        -----------

        encrypted_document : bytes
            It is a reference (pointer) to the document that contains the encrypted document
        
        receiver_private_key : bytes
            It is the receiver private key that will be used to decrypt the AES session key

        sender_public_key : bytes
            It is the sender public key that will be used to verify the signature
    '''
    # Getting the receiver private key
    private_key = RSA.import_key(receiver_private_key)

    # Getting the sender public key
    public_key = RSA.import_key(sender_public_key)

    # Getting the necessary information to decrypt the document
    enc_session_key, nonce, tag, ciphertext = \
    [ encrypted_document.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypting the session key using the receiver private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypting the document using the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_document = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Getting the document signature
    with open("../signatures/document_signature.bin", "rb") as signature_file:
        signature = signature_file.read() 

    # Verifying the signature
    is_valid_signature = verify_signature(decrypted_document, sender_public_key, signature)

    if is_valid_signature:
        # Writing the decrypted document in a new PDF file
        with open("../decrypted_files/decrypted_document.pdf", "wb") as decrypted_data_file:
            decrypted_data_file.write(decrypted_document)
        print("The document was decrypted successfully")
    else:
        print("The signature is not authentic and the document was not decrypted.")



if __name__ == "__main__":
    # Getting the receiver private key
    with open("../private_keys/receiver_private.pem", "rb") as receiver_private_key_file:
        receiver_private_key = receiver_private_key_file.read()

    # Getting the sender public key
    with open("../public_keys/sender_public_key.pem", "rb") as sender_public_key_file:
        sender_public_key = sender_public_key_file.read()
    
    # Opening the encrypted document
    encrypted_document = open("../encrypted_files/encrypted_data.bin", "rb")
    
    # Decrypting the document
    decrypt_document(encrypted_document, receiver_private_key, sender_public_key)
    
    # Closing the encrypted document
    encrypted_document.close()


