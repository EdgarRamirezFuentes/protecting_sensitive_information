from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_rsa_keys() -> RSA.RsaKey:
    '''
        Generate a RSA key of 2048 bits

        Return
        --------
        rsa_key: RsaKey
            The generated key
    '''
    return RSA.generate(2048)


def sign_document(document : bytes, sender_private_key : bytes) -> None:
    '''
        Generate a sign for the provided document

        Parameters
        -----------
        document : bytes
            It is the document that will be signed

        sender_private_key : bytes
            It is the private key that will be used to sign the document
    '''
    # Getting the sender private key
    key = RSA.import_key(sender_private_key)
    # Hashing the document
    h = SHA256.new(document)
    # Signing the hashed document
    signature = pss.new(key).sign(h)

    # Storing the signature
    with open("../signatures/document_signature.bin", "wb") as sign_file:
        sign_file.write(signature)


def encrypt_document(document : bytes, receiver_public_key : bytes):
    '''
        Encrypt a document using a hybrid encryption scheme. 
        It uses RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key.

        Parameters
        ----------
        document : bytes
            It is the document that will be encrypted

        receiver_public_key : bytes
            It is the public key that will be used to encrypt the document
    '''

    # Getting the receiver public key
    key = RSA.importKey(receiver_public_key)

    # Generating the AES session key 
    session_key = get_random_bytes(16)

    # Encrypting the session key using the receiver public key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypting the document using the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)

    # Storing the encrypted data
    with open("../encrypted_files/encrypted_data.bin", "wb") as encrypted_file:
        [ encrypted_file.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]


if __name__ == "__main__":
    # Generating the sender keys
    sender_key = generate_rsa_keys()
    sender_private_key = sender_key.export_key()
    sender_public_key = sender_key.public_key().export_key()

    # Generating the receiver keys
    receiver_key = generate_rsa_keys()
    receiver_private_key = receiver_key.export_key()
    receiver_public_key = receiver_key.public_key().export_key()

    # Storing the sender keys in its own file
    with open("../private_keys/sender_private.pem", "wb") as private_key_file:
        private_key_file.write(sender_private_key)

    with open("../public_keys/sender_public_key.pem", "wb") as public_key_file:
        public_key_file.write(sender_public_key)

    # Storing the sender keys in its own file
    with open("../private_keys/receiver_private.pem", "wb") as private_key_file:
        private_key_file.write(receiver_private_key)

    with open("../public_keys/receiver_public_key.pem", "wb") as public_key_file:
        public_key_file.write(receiver_public_key)

    # Getting the document to be encrypt
    with open("../files/Protecting_sentitive_information.pdf", "rb") as file:
        document = file.read()
    
    # Signing the document
    sign_document(document, sender_private_key)
    # Encrypting the document
    encrypt_document(document, receiver_public_key)
    

