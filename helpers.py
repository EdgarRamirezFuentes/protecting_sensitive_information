from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os, shutil, time

ALLOWED_EXTENSIONS = {'bin', 'pdf'}
TMP_FOLDER = './assets/tmp/'

def allowed_file(filename : str):
    '''
        Check if the introduced file is allowed

        Paramaters
        -----------

        filename : str
            It is the filename that will be verified

        Return
        ----------
        True if the file is allowed. Otherwise, False
    '''
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
    try:
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
    except:
        # Something went wrong
        return False


def decrypt_document(encrypted_document : bytes, receiver_private_key : bytes, sender_public_key : bytes, original_signature : bytes, filename : str):
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

        original_signature : bytes
            It is the original signature of the file that will be decrypted

        filename : str
            It is the filename of the encrypted file

        Return
        -------
        True if the file was decrypted successfully. Otherwise, it returns False
    '''
    try:
        # Getting the receiver private key
        private_key = RSA.import_key(receiver_private_key)

        # Getting the necessary information to decrypt the document
        enc_session_key, nonce, tag, ciphertext = \
        [ encrypted_document.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypting the session key using the receiver private key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypting the document using the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_document = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Verifying the signature
        is_valid_signature = verify_signature(decrypted_document, sender_public_key, original_signature)

        if is_valid_signature:
            # Writing the decrypted document in a new PDF file
            with open(f"{TMP_FOLDER}{filename}.pdf", "wb") as decrypted_document_file:
                decrypted_document_file.write(decrypted_document)
            return True
        else:
            return False
    except:
        return False


def generate_rsa_keys() -> RSA.RsaKey:
    '''
        Generate a RSA key of 2048 bits

        Return
        --------
        rsa_key: RsaKey
            The generated key
    '''
    return RSA.generate(2048)


def delete_tmp_file(filename):
    '''
        Delete a tmp file if it exists

        Parameters
        -----------
        filename : str
            It is the file that will be deleted
    '''
    time.sleep(30)
    if os.path.exists(f"{TMP_FOLDER}{filename}"):
        os.remove(f"{TMP_FOLDER}{filename}")

def validatePassword(password, idEmisor):
    pass 