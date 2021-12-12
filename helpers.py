from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os, shutil, time
from Crypto.Random import get_random_bytes
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

ALLOWED_EXTENSIONS = {'bin', 'pdf'}
TMP_FOLDER = './assets/tmp/'
SIGNATURES_FOLDER = "./assets/signatures/"
PUBLIC_KEY_FOLDER = "./assets/public_keys/" 
PRIVATE_KEY_FOLDER = "./assets/private_keys/"

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
        print("Llegue aquí")
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
        print("Entre al except")
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

def sign_document(document : bytes, sender_private_key : bytes,idReceptor,idEmisor,nombreArchivo,idCifrado) -> None:
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
    with open(f"{SIGNATURES_FOLDER}{idEmisor}_{idReceptor}_{nombreArchivo}_{idCifrado}.bin", "wb") as sign_file:
        sign_file.write(signature)

def encrypt_document(document : bytes, receiver_public_key : bytes, idEmisor,idReceptor,numeroDocumento,nombreArchivo):
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
    with open(f"{TMP_FOLDER}{idEmisor}_{idReceptor}_{nombreArchivo}_{numeroDocumento}.bin", "wb") as encrypted_file:
        [ encrypted_file.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]    

def sendDocument(email,path,fileName):
    try:

        secret_key = "Usuario123_"
        sender_email = "graphycrypto8@gmail.com"
        receiver_email = email
        message = MIMEMultipart()
        message["From"] = sender_email
        message['To'] = receiver_email
        message['Subject'] = "Archivo cifrado - " +fileName
        attachment = open(path,'rb')
        obj = MIMEBase('application','octet-stream')
        obj.set_payload((attachment).read())
        encoders.encode_base64(obj)
        obj.add_header('Content-Disposition',"attachment; filename= "+fileName)
        message.attach(obj)
        my_message = message.as_string()
        email_session = smtplib.SMTP('smtp.gmail.com',587)
        email_session.starttls()
        email_session.login(sender_email, secret_key)
        email_session.sendmail(sender_email,receiver_email,my_message)
        email_session.quit()
        print("YOUR MAIL HAS BEEN SENT SUCCESSFULLY")
        return True
    except: 
        print("EMAIL MESSAGE")
        return False