         ###########################################################
        #         Protecting sensitive information                #
       #             Cryptography final project                  #
      #                   Semester 2022-1                       #
     #                                                         #
    #                                                         #
   #            Ramírez Fuentes Edgar Alejandro              #
  #             Salmerón Contreras María José               #
 #             Rodríguez Melgoza Ivette                    #
###########################################################
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

TMP_FOLDER = './assets/tmp/'
SIGNATURES_FOLDER = "./assets/signatures/"
PUBLIC_KEY_FOLDER = "./assets/public_keys/" 
PRIVATE_KEY_FOLDER = "./assets/private_keys/"

def verifySignature(decryptedDocument : bytes, senderPublicKey : bytes, signature : bytes) -> bool:
    '''
        Veryfy if the original signature is the same than the obtained signature from the decrypted document

        Parameters
        -----------
        decryptedDocument : bytes
            It is the decrypted document that will be used to generate a signature

        senderPublicKey : bytes
            It is the sender public key that will be used to verify if the obtained signature is the same than the original signature

        signature : bytes
            It is the original signature
        
        Return
        ---------
            True if the signatures match, otherwise False
    '''
    try:
        # Getting the sender public key
        key = RSA.import_key(senderPublicKey)

        # Hashing the decrypted document
        h = SHA256.new(decryptedDocument)

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


def decryptDocument(encryptedDocument : bytes, receiverPrivateKey : bytes, senderPublicKey : bytes, originalSignature : bytes, filename : str) -> bool:
    '''
        Decrypt a document using a hybrid encryption scheme. 
        It uses RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key.

        Parameters
        -----------

        encryptedDocument : bytes
            It is a reference (pointer) to the document that contains the encrypted document
        
        receiverPrivateKey : bytes
            It is the receiver private key that will be used to decrypt the AES session key

        senderPublicKey : bytes
            It is the sender public key that will be used to verify the signature

        originalSignature : bytes
            It is the original signature of the file that will be decrypted

        filename : str
            It is the filename of the encrypted file

        Return
        -------
        True if the file was decrypted successfully. Otherwise, it returns False
    '''
    try:
        # Getting the receiver private key
        privateKey = RSA.import_key(receiverPrivateKey)

        # Getting the necessary information to decrypt the document
        encSessionKey, nonce, tag, ciphertext = \
        [ encryptedDocument.read(x) for x in (privateKey.size_in_bytes(), 16, 16, -1) ]

        # Decrypting the session key using the receiver private key
        cipherRSA = PKCS1_OAEP.new(privateKey)
        sessionKey = cipherRSA.decrypt(encSessionKey)

        # Decrypting the document using the AES session key
        cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
        decryptedDocument = cipherAES.decrypt_and_verify(ciphertext, tag)

        # Verifying the signature
        is_valid_signature = verifySignature(decryptedDocument, senderPublicKey, originalSignature)

        if is_valid_signature:
            # Writing the decrypted document in a new PDF file
            with open(f"{TMP_FOLDER}{filename}.pdf", "wb") as decryptedDocument_file:
                decryptedDocument_file.write(decryptedDocument)
            return True
        else:
            return False
    except:
        return False


def deleteFile(filePath):
    '''
        Delete a file if it exists

        Parameters
        -----------
        filePath : str
            It is the path of the file that will be deleted
    '''
    if os.path.exists(filePath):
        time.sleep(30)
        os.remove(filePath)


def signDocument(document : bytes, senderPrivateKey : bytes, documentPath : str) -> bool:
    '''
        Generate a sign for the provided document

        Parameters
        -----------
        document : bytes
            It is the document that will be signed

        senderPrivateKey : bytes
            It is the private key that will be used to sign the document

        documentPath : str
            It is the path where the document is stored

        Return
        --------
        True if the sign was generated successfully, otherwise False
    '''
    try:
        # Getting the sender private key
        key = RSA.import_key(senderPrivateKey)
        # Hashing the document
        h = SHA256.new(document)
        # Signing the hashed document
        signature = pss.new(key).sign(h)

        # Storing the signature
        with open(documentPath, "wb") as signFile:
            signFile.write(signature)
        return True
    except:
        return False


def encryptDocument(document : bytes, receiverPublicKey : bytes, encryptedDocumentFilename : str) -> bool:
    '''
        Encrypt a document using a hybrid encryption scheme. 
        It uses RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key.

        Parameters
        ----------
        document : bytes
            It is the document that will be encrypted

        receiverPublicKey : bytes
            It is the public key that will be used to encrypt the document

        Return
        -------
        True if the document was encrypted successfully, otherwise False
    '''
    try:
        # Getting the receiver public key
        key = RSA.importKey(receiverPublicKey)

        # Generating the AES session key 
        sessionKey = get_random_bytes(16)

        # Encrypting the session key using the receiver public key
        cipherRSA = PKCS1_OAEP.new(key)
        encSessionKey = cipherRSA.encrypt(sessionKey)

        # Encrypting the document using the AES session key
        cipherAES = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipherAES.encrypt_and_digest(document)

        # Storing the encrypted data
        with open(f"{TMP_FOLDER}{encryptedDocumentFilename}", "wb") as encrypted_file:
            [ encrypted_file.write(x) for x in (encSessionKey, cipherAES.nonce, tag, ciphertext) ]
        return True  
    except:
        return False  


def sendDocument(receiverEmail : str, documentPath : str, filename : str) -> bool: 
    '''
        Send an email that contains the encrypted document

        Parameters
        -----------
        receiverEmail : str
            It is the email that will receive the encryped document

        documentPath : str
            It is the path where the encrypted file is stored

        filename : str
            It is the encrypted file filename

        Return
        -----------
        True if the email was sent successfully, otherwise False
    '''
    try:
        # Project email credentials
        secretkey = "Usuario123_"
        senderEmail = "graphycrypto8@gmail.com"
        message = MIMEMultipart()
        # Email info
        message["From"] = senderEmail
        message['To'] = receiverEmail
        message['Subject'] = f"Archivo cifrado - {filename}"
        attachment = open(documentPath,'rb')
        obj = MIMEBase('application','octet-stream')
        obj.set_payload((attachment).read())
        encoders.encode_base64(obj)
        obj.add_header('Content-Disposition',f"attachment; filename={filename}")
        message.attach(obj)
        myMessage = message.as_string()
        emailSession = smtplib.SMTP('smtp.gmail.com',587)
        emailSession.starttls()
        emailSession.login(senderEmail, secretkey)
        emailSession.sendmail(senderEmail,receiverEmail,myMessage)
        emailSession.quit()
        return True
    except: 
        return False