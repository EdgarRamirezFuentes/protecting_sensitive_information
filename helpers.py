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

# Cryptography module
from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
# Delete file
import os, time
# Email 
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
# Sessions validation
from flask import redirect, session, render_template
from functools import wraps
# Database
import mysql.connector

  #############################
 #       Folder Paths        #
#############################

TMP_FOLDER = './assets/tmp/'
SIGNATURES_FOLDER = "./assets/signatures/"
PUBLIC_KEY_FOLDER = "./assets/public_keys/" 
PRIVATE_KEY_FOLDER = "./assets/private_keys/"


  #############################
 #     Signature module      #
#############################

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
        # h = SHA256.new(decryptedDocument)
        h = SHA3_256.new(decryptedDocument)

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
        h = SHA3_256.new(document)
        # Signing the hashed document
        signature = pss.new(key).sign(h)

        # Storing the signature
        with open(documentPath, "wb") as signFile:
            signFile.write(signature)
        return True
    except:
        return False


  #############################
 #     Decryption module     #
#############################

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


  #############################
 #     Encryption module     #
#############################

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


  #############################
 #     Cleaning module       #
#############################

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


  #############################
 #       Email module        #
#############################

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


  #############################
 #      Database module      #
#############################

def dataBaseConnection()->mysql.connector:
    '''
        Get the connection to the database

        Return 
        ---------
        connection : mysql.connector
            It is the connection to the database
    '''
    connection = mysql.connector.connect(
            user = "root", 
            password = "REVOLUCIONde1910", 
            host="localhost",
            database="bdcryptography", 
            port="3306"
            )
    return connection


def getUserList(connection : mysql.connector, idUser : str) -> tuple:
    '''
        Get the id and username of the users in the dabase except for the one that is logged in

        Parameters
        ---------------
        connection : mysql.connector
            It is the connection to the database

        idUser : str
            It is the id of the user that is logged in

        Return
        ----------
        userList : tuple
            It is the list of the users in the database
    '''
    cursor = connection.cursor()
    cursor.execute("SELECT idUsuario, nombreUsuario FROM usuario WHERE idUsuario != %s ORDER BY nombreUsuario;", (idUser,))
    userList = cursor.fetchall()
    return userList


def getCredentials(connection : mysql.connector, username : str) -> tuple:
    '''
        Get the credentials of the username to login

        Parameters
        -----------
        connection : mysql.connector
            It is the connection to the database

        username : str
            It is the username that will be looked for their credentials

        Return 
        ---------
        credentials : tuple
            It is a tuple that contains the id and password of the username
    '''
    cursor = connection.cursor()
    cursor.execute("SELECT idUsuario, contrasena FROM usuario WHERE nombreUsuario = %s;", (username,))
    credentials = cursor.fetchone()
    return credentials


def getReceiverData(connection : mysql.connector, idReceiver : str, idUser : str) -> tuple:
    '''
        Get the necessary data to send an encrypted document

        Paramaters
        -------------
        connection : mysql.connector
            It is the connection to the database

        idReceiver : str 
            It is the id of the person that will receive the encrypted document
        
        idUser : str
            It is the id of the person that will send the encrypted document

        Return 
        -----------
        receiverList : tuple
            It is a tuple that contains the information of a specific user 
            or a tuple that contains a tuple that contains the information of all the users in the DB
        
    '''
    cursor = connection.cursor()

    if idReceiver == '0':
        # All the users
        cursor.execute("SELECT idUsuario, email FROM usuario WHERE idUsuario != %s;", (idUser,))
        receiverList = cursor.fetchall()
        return receiverList
    else:
        # Specific user
        cursor.execute("SELECT email FROM usuario WHERE idUsuario = %s;", (idReceiver,))
        receiverList = cursor.fetchone()
        return receiverList


def getEncryptedDocumentsQuantity(connection : mysql.connector, idUser : str) -> tuple:
    '''
        Get the number of documents that a specific user has encrypted

        Parameters
        -----------
        connection : mysql.connector
            It is the connection to the database

        idUser : str
            It is the id of the user that is logged in

        Return
        ---------
        encryptedDocuments : tuple
            It is a tuple that contains the number of encrypted documents
    '''
    cursor = connection.cursor()
    cursor.execute("SELECT numArchivos FROM usuario WHERE idUsuario = %s;", (idUser,))
    encryptedDocuments = cursor.fetchone()
    return encryptedDocuments


def updateEncryptedDocumentsQuantity(connection, idUser, quantity):
    cursor = connection.cursor()
    cursor.execute("UPDATE usuario SET numArchivos = %s WHERE idUsuario = %s;", (quantity, idUser))


  #############################
 #       Login module        #
#############################

def login_required(f):
    """
    Decorate routes to require login.
    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("idUser") is None:
            return redirect('login')
        return f(*args, **kwargs)
    return decorated_function


  #############################
 #      Log out module       #
#############################

def logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("idUser"):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


  #############################
 #    Error Handlig module   #
#############################

def escape(s):
    """
    Escape special characters.
    https://github.com/jacebrowning/memegen#special-characters
    """
    for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                    ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
        s = s.replace(old, new)
        return s


def error_message(message, code=400, username=""):
    return render_template("error_message.html", top=code, bottom=escape(message), username=username), code