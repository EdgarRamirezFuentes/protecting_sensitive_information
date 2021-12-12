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

from flask import Flask, flash, redirect, render_template, request, session, send_from_directory, url_for
from flask_session import Session
from werkzeug.utils import secure_filename
from helpers import deleteFile, decryptDocument, encryptDocument,sendDocument, signDocument
from helpers import TMP_FOLDER, SIGNATURES_FOLDER, PUBLIC_KEY_FOLDER, PRIVATE_KEY_FOLDER,dataBaseConnection,lectureOfNumArchivos,lectureOfUsuario,closeDB
from threading import Thread
import os, re

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = "123" 

  #############################
 #     Index page route      #
#############################
@app.route("/")
def index():
    return render_template("./index.html")


  #############################
 #     Login page route      #
#############################
@app.route("/login", methods=["GET","POST"])
def login():
    return render_template("login.html")

  #############################
 #     Decrypt file route    #
#############################
@app.route("/decrypt-file", methods=["POST",])
def decrypt_file():
    # Get the sender ID
    senderId = request.form.get('senderId')

    # Check if the senderId was sent
    if not senderId:
        flash(f'No selected sender', 'danger')
        return redirect(url_for('index'))
    
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash(f'No file part', 'danger')
        return redirect(url_for('index'))

    # Getting the file from the form
    file = request.files['file']

    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash(f'No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        try:
            filename = secure_filename(file.filename)

            # Check if the filename fulfills the standard
            # Filename standard: senderID_receiverID_encryptedFilename_encryptionID.bin
            filenameRegex = r"^[0-9]+_[0-9]+_[\w\-]+_[0-9]\.bin$"

            if not re.match(filenameRegex, filename):
                flash('The filename was modified or it is not a bin file', 'danger')
                return redirect(url_for('index'))

            filenameWithoutExtension = filename.split('.')[0]
            
            documentPath = os.path.join(TMP_FOLDER, filename)

            # Store the file in the provided path
            file.save(documentPath)

            # Getting the sender public key
            with open(f"{PUBLIC_KEY_FOLDER}{senderId}.pem", "rb") as senderPublicKeyFile:
                senderPublicKey = senderPublicKeyFile.read()
            
            # Getting the logged in user id
            # receiver_id = session.get('id')

            # Getting the user private key
            # Using a temporary  private key while the login module is finished
            with open(f"{PRIVATE_KEY_FOLDER}3.pem", "rb") as receiverPrivateKeyFile:
                receiverPrivateKey = receiverPrivateKeyFile.read()

            # Getting the signature
            # Using a temporary signature while the database is connected
            with open(f"{SIGNATURES_FOLDER}{filename}", "rb") as signatureFile:
                signature = signatureFile.read()

            # Getting the reference to the file to decrypt
            encryptedDocument = open(documentPath, "rb")
            # Check if the file was decrypted successfully
            decrypted = decryptDocument(encryptedDocument, receiverPrivateKey, senderPublicKey, signature, filenameWithoutExtension) 
            encryptedDocument.close()

            # Open a thread to delete the uploaded file
            uploadedFileThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
            uploadedFileThread.daemon = True
            uploadedFileThread.start()

            if decrypted:
                # Open a thread to delete the decrypted file
                pdfThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filenameWithoutExtension}.pdf",))
                pdfThread.daemon = True
                pdfThread.start()

                return redirect(url_for('download_file', name=f"{filenameWithoutExtension}.pdf"))
            else:
                # Return an error message
                flash(f'The signature is not authentic. Try later', 'danger')
                return redirect(url_for('index'))  
        except:
            flash('Something went wrong', 'danger')
            return redirect(url_for('index'))
    else:
        flash(f'No file sent', 'danger')
        return redirect(url_for('index'))


  #############################
 #     Encrypt file route    #
#############################
@app.route("/encrypt-file", methods=["POST",])
def encrypt_file():
    '''
        Data needed to encrypt a PDF document:
        - Sender private key
        - Receiver public key
        - Receiver ID
        - Sender ID
        - Receiver email
        - PDF document
    '''
# DB Connection
    conexion = dataBaseConnection()


#OBTENIENDO DATOS DE PRUEBA
    numeroDeArchivos = lectureOfNumArchivos(conexion)
    print("Numero de archivos en BD : ",numeroDeArchivos)

    nombreUsuario = lectureOfUsuario(conexion,"nombreUsuario",1)
    print("Nombre de usuario en BD : ",nombreUsuario)

    contrasena = lectureOfUsuario(conexion,"contrasena",1)
    print("Contraseña en BD : ", contrasena)

#** OBTENIENDO DATOS DE PRUEBA
    closeDB(conexion)
    # Getting the receiver ID
    # all = 0, specific user != 0
    receiverId = request.form.get("receiverId")

    if not receiverId:
        flash(f'No receiver selected', 'danger')
        return redirect(url_for('index'))
    
    if int(receiverId) < 0:
        flash(f'Invalid receiver ID', 'danger')
        return redirect(url_for('index'))

    # Getting the sender ID
    # Using a temporary senderId while the login module is not ready
    senderId = "2"

    # Check if the post request has the file part
    if 'file' not in request.files:
        flash(f'No file part', 'danger')
        return redirect(url_for('index'))

    # Getting the file from the form
    file = request.files['file']

    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash(f'No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        try:
            filename = secure_filename(file.filename)
            # Check if the filename fulfills the standard
            # Filename standard: senderID_receiverID_encryptedFilename_encryptionID.bin
            filenameRegex = r"^[\w\-]+\.pdf$"

            if not re.match(filenameRegex, filename):
                flash('The file is not a PDF file or the filename is not valid', 'danger')
                return redirect(url_for('index'))

            filenameWithoutExtension = filename.split('.')[0]

            # It is the path where the uploaded file will be stored
            path = os.path.join(TMP_FOLDER, filename)

            # Store the file in the provided path
            file.save(path)

            # Getting the emisor private key
            with open(f"{PRIVATE_KEY_FOLDER}{senderId}.pem", "rb") as privateKeyFile:
                    emisorPrivateKey = privateKeyFile.read()
            
            if receiverId == "0":
                '''
                    Required data from the DB:
                    - Receivers ID
                    - Receivers email
                    - Emisor encrypted documents quantity
                '''
                # For each receiver sign and encrypt the PDF file
                pass
            else:
                '''
                    Required data from the DB:
                    - Receiver email
                    - Emisor encrypted documents quantity
                '''
                receiverEmail = "edgar.alejandro.fuentes98@gmail.com"
                numeroCifrados = "3"
                with open(f"{PUBLIC_KEY_FOLDER}{receiverId}.pem", "rb") as publicKeyFile:
                    receiverPublicKey = publicKeyFile.read()
                
                with open(path, "rb") as PDF:
                    plaintext = PDF.read()
                
                # Building the encrypted filename format
                encryptedFilename = f"{senderId}_{receiverId}_{filenameWithoutExtension}_{int(numeroCifrados) + 1}.bin"

                signed = signDocument(plaintext, emisorPrivateKey, f"{SIGNATURES_FOLDER}{encryptedFilename}")
                
                encrypted = encryptDocument(plaintext, receiverPublicKey,encryptedFilename)
                
                # Check if the PDF was encrypted successfully
                if signed and encrypted:
                    sent = sendDocument(receiverEmail ,f"{TMP_FOLDER}{encryptedFilename}", encryptedFilename)
                    # Check if the email was sent successfully
                    if sent:
                        flash('Document encrypted successfully.', 'success')
                        # Open a thread to delete the uploaded file
                        uploadedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
                        uploadedThread.daemon = True
                        uploadedThread.start()

                        # Open a thread to delete the encrypted document
                        encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
                        encryptedThread.daemon = True
                        encryptedThread.start()
                        return redirect(url_for('index'))
                    else:
                        # Open a thread to delete the signature
                        signatureThread = Thread(target=deleteFile, args=(f"{SIGNATURES_FOLDER}{encryptedFilename}",))
                        signatureThread.daemon = True
                        signatureThread.start()

                        # Open a thread to delete the uploaded file
                        uploadedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
                        uploadedThread.daemon = True
                        uploadedThread.start()

                        # Open a thread to delete the encrypted document
                        encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
                        encryptedThread.daemon = True
                        encryptedThread.start()
                        
                        flash("There was an error trying to send the encrypted file. Try later.", "danger")
                        return redirect(url_for('index'))
                else:
                    # Open a thread to delete the signature
                    signatureThread = Thread(target=deleteFile, args=(f"{SIGNATURES_FOLDER}{encryptedFilename}",))
                    signatureThread.daemon = True
                    signatureThread.start()

                    # Open a thread to delete the encrypted document
                    encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
                    encryptedThread.daemon = True
                    encryptedThread.start()

                    flash("There was an error trying to encrypt the file. Try later.", "danger")
                    return redirect(url_for('index'))
        except:
            # Open a thread to delete the signature
            signatureThread = Thread(target=deleteFile, args=(f"{SIGNATURES_FOLDER}{encryptedFilename}",))
            signatureThread.daemon = True
            signatureThread.start()

            # Open a thread to delete the uploaded file
            uploadedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
            uploadedThread.daemon = True
            uploadedThread.start()

            # Open a thread to delete the encrypted document
            encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
            encryptedThread.daemon = True
            encryptedThread.start()
            
            flash("There was an error trying to encrypt the file. Try later.", "danger")
            return redirect(url_for('index'))


  #############################
 #     Download file route   #
#############################
@app.route('/uploads/<name>')
def download_file(name):
    # Send the request to download a file
    flash("Decrypted file successfully", "success")
    return send_from_directory(TMP_FOLDER, name, as_attachment=True)
