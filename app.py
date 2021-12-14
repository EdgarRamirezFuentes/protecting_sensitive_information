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
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from Crypto.Hash import SHA3_256
from helpers import deleteFile, decryptDocument, encryptDocument, getCredentials, getEncryptedDocumentsQuantity, getReceiverData, getUserList, login_required, logout_required,sendDocument, signDocument, error_message, updateEncryptedDocumentsQuantity, dataBaseConnection
from helpers import TMP_FOLDER, SIGNATURES_FOLDER, PUBLIC_KEY_FOLDER, PRIVATE_KEY_FOLDER
from threading import Thread
import os, re

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = os.environ.get('APP_KEY')

  #############################
 #     Index page route      #
#############################

@app.route("/")
@login_required
def index():
    connection = dataBaseConnection()

    if not connection:
        flash('There is a problem. Try later')
        return redirect(url_for('index'))

    # Get the list of users in the DB except the one that is logged in
    userList = getUserList(connection, session.get("idUser"))
    connection.close()
    return render_template("./index.html", userList = userList, idUser = session.get("idUser"))



  #############################
 #     Login page route      #
#############################

@app.route("/login", methods=["GET","POST"])
@logout_required
def login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        username = request.form.get('user')
        password = request.form.get("psw")

        if not username:
            flash("Username is required", "danger")
            return redirect(url_for('index'))

        if not password:
            flash('Password required', 'danger')
            return redirect(url_for('index'))

        # Hashing password    
        password = bytes(password, 'utf-8')
        password = SHA3_256.new(password).hexdigest()

        connection = dataBaseConnection()
        if not connection:
            flash('There is a problem. Try later')
            return redirect(url_for('index'))
        

        userData = getCredentials(connection, username)
        
        if not userData:
            flash('The username is not registered', 'danger')
            connection.close()
            return redirect(url_for('index'))
        
        # Getting the user id and password
        idUser = userData[0]
        passwordUser = userData[1]

        if passwordUser == password:
            session["idUser"] = idUser
            flash(f'Welcome {username}!', 'info')
        else:
            flash('Wrong password', 'danger')

        connection.close()
        return redirect(url_for('index'))


  #############################
 #     Log out page route    #
#############################

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


  #############################
 #     Decrypt file route    #
#############################

@app.route("/decrypt-file", methods=["POST",])
@login_required
def decrypt_file():
    # Get the sender ID
    senderId = request.form.get('senderId')
    receiverId = session.get('idUser')
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

            # Getting the user private key
            # Using a temporary  private key while the login module is finished
            with open(f"{PRIVATE_KEY_FOLDER}{receiverId}.pem", "rb") as receiverPrivateKeyFile:
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

@login_required
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
    # Getting the id of the user that is logged in
    senderId = session.get('idUser')

    # Getting the receiver ID
    receiverId = request.form.get("receiverId")

    if not receiverId:
        flash(f'No receiver selected', 'danger')
        return redirect(url_for('index'))
    
    if int(receiverId) < 0:
        flash(f'Invalid receiver ID', 'danger')
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
            
            connection = dataBaseConnection()

            if not connection:
                flash('There is a problem. Try later')
                return redirect(url_for('index'))

            # Getting the quantity of encrypted documents
            encryptedDocuments = getEncryptedDocumentsQuantity(connection, senderId)[0]

            if receiverId == "0":
                '''
                    Required data from the DB:
                    - Receivers ID
                    - Receivers email
                    - Emisor encrypted documents quantity
                '''
                # For each receiver sign and encrypt the PDF file
                receiverData = getReceiverData(connection, receiverId, senderId)
                if not receiverData:
                    flash('Not valid receiver')
                    connection.close()
                    return redirect(url_for('index'))

                for receiver in receiverData:
                    receiverId = receiver[0]
                    receiverEmail = receiver[1]
                    encryptedDocuments += 1
                    with open(f"{PUBLIC_KEY_FOLDER}{receiverId}.pem", "rb") as publicKeyFile:
                        receiverPublicKey = publicKeyFile.read()
                    
                    with open(path, "rb") as PDF:
                        plaintext = PDF.read()
                    
                    # Building the encrypted filename format
                    encryptedFilename = f"{senderId}_{receiverId}_{filenameWithoutExtension}_{encryptedDocuments}.bin"

                    signed = signDocument(plaintext, emisorPrivateKey, f"{SIGNATURES_FOLDER}{encryptedFilename}")
                    
                    encrypted = encryptDocument(plaintext, receiverPublicKey,encryptedFilename)
                    
                    # Check if the PDF was encrypted successfully
                    if signed and encrypted:
                        sent = sendDocument(receiverEmail ,f"{TMP_FOLDER}{encryptedFilename}", encryptedFilename)
                        # Check if the email was sent successfully
                        if sent:
                            # Update the quantity of encrypted documents
                            updateEncryptedDocumentsQuantity(connection, senderId, encryptedDocuments)

                            # Open a thread to delete the uploaded file
                            uploadedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
                            uploadedThread.daemon = True
                            uploadedThread.start()

                            # Open a thread to delete the encrypted document
                            encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
                            encryptedThread.daemon = True
                            encryptedThread.start()

                            flash('Document encrypted successfully.', 'success')
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
                    else:
                        # Closing the connection to the DB
                        connection.close()

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
                return redirect(url_for("index"))
            else:
                '''
                    Required data from the DB:
                    - Receiver email
                    - Emisor encrypted documents quantity
                '''
                receiverData = getReceiverData(connection, receiverId, senderId)

                if not receiverData:
                    flash('Not valid receiver')
                    connection.close()
                    return redirect(url_for('index'))

                receiverEmail = receiverData[0]

                with open(f"{PUBLIC_KEY_FOLDER}{receiverId}.pem", "rb") as publicKeyFile:
                    receiverPublicKey = publicKeyFile.read()
                
                with open(path, "rb") as PDF:
                    plaintext = PDF.read()
                
                # Building the encrypted filename format
                encryptedFilename = f"{senderId}_{receiverId}_{filenameWithoutExtension}_{encryptedDocuments + 1}.bin"

                signed = signDocument(plaintext, emisorPrivateKey, f"{SIGNATURES_FOLDER}{encryptedFilename}")
                
                encrypted = encryptDocument(plaintext, receiverPublicKey,encryptedFilename)
                
                # Check if the PDF was encrypted successfully
                if signed and encrypted:
                    sent = sendDocument(receiverEmail ,f"{TMP_FOLDER}{encryptedFilename}", encryptedFilename)
                    # Check if the email was sent successfully
                    if sent:
                        # Update the quantity of encrypted documents
                        updateEncryptedDocumentsQuantity(connection, senderId, encryptedDocuments + 1)

                        # Open a thread to delete the uploaded file
                        uploadedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{filename}",))
                        uploadedThread.daemon = True
                        uploadedThread.start()

                        # Open a thread to delete the encrypted document
                        encryptedThread = Thread(target=deleteFile, args=(f"{TMP_FOLDER}{encryptedFilename}",))
                        encryptedThread.daemon = True
                        encryptedThread.start()

                        flash('Document encrypted successfully.', 'success')
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
                    
                    # Closing the connection to the DB
                    connection.close()
                    return redirect(url_for('index'))
                else:
                    # Closing the connection to the DB
                    connection.close()

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
            # Closing the connection to the DB
            connection.close()

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
@login_required
def download_file(name):
    # Send the request to download a file
    flash("Decrypted file successfully", "success")
    return send_from_directory(TMP_FOLDER, name, as_attachment=True)


  #############################
 #    Error Handlig module   #
#############################

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error_message(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)