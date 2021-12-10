from flask import Flask, flash, redirect, render_template, request, session, send_from_directory, url_for
from flask_session import Session
from werkzeug.utils import secure_filename
from helpers import delete_tmp_file, allowed_file, decrypt_document, delete_tmp_file, TMP_FOLDER, validatePassword, SIGNATURES_FOLDER, PUBLIC_KEY_FOLDER, PRIVATE_KEY_FOLDER, encrypt_document,sendDocument
from threading import Thread
import os, re

 
app = Flask(__name__)
app.config['TMP_FOLDER'] = TMP_FOLDER
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = "123" 


@app.route("/")
def index():
    return render_template("./index.html")

@app.route("/decrypt-file", methods=["GET", "POST"])
def decrypt_file():
    if request.method == "GET":
        return render_template("./decrypt_file.html")
    elif request.method == "POST":
        # Get the sender ID
        sender_id = request.form.get('sender_id')

        # Check if the sender_id was sent
        if not sender_id:
            #warning
            flash(f'No selected sender', 'danger')
            return redirect(request.url)

        # Check if the post request has the file part
        if 'file' not in request.files:
            flash(f'No file part', 'danger')
            return redirect(request.url)
        #obteniendo el archivo
        file = request.files['file']

        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash(f'No selected file', 'danger')
            return redirect(request.url)

        # is_allowed_file = allowed_file(file.filename)
        
        if file:
            try:
                #Limpieza
                filename = secure_filename(file.filename)

                # Check if the filename fulfills the standard
                # Filename standard: senderID_receiverID_encryptedFilename_encryptionID.bin
                filename_regex = r"^[0-9]+_[0-9]+_\w+_[0-9].bin$"

                if not re.match(filename_regex, filename):
                    flash('The filename was modified or it is not a bin file', 'danger')
                    return redirect(request.url)

                filename_without_extension = filename.split('.')[0]

                # Getting the sender public key
                with open(f"./assets/public_keys/{sender_id}.pem") as sender_public_key_file:
                    sender_public_key = sender_public_key_file.read()
                
                # Getting the logged in user id
                # receiver_id = session.get('id')

                # Getting the user private key
                # Using a temporary  private key while the login module is finished
                with open("./assets/private_keys/2.pem", "rb") as receiver_private_key_file:
                    receiver_private_key = receiver_private_key_file.read()

                # Getting the signature
                # Using a temporary signature while the database is connected
                with open("./assets/signatures/1_2_Protecting_sensitive_information_1.bin", "rb") as signature_file:
                    signature = signature_file.read()

                # It is the path where the uploaded file will be stored
                path = os.path.join(app.config['TMP_FOLDER'], filename)

                # Store the file in the provided path
                file.save(path)

                # Getting the reference to the file to decrypt
                encrypted_document = open(path, "rb")
                # Check if the file was decrypted successfully
                decrypted = decrypt_document(encrypted_document, receiver_private_key, sender_public_key, signature, filename_without_extension) 
                encrypted_document.close()

                # Open a thread to delete the uploaded file
                uploaded_file_thread = Thread(target=delete_tmp_file, args=(filename,))
                uploaded_file_thread.daemon = True
                uploaded_file_thread.start()

                if decrypted:
                    # Open a thread to delete the decrypted file
                    pdf_thread = Thread(target=delete_tmp_file, args=(f"{filename_without_extension}.pdf",))
                    pdf_thread.daemon = True
                    pdf_thread.start()

                    return redirect(url_for('download_file',
                                        name=f"{filename_without_extension}.pdf"))
                else:
                    # Return an error message
                    flash(f'The signature is not authentic. Try later', 'danger')
                    return redirect(request.url)  
            except:
                flash('Something went wrong', 'danger')
                return redirect(request.url)
        else:
            flash(f'No file sent', 'danger')
            return redirect(request.url)



#Cipher section --------------------------------------------------------------------------------------------------------------------
@app.route("/encrypt-file", methods=["POST",])
def encrypt_file():
    # Check if the sender_id was sent
    # 1.- id(s) receptor
    # 2.- id emisor
    # 3.- Archivo
    # 4.- Contraseña emisor
    # Validar que todos los datos tienen entradas, si no, enviar msj de error

    # Obteniendo 1
    receiverId = request.form.get("receiverId")
    print(receiverId, " receiverId")
    if not receiverId:
        #warning
        flash(f'No selected receiver', 'danger')
        return redirect(request.url)
    #Obtener del inicio de sesion *PENDIENTE
    senderId = "1"

    #Obteniendo 3
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash(f'No file part', 'danger')
        return redirect(request.url)
    #obteniendo el archivo
    file = request.files['file']

    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash(f'No selected file', 'danger')
        return redirect(request.url)

    # is_allowed_file = allowed_file(file.filename)
    # Obteniendo 4
    password = request.form.get("pswd")
    print(password," password")
    if not password:
        #warning
        flash(f'No password', 'danger')
        return redirect(request.url)

    #falta validatePassword
    if file:
        try:
            #Limpieza
            filename = secure_filename(file.filename)
            print(filename, " filename")
            # Check if the filename fulfills the standard
            # Filename standard: senderID_receiverID_encryptedFilename_encryptionID.bin
            filename_regex = r"^\w+.pdf$"

            if not re.match(filename_regex, filename):
                flash('The file is not a pdf', 'danger')
                return redirect(request.url)

            filename_without_extension = filename.split('.')[0]
            #Obtener llave privada del emisor
            #Comprobacion (todos = 0, uno en especifico = id)
            #Para todos
             # It is the path where the uploaded file will be stored
            path = os.path.join(app.config['TMP_FOLDER'], filename)

            # Store the file in the provided path
            file.save(path)


            if receiverId == "0":
                pass
                #Traer de la BD
                #Id, correo(Receptores), numArchivo(Emisor)
                #Por cada receptor obtener su llave pública
                #Se firma el documento()
                #cifrar documento
            else:
                correo = "marymorrera12@gmail.com"
                numeroCifrados = "3"
                idEmisor = "2"
                with open(f"{PUBLIC_KEY_FOLDER}{receiverId}.pem", "rb") as publicKeyFile:
                    publicKey = publicKeyFile.read()
                
                with open(f"{PRIVATE_KEY_FOLDER}{idEmisor}.pem", "rb") as privateKeyFile:
                    privateKey = privateKeyFile.read()

                with open(path, "rb") as plainText:
                    plainText = plainText.read()

                encrypt_document(plainText,publicKey,idEmisor,receiverId,int(numeroCifrados)+1,filename_without_extension)
                sendDocument(correo,f"{TMP_FOLDER}{idEmisor}_{receiverId}_{filename_without_extension}_{int(numeroCifrados)+1}.bin",filename_without_extension)
                flash('Encrypted file', 'success')
                return redirect("/")
        except:
            pass
@app.route('/uploads/<name>')
def download_file(name):
    # Send the request to download a file
    return send_from_directory(app.config["TMP_FOLDER"], name, as_attachment=True)


#*Cipher section -------------------------------------------------------------------------------------------------------------------