from flask import Flask, flash, redirect, render_template, request, session, send_from_directory, url_for
from flask_session import Session
from werkzeug.utils import secure_filename
from helpers import delete_tmp_file, allowed_file, decrypt_document, delete_tmp_file, TMP_FOLDER
from threading import Thread
import os

 
app = Flask(__name__)
app.config['TMP_FOLDER'] = TMP_FOLDER
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY") 


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
            flash(f'No selected sender', 'danger')
            return redirect(request.url)

        # Check if the post request has the file part
        if 'file' not in request.files:
            flash(f'No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']

        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash(f'No selected file', 'danger')
            return redirect(request.url)

        is_allowed_file = allowed_file(file.filename)
        
        if file and is_allowed_file:
            filename = secure_filename(file.filename)
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

            if decrypted:
                # Open a thread to delete the decrypted file
                pdf_thread = Thread(target=delete_tmp_file, args=(f"{filename_without_extension}.pdf",))
                pdf_thread.daemon = True
                pdf_thread.start()

                # Open a threah to delete the uploaded file
                uploaded_file_thread = Thread(target=delete_tmp_file, args=(filename,))
                uploaded_file_thread.daemon = True
                uploaded_file_thread.start()

                return redirect(url_for('download_file',
                                    name=f"{filename_without_extension}.pdf"))
            else:
                # Return an error message
                flash(f'The signature is not authentic', 'danger')
                return redirect(request.url)  
        else:
            flash(f'No allowed file', 'danger')
            return redirect(request.url)

@app.route('/uploads/<name>')
def download_file(name):
    # Send the request to download a file
    return send_from_directory(app.config["TMP_FOLDER"], name, as_attachment=True)
