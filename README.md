<p align="center">
  <a href="" rel="noopener">
 <img width=200px height=200px src="https://i.imgur.com/xR2zjiu.jpeg" alt="Project logo"></a>
</p>

<h3 align="center">Protecting sentitive information</h3>

---
<br>

## 📝 Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Deployment](#deployment)
- [Usage](#usage)
- [Built Using](#built_using)
- [Documentation](.\README_FILES\documentation\Protecting_sentitive_information.pdf)
- [User manual](.\README_FILES\documentation\UserManual.pdf)
- [Authors](#authors)

## 🧐 About <a name = "about"></a>
Our cryptography class project is based on the following requirements:  
The CEO of certain company is promoting less use of paper. He wishes that sensitive
documents be digital. Thus, this documents usually are signed by the board of directors
(group of people that take decisions in the company). Also only the board of directors 
can see the content of these sensitive documents. They do not want to share a unique key,
i.e. every member of the board must have their own key or keys. Imagine that your team is hired to develop a solution for this company.

## 🏁 Getting Started <a name = "getting_started"></a>
### Installing
The requirements to run the web app are listed in the file called <i>requirements.txt</i>, and to install them you need to run the following command in your terminal placed in the project folder.
```
pip install -r requirements.txt
```
After running the previous command all the packages needed to run the project will be installed.

## 🎈 Usage <a name="usage"></a>

### Login
- When you visit the web app the login UI will be shown.  
![Login UI](.\README_FILES\img\loginUI.JPG)
- Enter your credentials and click the button <i>LOG IN</i> to enter.  
![Credentials](.\README_FILES\img\credentials.JPG)
- If your credentials are correct, a welcome message will be shown and you will access to the system.  
![Welcome message](.\README_FILES\img\welcome.JPG)

### Main page
- In the main page you will find the allowed actions and the user manual.
![Main page](.\README_FILES\img\mainPage.JPG)

### Encipher section
- If you clicked in the <i>Cipher document section</i>, you will be sent to the encipher  section where you will be able to send enciphered <i>PDF Files</i>.   
<b>It is important to mention that this app only allows you to encipher PDF files.</b>
![Cipher section](.\README_FILES\img\cipherSection.JPG)
- You need to select the PDF document to be enciphered clicking in the next button.  
![Select document field](.\README_FILES\img\selectDocumentEncipher.JPG)
- Select the document that will be enciphered
![File selection](.\README_FILES\img\fileSelectionEncipher.JPG)
- The <i>Cipher document section</i> will be updated with the selected file
![Selected file](.\README_FILES\img\selectedDocumentEncipher.JPG)
- Select the person that will receive the enciphered document. In this case will be sent to EdgarARF.    
<b>Note: It could be sent to all the registered people in the app using the option <i>All</i></b>
![Encipher section completed](.\README_FILES\img\encipherSectionComplete.JPG)
- If the document was enciphered successfully, EdgarARF will receive and email that contains the enciphered document and its digital signature.  
![Document enciphered successfully](.\README_FILES\img\encryptSuccess.JPG)
![Enciphered document email](.\README_FILES\img\encipherEmail.JPG)
![Enciphered document digital signature](.\README_FILES\img\digitalSignature.JPG)

### Decipher section
- First, It is needed to download the enciphered file that you received in your email.
![Download Enciphered document](.\README_FILES\img\downloadBinaryDecipher.JPG)
- Once you downloaded the enciphered file, go to the <i>Decipher section</i> in the app
![Decipher section](.\README_FILES\img\decipherSection.JPG)
- Select the enciphered file that will be deciphered and who sent it.  
<b>Note: The sender must be the correct and the enciphered file must not be renamed or modified in order to be deciphered successfully</b>
![Decipher section completed](.\README_FILES\img\decipherSectionComplete.JPG)
- If everything is ok, the document will be deciphered and downloaded.
![Decipher success](.\README_FILES\img\decipherSuccess.JPG)
- If you open the donwloaded file, you will be able to check the content.
![Decipher success](.\README_FILES\img\decipheredDocument.JPG)

## 🚀 Deployment <a name = "deployment"></a>
The project was deployed in Heroku using PostgreSQL as DBMS.  
[Click here](https://crypto-project-escom.herokuapp.com/login) to visit the project online

## ⛏️ Built Using <a name = "built_using"></a>
### Back-end
- [Python3 (Flask)](https://flask.palletsprojects.com/)
### DBMS
- [PostgreSQL (Deployment)](https://www.postgresql.org/)
- [MySQL (Development)](https://www.mysql.com/)
### Front-end
- [HTML](https://developer.mozilla.org/en-US/docs/Learn/Getting_started_with_the_web/HTML_basics)
- [CSS3 (Bootstrap)](https://getbootstrap.com/)
- [JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

## ✍️ Authors <a name = "authors"></a>

- Ram&iacute;rez Fuentes Edgar Alejandro - [@EdgarRamirezFuentes](https://github.com/EdgarRamirezFuentes)
- Salmer&oacute;n Contreras Mar&iacute;a Jos&eacute; - [@MarySalmeron](https://github.com/MarySalmeron)
- Rodr&iacute;guez Melgoza Ivette - [@Ivette1111](https://github.com/Ivette1111)
