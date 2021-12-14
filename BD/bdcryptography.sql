CREATE DATABASE bdcryptography
USE bdcryptography

CREATE TABLE usuario(
    idUsuario VARCHAR(10) PRIMARY KEY NOT NULL,
    nombreUsuario VARCHAR(50) NOT NULL,
    contrasena VARCHAR(70) NOT NULL,
    email VARCHAR(80) NOT NULL,
    numArchivos INT NOT NULL
);

INSERT INTO usuario (idUsuario, nombreUsuario, contrasena, email, numarchivos) VALUES ("2014131046","EdgarARF","f1f5f9daf23864983276705d747721727c76eaaf71133bda89b6e074cdbe6fee","edgar.alejandro.fuentes98@gmail.com", 0);
INSERT INTO usuario (idUsuario, nombreUsuario, contrasena, email, numarchivos) VALUES ("2018630142","MaryJSC","62b37fc0ec7da39332a806efb818dcd6fd51396c50d1bda04918755726ca9c87","marymorrera12@gmail.com", 0);
INSERT INTO usuario (idUsuario, nombreUsuario, contrasena, email, numarchivos) VALUES ("2019630522","IvetteRM","006683da63ad3acd43a16e15c3fd811e065b91982d182a3690006611a0ff9de2","ivette_ro_m@hotmail.com", 0);


