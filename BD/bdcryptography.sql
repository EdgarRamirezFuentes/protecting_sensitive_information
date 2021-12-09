use bdcryptography;

CREATE TABLE Usuario
(
IdUsuario int primary key not null,
NombreUsuario varchar(50) not null,
contrasena varchar(50) not null,
PrivateKey int not null,
PublicKey int not null,
Email varchar(50) not null
);

CREATE TABLE Firma
(
	NombreGenerado varchar(60) primary key not null,
	idEmisor int not null,
    idReceptor int not null,
    rutaDigesto varchar(200) not null
);