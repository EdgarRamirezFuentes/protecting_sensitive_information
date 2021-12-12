use bdcryptography
drop table usuario
ALTER TABLE usuario ADD numArchivos int not NULL ;
CREATE TABLE usuario(
idUsuario int primary key not null,
nombreUsuario varchar(50) not null,
contrasena varchar(60) not null,
email varchar(80) not null,
numArchivos int not null
);
insert into usuario (idUsuario,nombreUsuario,contrasena,email,numarchivos) values (1,"Usuario de prueba","contrasena de prueba","email de prueba",14)