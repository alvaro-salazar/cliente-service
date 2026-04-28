-- Datos de prueba para ClienteService
-- Se ejecuta automáticamente al arrancar con ddl-auto=create-drop

-- Regiones (sin IDs explícitos — los asigna el autoincrement)
INSERT INTO regiones (nombre) VALUES ('Suramerica');
INSERT INTO regiones (nombre) VALUES ('Centroamerica');
INSERT INTO regiones (nombre) VALUES ('Norteamerica');
INSERT INTO regiones (nombre) VALUES ('Europa');
INSERT INTO regiones (nombre) VALUES ('Asia');
INSERT INTO regiones (nombre) VALUES ('Africa');
INSERT INTO regiones (nombre) VALUES ('Oceania');
INSERT INTO regiones (nombre) VALUES ('Antartida');

-- Clientes de referencia (pioneros de la informática)
INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Linus', 'Torvalds', 'linus@linux.org', 'linus.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('James', 'Gosling', 'james@java.com', 'james.jpg', 3);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Dennis', 'Ritchie', 'dennis@bell.com', 'dennis.jpg', 3);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Grace', 'Hopper', 'grace@navy.mil', 'grace.jpg', 3);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Ada', 'Lovelace', 'ada@babbage.io', 'ada.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Alan', 'Turing', 'alan@bletchley.uk', 'alan.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Margaret', 'Hamilton', 'margaret@nasa.gov', 'margaret.jpg', 3);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Tim', 'Berners-Lee', 'tim@w3.org', 'tim.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Guido', 'van Rossum', 'guido@python.org', 'guido.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Ken', 'Thompson', 'ken@bell.com', 'ken.jpg', 3);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Bjarne', 'Stroustrup', 'bjarne@cpp.org', 'bjarne.jpg', 4);

INSERT INTO clientes (nombre, apellido, email, foto, region_id)
VALUES ('Brian', 'Kernighan', 'brian@bell.com', 'brian.jpg', 3);
