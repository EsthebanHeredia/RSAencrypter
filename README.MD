# RSA Encrypter

Proyecto final del curso de Matemática Discreta y Herramientas de Modelación Matemática.  
Este proyecto consiste en una página web que permite generar llaves RSA, encriptar y desencriptar mensajes de manera sencilla y didáctica.

## Descripción

La aplicación web implementa el algoritmo RSA, un sistema de criptografía de clave pública. Permite a los usuarios:

- Generar llaves públicas y privadas.
- Encriptar mensajes utilizando la llave pública.
- Desencriptar mensajes utilizando la llave privada.


## Tecnologías utilizadas

- **Python**: Lógica principal de generación de claves y operaciones criptográficas.
- **HTML**: Estructura de la interfaz web.
- **CSS**: Estilos y diseño visual de la página.

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/EsthebanHeredia/RSAencrypter.git
   ```
2. Ingresa al directorio del proyecto:
   ```bash
   cd RSAencrypter
   ```
3. Instala las dependencias necesarias (si aplica, por ejemplo Flask):
   ```bash
   pip install -r requirements.txt
   ```
4. Ejecuta la aplicación:
   ```bash
   python app.py
   ```
5. Accede a la página web desde tu navegador en `http://localhost:5000`

## Uso

1. Ingresa al sitio web local.
2. Genera un par de llaves RSA.
3. Encripta un mensaje utilizando la llave pública.
4. Desencripta el mensaje usando la llave privada correspondiente.

## Estructura del repositorio

- `/app.py` — Archivo principal de la aplicación.
- `/templates/` — Archivos HTML para la interfaz.
- `/static/` — Archivos CSS para los estilos.
- `/rsa_utils.py` — Funciones relacionadas con el algoritmo RSA.

## Créditos

Desarrollado por Estheban Heredia 

```