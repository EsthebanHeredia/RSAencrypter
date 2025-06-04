from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import time
from rsa_utils import generar_claves_rsa, cifrar_mensaje, descifrar_mensaje, guardar_mensaje
from config import USER_CREDENTIALS, USERS, KEYS_DIR, MESSAGES_DIR

app = Flask(__name__)
# Clave secreta para las sesiones de Flask (protege las cookies)
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    """
    Ruta raíz: muestra la página principal para seleccionar usuario.
    Renderiza la plantilla index.html que contiene el formulario de selección de usuario.
    """
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """
    Procesa el formulario de inicio de sesión.
    Verifica si el usuario y contraseña son válidos.
    """
    usuario = request.form.get('usuario')
    password = request.form.get('password')
    
    # Verificamos que el usuario esté en nuestra lista y la contraseña sea correcta
    if usuario in USERS and USER_CREDENTIALS[usuario] == password:
        # Guardamos el usuario en la sesión
        session['usuario'] = usuario
        return redirect(url_for('menu'))
    else:
        # Si el usuario o contraseña no son válidos, mostramos mensaje de error
        flash('Usuario o contraseña incorrectos')
        return redirect(url_for('index'))

@app.route('/menu')
def menu():
    """
    Muestra el menú principal con opciones según el usuario.
    Verifica si el usuario tiene claves generadas y si puede cifrar mensajes.
    """
    # Si no hay usuario en sesión, redirigimos al inicio
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    # Determinamos quién es el otro usuario del sistema
    otro_usuario = USERS[1] if usuario == USERS[0] else USERS[0]
    
    # Verificamos si el usuario tiene claves generadas
    tiene_claves = os.path.exists(os.path.join(KEYS_DIR, f"{usuario}_private.key"))
    # Verificamos si el otro usuario tiene clave pública (necesaria para cifrar)
    otro_tiene_claves = os.path.exists(os.path.join(KEYS_DIR, f"{otro_usuario}_public.key"))
    
    return render_template('menu.html', 
                          usuario=usuario, 
                          otro_usuario=otro_usuario,
                          tiene_claves=tiene_claves,
                          otro_tiene_claves=otro_tiene_claves)

@app.route('/generar_claves')
def generar_claves():
    """
    Muestra la página para generar claves RSA.
    """
    # Verificación de seguridad: debe haber un usuario en sesión
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    tiene_claves = os.path.exists(os.path.join(KEYS_DIR, f"{usuario}_private.key"))
    
    return render_template('generar.html', usuario=usuario, tiene_claves=tiene_claves)

@app.route('/procesar_generacion', methods=['POST'])
def procesar_generacion():
    """
    Procesa la generación de claves RSA para el usuario actual.
    Genera un par de claves (pública y privada) y las guarda en archivos.
    """
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    
    try:
        # Verificamos si hay que eliminar claves antiguas
        private_key_path = os.path.join(KEYS_DIR, f"{usuario}_private.key")
        public_key_path = os.path.join(KEYS_DIR, f"{usuario}_public.key")
        
        if os.path.exists(private_key_path):
            os.remove(private_key_path)
        if os.path.exists(public_key_path):
            os.remove(public_key_path)
        
        # Llamamos a la función que genera y guarda las claves
        if generar_claves_rsa(usuario):
            flash('Claves generadas con éxito')
        else:
            flash('Error al generar las claves')
    except Exception as e:
        flash(f'Error: {str(e)}')
    
    return redirect(url_for('menu'))

@app.route('/cifrar')
def cifrar():
    """
    Muestra la página para cifrar mensajes.
    El usuario podrá escribir un mensaje y cifrarlo usando la clave pública del otro usuario.
    """
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    otro_usuario = USERS[1] if usuario == USERS[0] else USERS[0]
    
    return render_template('cifrar.html', 
                          usuario=usuario,
                          otro_usuario=otro_usuario)

@app.route('/procesar_cifrado', methods=['POST'])
def procesar_cifrado():
    """
    Procesa el cifrado de un mensaje y lo muestra en pantalla.
    """
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    otro_usuario = USERS[1] if usuario == USERS[0] else USERS[0]
    mensaje = request.form.get('mensaje')
    nombre_archivo = request.form.get('nombre_archivo')
    
    try:
        # Ciframos el mensaje usando la clave pública del destinatario
        mensaje_cifrado = cifrar_mensaje(mensaje, otro_usuario)
        if mensaje_cifrado:
            # Guardamos el mensaje cifrado en un archivo
            ruta_guardado = guardar_mensaje(mensaje_cifrado, nombre_archivo, cifrado=True)
            
            # Mostramos el resultado en una página específica
            return render_template('resultado_cifrado.html',
                                  usuario=usuario,
                                  mensaje_original=mensaje,
                                  mensaje_cifrado=mensaje_cifrado,
                                  destinatario=otro_usuario,
                                  ruta_guardado=ruta_guardado)
        else:
            flash('Error al cifrar el mensaje')
            return redirect(url_for('cifrar'))
    except Exception as e:
        flash(f'Error: {str(e)}')
        return redirect(url_for('cifrar'))

@app.route('/descifrar')
def descifrar():
    """
    Muestra la página para descifrar mensajes.
    """
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    # Obtenemos la lista de archivos cifrados disponibles
    archivos_cifrados = [f for f in os.listdir(MESSAGES_DIR) if f.endswith('_cifrado.txt')]
    
    return render_template('descifrar.html', 
                          usuario=session['usuario'],
                          archivos=archivos_cifrados)

@app.route('/procesar_descifrado', methods=['POST'])
def procesar_descifrado():
    """
    Procesa el descifrado de un mensaje y lo muestra en pantalla.
    Puede recibir el mensaje desde un archivo o directamente como texto.
    """
    if 'usuario' not in session:
        return redirect(url_for('index'))
    
    usuario = session['usuario']
    metodo = request.form.get('metodo', 'archivo')
    
    try:
        # Determinamos la fuente del texto cifrado
        if metodo == 'archivo':
            archivo = request.form.get('archivo')
            nombre_archivo = os.path.splitext(archivo)[0].replace('_cifrado', '')
            
            # Leemos el mensaje cifrado del archivo
            with open(os.path.join(MESSAGES_DIR, archivo), 'r') as f:
                mensaje_cifrado = f.read()
                
            fuente = f"archivo: {archivo}"
        else:  # metodo == 'texto'
            mensaje_cifrado = request.form.get('texto_cifrado')
            nombre_archivo = request.form.get('nombre_archivo', f"mensaje_directo_{int(time.time())}")
            fuente = "entrada directa de texto"
        
        # Desciframos el mensaje usando la clave privada del usuario
        mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, usuario)
        
        if mensaje_descifrado:
            # Guardamos el mensaje descifrado en un nuevo archivo solo si se proporciona un nombre
            if nombre_archivo:
                ruta_guardado = guardar_mensaje(mensaje_descifrado, nombre_archivo, cifrado=False)
            else:
                ruta_guardado = "No guardado (no se proporcionó nombre)"
            
            # Mostramos el resultado en una página específica
            return render_template('resultado_descifrado.html',
                                  usuario=usuario,
                                  mensaje_cifrado=mensaje_cifrado,
                                  mensaje_descifrado=mensaje_descifrado,
                                  nombre_archivo=fuente,
                                  ruta_guardado=ruta_guardado)
        else:
            flash('Error al descifrar el mensaje. Es posible que no tengas la clave privada correcta o el formato sea incorrecto.')
            return redirect(url_for('descifrar'))
    except Exception as e:
        flash(f'Error al descifrar: {str(e)}')
        return redirect(url_for('descifrar'))

@app.route('/logout')
def logout():
    """
    Cierra la sesión del usuario eliminando su información de la sesión.
    """
    session.pop('usuario', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Creamos los directorios necesarios si no existen
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(MESSAGES_DIR, exist_ok=True)
    
    # Iniciamos la aplicación en modo debug para desarrollo
    app.run(debug=True)