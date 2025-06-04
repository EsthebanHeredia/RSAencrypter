# Configuración de directorios
import os

# Directorio base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directorios para almacenar claves y mensajes
KEYS_DIR = os.path.join(BASE_DIR, "claves")
MESSAGES_DIR = os.path.join(BASE_DIR, "mensajes")

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(MESSAGES_DIR, exist_ok=True)

# Usuarios y contraseñas
USER_CREDENTIALS = {
    "BOB": "passwordBOB",
    "ALICE": "passwordALICE"
}
USERS = list(USER_CREDENTIALS.keys())

# Configuración RSA
# Tamaño de los números primos 
PRIME_MIN = 100
PRIME_MAX = 1000

# Funciones auxiliares para obtener rutas de archivos de claves
def get_private_key_path(user):
    """Devuelve la ruta al archivo de clave privada de un usuario."""
    return os.path.join(KEYS_DIR, f"{user}_private.key")

def get_public_key_path(user):
    """Devuelve la ruta al archivo de clave pública de un usuario."""
    return os.path.join(KEYS_DIR, f"{user}_public.key")