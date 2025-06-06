import random
import math
import json
from config import get_private_key_path, get_public_key_path, PRIME_MIN, PRIME_MAX

def es_primo(n):
    # Casos base
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    # Aqui se usa la criba de eratóstenes para verificar la primalidad
    k = math.isqrt(n)
    
    # Generamos los números primos hasta k usando la criba de Eratóstenes
    es_primo_array = [True] * (k + 1)
    es_primo_array[0] = es_primo_array[1] = False  # 0 y 1 no son primos
    
    # Aplicamos la criba de Eratóstenes
    for i in range(2, int(math.sqrt(k)) + 1):
        if es_primo_array[i]:
            # Marcamos todos los múltiplos de i como no primos
            for j in range(i*i, k + 1, i):
                es_primo_array[j] = False
    
    # Verificamos si n es divisible por algún número primo hasta su raíz cuadrada
    for i in range(2, k + 1):
        if es_primo_array[i] and n % i == 0:
            return False
    
    return True

def generar_primo(min_val=PRIME_MIN, max_val=PRIME_MAX):
    """
    Genera un número primo aleatorio entre min_val y max_val.
    """
    p = random.randint(min_val, max_val)
    while not es_primo(p):
        p = random.randint(min_val, max_val)
    return p

def mcd_extendido(a, b):
    """
    Algoritmo de Euclides extendido para encontrar el MCD y los coeficientes de Bézout.
    Retorna (mcd, x, y) donde mcd es el máximo común divisor de a y b,
    y x, y son coeficientes tales que a*x + b*y = mcd(x,y).
    """
    if a == 0:
        return b, 0, 1
    else:
        mcd, x1, y1 = mcd_extendido(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return mcd, x, y

def encontrar_inverso_modular(e, phi):
    """
    Encuentra el inverso modular de e módulo phi.
    Es decir, encuentra d tal que (e * d) % phi = 1.
    """
    mcd, x, y = mcd_extendido(e, phi)
    if mcd != 1:
        # e y phi no son coprimos, lo cual es un requisito en RSA
        raise ValueError("El MCD debe ser 1 para encontrar el inverso modular")
    else:
        # Aseguramos que d sea positivo
        return (x % phi + phi) % phi

def generar_claves_rsa(usuario):
    """
    Genera un par de claves RSA para el usuario especificado.
    
    El algoritmo RSA sigue estos pasos:
    1. Generar dos números primos grandes, p y q
    2. Calcular n = p * q (módulo de cifrado)
    3. Calcular φ(n) = (p-1) * (q-1) (función de Euler)
    4. Elegir un exponente e que sea coprimo con φ(n)
    5. Calcular el inverso modular de e módulo φ(n): d
    6. La clave pública es (n, e)
    7. La clave privada es (n, d)
    """
    # Paso 1: Generar primos p y q
    p = generar_primo()
    q = generar_primo()
    # Asegurar que p y q sean distintos
    while p == q:
        q = generar_primo()
    
    # Paso 2: Calcular n
    n = p * q
    
    # Paso 3: Calcular φ(n)
    phi_n = (p - 1) * (q - 1)
    
    # Paso 4: Elegir exponente e aleatorio
    e = random.randrange(2, phi_n)
    # Aseguramos que e y phi_n sean coprimos
    while math.gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)
    
    # Paso 5: Calcular d (inverso modular de e módulo phi_n)
    d = encontrar_inverso_modular(e, phi_n)
    
    # Guardar claves en archivos
    # La clave pública es (n, e)
    public_key = {"n": n, "e": e}
    with open(get_public_key_path(usuario), 'w') as f:
        json.dump(public_key, f)
    
    # La clave privada es (n, d)
    private_key = {"n": n, "d": d}
    with open(get_private_key_path(usuario), 'w') as f:
        json.dump(private_key, f)
    
    return True

def cargar_clave_publica(usuario):
    """Carga la clave pública de un usuario desde archivo."""
    try:
        with open(get_public_key_path(usuario), 'r') as f:
            key_data = json.load(f)
        return key_data
    except Exception as e:
        print(f"Error al cargar la clave pública: {e}")
        return None

def cargar_clave_privada(usuario):
    """Carga la clave privada de un usuario desde archivo."""
    try:
        with open(get_private_key_path(usuario), 'r') as f:
            key_data = json.load(f)
        return key_data
    except Exception as e:
        print(f"Error al cargar la clave privada: {e}")
        return None

def potencia_modular(base, exponente, modulo):
    """
    Calcula (base^exponente) % modulo de manera tradicional.
    Usa multiplicaciones sucesivas para calcular el resultado.
    """
    resultado = 1
    for _ in range(exponente):
        resultado = (resultado * base) % modulo
    return resultado

def cifrar_mensaje(mensaje, usuario_destino):
    """
    Cifra un mensaje usando la clave pública del usuario destino.
    El cifrado se realiza caracter por caracter usando ASCII.
    """
    public_key = cargar_clave_publica(usuario_destino)
    if not public_key:
        return None
    
    n = public_key["n"]
    e = public_key["e"]
    
    # Ciframos cada caracter del mensaje
    # Para cada caracter ASCII c, calculamos c^e mod n
    cifrado = []
    for char in mensaje:
        # Convertimos el caracter a su valor ASCII
        m = ord(char)
        
        # Verificamos que el valor no sea mayor que n
        if m >= n:
            raise ValueError(f"El valor ASCII {m} es demasiado grande para el módulo {n}. Usa primos más grandes.")
            
        # Cifrado RSA: c = m^e mod n
        c = potencia_modular(m, e, n)
        cifrado.append(c)
    
    # Convertimos la lista de números a texto para almacenamiento
    return json.dumps(cifrado)

def descifrar_mensaje(mensaje_cifrado, usuario):
    """
    Descifra un mensaje usando la clave privada del usuario.
    El descifrado se realiza número por número y se convierte de vuelta a ASCII.
    """
    private_key = cargar_clave_privada(usuario)
    if not private_key:
        return None
    
    n = private_key["n"]
    d = private_key["d"]
    
    try:
        # Convertimos el mensaje cifrado de texto a lista de números
        cifrado = json.loads(mensaje_cifrado)
        
        # Desciframos cada número
        mensaje = ""
        for c in cifrado:
            # Descifrado RSA: m = c^d mod n
            m = potencia_modular(c, d, n)
            
            # Convertimos el valor numérico de vuelta a caracter ASCII
            char = chr(m)
            mensaje += char
        
        return mensaje
    except Exception as e:
        print(f"Error al descifrar: {e}")
        return None

def guardar_mensaje(contenido, nombre_archivo, cifrado=True):
    """Guarda un mensaje en un archivo."""
    from config import MESSAGES_DIR
    import os
    
    # Creamos la ruta completa al archivo
    tipo = "cifrado" if cifrado else "descifrado"
    ruta_archivo = os.path.join(MESSAGES_DIR, f"{nombre_archivo}_{tipo}.txt")
    
    # Guardamos el contenido
    with open(ruta_archivo, 'w') as f:
        f.write(contenido)
    
    return ruta_archivo