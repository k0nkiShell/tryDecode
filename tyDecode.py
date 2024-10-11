import base64
import codecs
from colorama import Fore, init, Style
import subprocess
import os
import re

# Inicializar colorama
init(autoreset=True)

# Función para filtrar caracteres no válidos de Base85
def filter_base85(text):
    valid_chars = set('!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
    return ''.join(c for c in text if c in valid_chars)

# Funciones de decodificación
def decode_base64(text):
    try:
        return f"{Fore.GREEN}{Style.BRIGHT}{base64.b64decode(text).decode('utf-8')}"
    except Exception as e:
        return f"{Fore.RED}Error decoding Base64: {e}"

def decode_base32(text):
    try:
        return f"{Fore.GREEN}{Style.BRIGHT}{base64.b32decode(text).decode('utf-8')}"
    except Exception as e:
        return f"{Fore.RED}Error decoding Base32: {e}"

def decode_base85a(text):
    filtered_text = filter_base85(text)
    try:
        decoded_bytes = base64.a85decode(filtered_text)
        return f"{Fore.GREEN}{Style.BRIGHT}{decoded_bytes.decode('utf-8')}"
    except Exception as e:
        return f"{Fore.RED}Error decoding a85decode: {e}"

def decode_base85b(text):
    filtered_text = filter_base85(text)
    try:
        decoded_bytes = base64.b85decode(filtered_text)
        return f"{Fore.GREEN}{Style.BRIGHT}{decoded_bytes.decode('utf-8')}"
    except Exception as e:
        return f"{Fore.RED}Error decoding b85decode: {e}"

def decode_rot13(text):
    try:
        return f"{Fore.GREEN}{Style.BRIGHT}{codecs.decode(text, 'rot_13')}"
    except Exception as e:
        return f"{Fore.RED}Error applying ROT13: {e}"

def caesar_cipher(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            shift_char = ord('a') if char.islower() else ord('A')
            result.append(chr(shift_char + (ord(char) - shift_char + shift) % 26))
        else:
            result.append(char)
    return f"{Fore.GREEN}{Style.BRIGHT}{''.join(result)}"

def decode_hex(text):
    try:
        return f"{Fore.GREEN}{Style.BRIGHT}{bytes.fromhex(text).decode('utf-8')}"
    except Exception as e:
        return f"{Fore.RED}Error decoding Hex: {e}"

def search_in_potfile(md5_hash):
    """Busca un hash MD5 en el archivo john.pot y devuelve la contraseña si se encuentra."""
    potfile_path = os.path.expanduser("~/.john/john.pot")

    if not os.path.exists(potfile_path):
        print("Archivo john.pot no encontrado.")
        return None

    #print(f"Buscando el hash MD5: {md5_hash} en el archivo john.pot...")

    try:
        with open(potfile_path, "r", encoding="utf-8") as potfile:
            for line in potfile:
                line = line.strip()
                #print(f"Revisando línea: {line}")  # Imprime la línea que se está revisando
                parts = line.split(':')
                # Comprueba si el hash está en la línea completa, excluyendo el prefijo
                if len(parts) > 1 and md5_hash in parts[0]:
                    #print(f"Hash encontrado: {parts[0]}, Contraseña: {parts[1]}")  # Imprime el hash y la contraseña
                    return parts[1]  # Devolver la contraseña

    except Exception as e:
        print(f"Error al leer el archivo john.pot: {e}")

    #print("Hash no encontrado en john.pot.")
    return None

def is_md5_hash(s):
    """Verifica si un string puede ser un hash MD5 válido."""
    return len(s) == 32 and bool(re.match(r'^[a-fA-F0-9]{32}$', s))

def decrypt_md5_with_john(md5_hash):
    # Verificar si el hash es un MD5 válido
    if not is_md5_hash(md5_hash):
        return f"{Fore.YELLOW}Formato no válido para MD5."
        
    # Verificar si el hash ya fue descifrado en el archivo john.pot
    result = search_in_potfile(md5_hash)
       
    if result:
        return f"{Fore.GREEN}{Style.BRIGHT}Hash encontrado en john.pot: {result}"

    # Si no fue encontrado, continuamos con John the Ripper
    current_directory = os.getcwd()
    hash_file_path = os.path.join(current_directory, "hash.txt")

    # Guardamos el hash en un archivo temporal
    with open(hash_file_path, "w", encoding="utf-8") as f:
        f.write(f"{md5_hash}\n")

    # Comando para ejecutar John the Ripper
    command = [
        "john",
        "--format=raw-md5",
        "--wordlist=/usr/share/wordlists/rockyou.txt",
        hash_file_path
    ]
    
    try:
        # Ejecutar John the Ripper y capturar la salida
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Decodificar la salida
        output = stdout.decode('utf-8') + stderr.decode('utf-8')
        
        # Imprimir la salida completa para depuración
        #print("Salida de John the Ripper:")
        #print(output)  # Para depuración, ver qué está devolviendo John

        # Procesar cada línea de la salida
        found_passwords = []
        for line in output.splitlines():
            #print(f"Buscando en línea: {line}")  # Para ver qué líneas se están procesando
            if "(?)" in line:  # Si la línea contiene "(?)", probablemente no es una contraseña
                found_passwords.append(line.strip())  # Devolver la línea completa que contiene la contraseña
            if md5_hash in line:  # Buscando línea con el hash
                continue

        if found_passwords:
            return f"{Fore.GREEN}{found_passwords[0]}"  # Devolver la primera contraseña encontrada
        else:
            return "No se encontró la contraseña."

    except subprocess.CalledProcessError as e:
        return f"Error al ejecutar John the Ripper: {e}"

# Función que intenta decodificar usando varios métodos
def analyze_text(text):
    methods = {
        "Base64   ": decode_base64,
        "Base32   ": decode_base32,
        "Base85a  ": decode_base85a,
        "Base85b  ": decode_base85b,
        "ROT13    ": decode_rot13,
        "Hexadec. ": decode_hex,
        "MD5      ": decrypt_md5_with_john,
        "Caesar 3 ": lambda t: caesar_cipher(t, -3),
        "Caesar 5 ": lambda t: caesar_cipher(t, -5),
        "Caesar 13": lambda t: caesar_cipher(t, -13),
    }
    
    print("")
    
    for method_name, method_function in methods.items():
        decoded = method_function(text)
        print(f"{Fore.CYAN}  [+] {Fore.RESET}{method_name}: {decoded}")

# Main
if __name__ == "__main__":
    text = input("Ingresa el texto codificado o hash MD5: ").strip()
    analyze_text(text)
