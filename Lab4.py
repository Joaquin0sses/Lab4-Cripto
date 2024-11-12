from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
import base64

def ajustar_clave(clave, longitud_necesaria):
    if len(clave) < longitud_necesaria:
        clave += get_random_bytes(longitud_necesaria - len(clave))
    elif len(clave) > longitud_necesaria:
        clave = clave[:longitud_necesaria]
    return clave

def cifrar_des(texto, clave, iv):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_padding = texto + (8 - len(texto) % 8) * ' '
    cifrado = cipher.encrypt(texto_padding.encode())
    return base64.b64encode(cifrado).decode()

def descifrar_des(cifrado, clave, iv):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    cifrado_bytes = base64.b64decode(cifrado)
    descifrado = cipher.decrypt(cifrado_bytes).decode().rstrip()
    return descifrado

def cifrar_aes(texto, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_padding = texto + (16 - len(texto) % 16) * ' '
    cifrado = cipher.encrypt(texto_padding.encode())
    return base64.b64encode(cifrado).decode()

def descifrar_aes(cifrado, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    cifrado_bytes = base64.b64decode(cifrado)
    descifrado = cipher.decrypt(cifrado_bytes).decode().rstrip()
    return descifrado

def cifrar_3des(texto, clave, iv):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_padding = texto + (8 - len(texto) % 8) * ' '
    cifrado = cipher.encrypt(texto_padding.encode())
    return base64.b64encode(cifrado).decode()

def descifrar_3des(cifrado, clave, iv):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    cifrado_bytes = base64.b64decode(cifrado)
    descifrado = cipher.decrypt(cifrado_bytes).decode().rstrip()
    return descifrado

def main():
    # Ingreso de datos
    texto = input("Ingrese el texto a cifrar: ")
    
    # DES
    clave_des = input("Ingrese la clave para DES (8 bytes): ").encode()
    iv_des = input("Ingrese el vector de inicialización para DES (8 bytes): ").encode()
    clave_des = ajustar_clave(clave_des, 8)
    iv_des = ajustar_clave(iv_des, 8)
    print("Clave final para DES:", clave_des)
    print("IV ajustado para DES:", iv_des)
    texto_cifrado_des = cifrar_des(texto, clave_des, iv_des)
    print("Texto cifrado con DES:", texto_cifrado_des)
    texto_descifrado_des = descifrar_des(texto_cifrado_des, clave_des, iv_des)
    print("Texto descifrado con DES:", texto_descifrado_des)
    print("Descifrado DES exitoso:", texto == texto_descifrado_des)
    
    # AES
    clave_aes = input("Ingrese la clave para AES-256 (32 bytes): ").encode()
    iv_aes = input("Ingrese el vector de inicialización para AES-256 (16 bytes): ").encode()
    clave_aes = ajustar_clave(clave_aes, 32)
    iv_aes = ajustar_clave(iv_aes, 16)
    print("Clave final para AES-256:", clave_aes)
    print("IV ajustado para AES-256:", iv_aes)
    texto_cifrado_aes = cifrar_aes(texto, clave_aes, iv_aes)
    print("Texto cifrado con AES-256:", texto_cifrado_aes)
    texto_descifrado_aes = descifrar_aes(texto_cifrado_aes, clave_aes, iv_aes)
    print("Texto descifrado con AES-256:", texto_descifrado_aes)
    print("Descifrado AES-256 exitoso:", texto == texto_descifrado_aes)
    
    # 3DES
    clave_3des = input("Ingrese la clave para 3DES (24 bytes): ").encode()
    iv_3des = input("Ingrese el vector de inicialización para 3DES (8 bytes): ").encode()
    clave_3des = ajustar_clave(clave_3des, 24)
    iv_3des = ajustar_clave(iv_3des, 8)
    print("Clave final para 3DES:", clave_3des)
    print("IV ajustado para 3DES:", iv_3des)
    texto_cifrado_3des = cifrar_3des(texto, clave_3des, iv_3des)
    print("Texto cifrado con 3DES:", texto_cifrado_3des)
    texto_descifrado_3des = descifrar_3des(texto_cifrado_3des, clave_3des, iv_3des)
    print("Texto descifrado con 3DES:", texto_descifrado_3des)
    print("Descifrado 3DES exitoso:", texto == texto_descifrado_3des)

if __name__ == "__main__":
    main()
