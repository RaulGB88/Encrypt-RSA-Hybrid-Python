from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes 
from Crypto.Cipher import AES, PKCS1_OAEP 
from pathlib import Path

# https://pycryptodome.readthedocs.io/en/latest/src/examples.html

data = ('Comentar el código es como limpiar el cuarto de baño; nadie quiere hacerlo, '
'pero el resultado es siempre una experiencia más agradable para uno mismo y sus invitados - Ryan Campbell')
datosBin = data.encode("utf-8") #pasamos el texto a binario

fichero_path = Path(__file__).parent / "DatosEncriptados.bin" #forzamos que el fichero se guarde junto a nuestro ejecutable py

file_out = open(fichero_path,"wb")

fichero_path = Path(__file__).parent / "publica_usuario_A.pem"

recipient_key = RSA.import_key(open(fichero_path).read()) #leemos el fichero con la clave pública 
session_key = get_random_bytes(16) #clave generada de forma aleatoria para cifrar los datos

#Encriptar la sesión con la clave pública el usuario_A
cipher_rsa = PKCS1_OAEP.new(recipient_key) #creamos un nuevo objeto con el algoritmo de cifrado PKCS1_OAEP, pesándole la clave pública RSA
enc_session_key = cipher_rsa.encrypt(session_key) #Encriptamos la clave simétrica (session_key) con la clave pública RSA

#Encriptar los datos con AES
cipher_aes= AES.new(session_key, AES.MODE_EAX)
cipher_text, tag = cipher_aes.encrypt_and_digest(datosBin) #Devuelve el texto cifrado y el Hash del texto (el HAsh se guarda en tag)

file_out.write(enc_session_key)
file_out.write(cipher_aes.nonce) #es de 16 bytes y nonce es un número generado aleatoria mente para un sólo uso 
file_out.write(tag) #es de 16 bytes
file_out.write(cipher_text)
file_out.close()