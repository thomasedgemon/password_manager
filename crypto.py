import cryptography
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import string
import secrets
from .session import clear_displayed_password

salt_size = 16
key_size = 32  #for aes256
iv_size = 16 
iterations = 600000
backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

def decrypt(master_password, common_name, ciphertext):
    #perform decryption
    
    #display label and decrypted password as str for 10 seconds, then
    clear_displayed_password()
    return

def encrypt(master_password, common_name, plaintext):
    #probably use aes-gcm
    #derive key with with iv and salt via pbkdf
    #pad data
    #encrypt with key
    #pull in data from user-inputted fields which don't yet exist. 
    salt = os.urandom(salt_size)
    iv = os.urandom(iv_size)  # Fixed: was 'iv' instead of 'iv_size'
    key = derive_key(master_password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt, iv, ciphertext
    blob = salt + iv + ciphertext
    return base64.b64encode(blob).decode()
    #save as common name, ciphertext to csv
    #wipe master password from session memory
    #wipe fields where user inputted common name and plaintext password.



