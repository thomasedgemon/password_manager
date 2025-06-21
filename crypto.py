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
import csv
from session import clear_displayed_password, clear_session_memory

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

def decrypt(master_password, common_name, csv_path):
    import base64

    # Find matching ciphertext
    try:
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['Label'] == common_name:
                    b64_blob = row['Ciphertext']
                    break
            else:
                print(f"Label '{common_name}' not found.")
                return None
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return None

    try:
        blob = base64.b64decode(b64_blob)
        salt = blob[:salt_size]
        iv = blob[salt_size:salt_size+iv_size]
        ciphertext = blob[salt_size+iv_size:]

        key = derive_key(master_password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def encrypt(master_password, common_name, plaintext, csv_path):
    if not master_password or not common_name or not plaintext:
        print("Encryption failed: missing inputs.")
        return

    salt = os.urandom(salt_size)
    iv = os.urandom(iv_size)  
    key = derive_key(master_password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    blob = salt + iv + ciphertext
    b64_blob = base64.b64encode(blob).decode()

    # Write (Label, Ciphertext) to CSV
    try:
        with open(csv_path, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([common_name, b64_blob])
        print(f"Saved encrypted password under label '{common_name}'.")
    except Exception as e:
        print(f"Error writing to CSV: {e}")

    
    # Clear session memory
    clear_session_memory()
    clear_displayed_password()



