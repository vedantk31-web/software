# encryption.py

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    # Generate a 256-bit AES key (32 bytes)
    aes_key = os.urandom(32)
    return aes_key

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ct

def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# Example usage
if __name__ == "__main__":
    aes_key = generate_aes_key()
    message = "Hello, world!"
    encrypted_message = encrypt_message(message, aes_key)
    decrypted_message = decrypt_message(encrypted_message, aes_key)
    print(f"Original Message: {message}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message.decode()}")
