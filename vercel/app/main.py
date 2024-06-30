import os
import logging
from encryption import encrypt_message, decrypt_message
from key_management import generate_rsa_key_pair, encrypt_aes_key, decrypt_aes_key
from signatures import sign_message, verify_message
from validation import generate_hash, verify_hash
from anomaly_detection import train_anomaly_detection, predict_anomaly
import numpy as np

if __name__ == "__main__":
    message = "This is a secure message."
    aes_key = os.urandom(32)  # Generate AES key

    # Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()

    # Encrypt the message
    encrypted_message = encrypt_message(message, aes_key)
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    
    # Sign the message
    signature = sign_message(message.encode(), private_key)

    # Decrypt the AES key and message
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    decrypted_message = decrypt_message(encrypted_message, decrypted_aes_key).decode()

    # Verify the signature
    try:
        verify_message(message.encode(), signature, public_key)
        print("Signature is valid.")
    except Exception as e:
        print("Signature verification failed:", e)

    # Hash and verify hash
    hash_value = generate_hash(message)
    if verify_hash(message, hash_value):
        print("Hash is valid.")
    else:
        print("Hash verification failed.")

    # Machine learning anomaly detection
    data = np.random.rand(100, 10)  # Dummy data for training
    model = train_anomaly_detection(data)
    new_data = np.random.rand(1, 10)  # Dummy new data
    if predict_anomaly(model, new_data) == -1:
        print("Anomaly detected.")
    else:
        print("No anomaly detected.")
