import sys
import os

# Get the absolute path to the parent directory of the current file (test_key.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Append the parent directory to sys.path
sys.path.append(parent_dir)
import os
from app.imports import *  # Assuming necessary functions are imported from the imports module
import numpy as np
import numpy as np


def test_secure_messaging():
    # Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()

    # Generate a message
    message = "This is a secure message."

    # Generate a random AES key
    aes_key = os.urandom(32)

    # Encrypt the message
    encrypted_message = encrypt_message(message, aes_key)

    # Encrypt the AES key using the public RSA key
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

    # Dummy data for anomaly detection
    data = np.random.rand(100, 10)
    # Train anomaly detection model
    model = train_anomaly_detection(data)
    
    # Dummy new data for prediction
    new_data = np.random.rand(1, 10)
    
    # Predict anomaly
    if predict_anomaly(model, new_data) == -1:
        print("Anomaly detected.")
    else:
        print("No anomaly detected.")

if __name__ == "__main__":
    test_secure_messaging()
