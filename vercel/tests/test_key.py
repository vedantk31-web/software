import sys
import os

# Get the absolute path to the parent directory of the current file (test_key.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Append the parent directory to sys.path
sys.path.append(parent_dir)

# Now you can import your modules
from key_management import generate_rsa_key_pair, serialize_rsa_key, encrypt_aes_key, decrypt_aes_key

# Your test cases go here...

import unittest
from key_management import generate_rsa_key_pair, serialize_rsa_key, encrypt_aes_key, decrypt_aes_key

class TestKeyManagement(unittest.TestCase):

    def test_generate_rsa_key_pair(self):
        # Test generating RSA key pair
        private_key, public_key = generate_rsa_key_pair()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_serialize_rsa_key(self):
        # Test serializing RSA keys
        private_key, public_key = generate_rsa_key_pair()
        private_key_pem, public_key_pem = serialize_rsa_key(private_key, public_key)
        self.assertIsNotNone(private_key_pem)
        self.assertIsNotNone(public_key_pem)

    def test_encrypt_decrypt_aes_key(self):
        # Test encrypting and decrypting AES key using RSA keys
        aes_key = b'0123456789abcdef0123456789abcdef'  # 256-bit key
        private_key, public_key = generate_rsa_key_pair()
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        self.assertEqual(aes_key, decrypted_aes_key)

if __name__ == '__main__':
    unittest.main()
