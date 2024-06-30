import sys
import os

# Get the absolute path to the parent directory of the current file (test_key.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Append the parent directory to sys.path
sys.path.append(parent_dir)
import unittest
from encryption import encrypt_message, decrypt_message

class TestEncryption(unittest.TestCase):

    def test_encrypt_message(self):
        # Test encryption of a message
        message = "This is a secret message."
        key = b'0123456789abcdef0123456789abcdef'  # 256-bit key
        encrypted_message = encrypt_message(message, key)
        
        # Assert that the encrypted message is not equal to the original message
        self.assertNotEqual(encrypted_message, message.encode())

    def test_decrypt_message(self):
        # Test decryption of an encrypted message
        message = "This is a secret message."
        key = b'0123456789abcdef0123456789abcdef'  # 256-bit key
        encrypted_message = encrypt_message(message, key)
        decrypted_message = decrypt_message(encrypted_message, key)
        
        # Assert that the decrypted message is equal to the original message
        self.assertEqual(decrypted_message.decode(), message)

    def test_empty_message(self):
        # Test encryption and decryption of an empty message
        empty_message = ""
        key = b'0123456789abcdef0123456789abcdef'  # 256-bit key
        encrypted_empty_message = encrypt_message(empty_message, key)
        decrypted_empty_message = decrypt_message(encrypted_empty_message, key)
        
        # Assert that the decrypted empty message is also empty
        self.assertEqual(decrypted_empty_message.decode(), empty_message)

if __name__ == '__main__':
    unittest.main()
