import sys
import os

# Get the absolute path to the parent directory of the current file (test_key.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Append the parent directory to sys.path
sys.path.append(parent_dir)
import unittest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from signatures import sign_message, verify_message

class TestSignatures(unittest.TestCase):

    def test_sign_verify_message(self):
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Create a message
        message = b"Test message"

        # Sign the message
        signature = sign_message(message, private_key)

        # Verify the signature
        verify_message(message, signature, public_key)

        # If the verification passes, no exception will be raised
        # If an exception is raised, the test will fail

if __name__ == '__main__':
    unittest.main()
