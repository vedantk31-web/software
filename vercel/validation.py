from hashlib import sha256

def generate_hash(message):
    return sha256(message.encode()).hexdigest()

def verify_hash(message, hash_value):
    return sha256(message.encode()).hexdigest() == hash_value
