from flask import Blueprint, request, render_template, jsonify, redirect, url_for, session
import os
import numpy as np
from key_management import generate_rsa_key_pair, encrypt_aes_key, decrypt_aes_key
from encryption import encrypt_message, decrypt_message
from signatures import sign_message, verify_message
from validation import generate_hash, verify_hash
from anomaly_detection import train_anomaly_detection, predict_anomaly

bp = Blueprint('routes', __name__)
bp.secret_key = 'your_secret_key'

# In-memory storage for user credentials and messages
user_credentials = {}
messages_store = []

# Function to authenticate user
def authenticate(username, password):
    return username in user_credentials and user_credentials[username] == password

@bp.route('/')
def home():
    return render_template('home.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in user_credentials:
            return render_template('register.html', message='Username already exists.')
        
        user_credentials[username] = password
        return redirect(url_for('routes.login'))

    return render_template('register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate(username, password):
            session['username'] = username
            return redirect(url_for('routes.dashboard'))
        else:
            return render_template('login.html', message='Invalid credentials. Please try again.')

    return render_template('login.html')

@bp.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        action = request.form['action']
        if action == 'send_message':
            return redirect(url_for('routes.send_message'))
        elif action == 'received_messages':
            return redirect(url_for('routes.received_messages'))

    return render_template('dashboard.html')

@bp.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        message = request.form['message']
        aes_key = os.urandom(32)  # Generate AES key

        # Generate RSA keys
        private_key, public_key = generate_rsa_key_pair()

        # Encrypt the message
        encrypted_message = encrypt_message(message, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Sign the message
        signature = sign_message(message.encode(), private_key)

        # Decrypt the AES key and message (for demonstration purposes)
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        decrypted_message = decrypt_message(encrypted_message, decrypted_aes_key).decode()

        # Verify the signature
        signature_valid = False
        try:
            verify_message(message.encode(), signature, public_key)
            signature_valid = True
        except Exception as e:
            signature_valid = False

        # Hash and verify hash (for demonstration purposes)
        hash_value = generate_hash(message)
        hash_valid = verify_hash(message, hash_value)

        # Machine learning anomaly detection (dummy implementation)
        data = np.random.rand(100, 10)  # Replace with your actual data for anomaly detection
        model = train_anomaly_detection(data)
        new_data = np.random.rand(1, 10)  # Replace with new data for prediction
        anomaly_detected = int(predict_anomaly(model, new_data) == -1)

        # Convert bytes to hexadecimal strings for serialization
        encrypted_message_hex = encrypted_message.hex()
        encrypted_aes_key_hex = encrypted_aes_key.hex()
        signature_hex = signature.hex()

        # Store the message in the in-memory storage
        messages_store.append({
            'sender': session['username'],
            'message': message,
            'encrypted_message': encrypted_message_hex,
            'encrypted_aes_key': encrypted_aes_key_hex,
            'signature': signature_hex,
            'decrypted_message': decrypted_message,
            'signature_valid': signature_valid,
            'hash_valid': hash_valid,
            'anomaly_detected': anomaly_detected
        })

        return jsonify({
            'encrypted_message': encrypted_message_hex,
            'encrypted_aes_key': encrypted_aes_key_hex,
            'signature': signature_hex,
            'decrypted_message': decrypted_message,
            'signature_valid': signature_valid,
            'hash_valid': hash_valid,
            'anomaly_detected': anomaly_detected
        })

    return render_template('send_message.html')

@bp.route('/received_messages', methods=['GET'])
def received_messages():
    if 'username' not in session:
        return redirect(url_for('routes.login'))

    # Fetch received messages
    received_messages = [msg for msg in messages_store if msg['sender'] == session['username']]

    return render_template('received_messages.html', received_messages=received_messages)

@bp.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('routes.login'))

def create_blueprint():
    return bp
