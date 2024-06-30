import logging
import os
from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from encryption import encrypt_message, decrypt_message
from key_management import generate_rsa_key_pair, encrypt_aes_key, decrypt_aes_key
from signatures import sign_message, verify_message
from validation import generate_hash, verify_hash
from anomaly_detection import train_anomaly_detection, predict_anomaly

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure value

# Dummy user credentials for demonstration purposes
USER_CREDENTIALS = {
    'testuser': 'testpassword'
}

# Function to authenticate user
def authenticate(username, password):
    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
        return True
    return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', message='Invalid credentials. Please try again.')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form['action']
        if action == 'send_message':
            return redirect(url_for('send_message'))
        elif action == 'received_messages':
            return redirect(url_for('received_messages'))

    return render_template('dashboard.html')

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

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
        data = None  # Replace with your actual data for anomaly detection
        model = train_anomaly_detection(data)
        new_data = None  # Replace with new data for prediction
        anomaly_detected = predict_anomaly(model, new_data)

        return jsonify({
            'encrypted_message': encrypted_message.hex(),
            'encrypted_aes_key': encrypted_aes_key.hex(),
            'signature': signature.hex(),
            'decrypted_message': decrypted_message,
            'signature_valid': signature_valid,
            'hash_valid': hash_valid,
            'anomaly_detected': anomaly_detected
        })

    return render_template('send_message.html')

@app.route('/received_messages', methods=['GET'])
def received_messages():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch received messages logic here (for demonstration purposes)
    received_messages = [
        {'sender': 'Alice', 'message': 'Hello from Alice'},
        {'sender': 'Bob', 'message': 'Hi, Bob here!'}
    ]

    return render_template('received_messages.html', received_messages=received_messages)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

