# app/auth.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

auth = Blueprint('auth', __name__)
jwt = JWTManager()

@auth.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # Validate credentials (e.g., check against database)
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@auth.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify(message="Protected route")

def init_app(app):
    jwt.init_app(app)
    app.register_blueprint(auth, url_prefix='/auth')
