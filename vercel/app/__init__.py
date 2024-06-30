from flask import Flask
import os
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    # Set the path to the templates directory
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    app.template_folder = templates_dir
    
    app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your own secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database file
    
    db.init_app(app)
    bcrypt.init_app(app)
    
    # Import routes and register blueprint
    from app import routes  # Assuming your routes are defined in a module named 'routes'
    app.register_blueprint(routes.bp)
    
    with app.app_context():
        db.create_all()  # Creates database tables based on defined models
    
    return app
