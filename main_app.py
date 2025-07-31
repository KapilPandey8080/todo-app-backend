# main_app.py

import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import jwt
from datetime import datetime, timedelta
from functools import wraps
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# =============================================================================
#  APP CONFIGURATION
# =============================================================================

app = Flask(__name__)

# --- General Config ---
# Enable Cross-Origin Resource Sharing (CORS) to allow the React frontend to communicate with this API.
CORS(app) 
# Bcrypt for hashing passwords
bcrypt = Bcrypt(app)

# --- Secret Keys & Environment Variables ---
# It's crucial to use environment variables for sensitive data.
# Create a .env file in your project root with these variables.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_super_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/tododb')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Google OAuth Config ---
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# --- Flask-Mail Config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your Gmail address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
mail = Mail(app)


# --- Database Initialization ---
db = SQLAlchemy(app)

# =============================================================================
#  DATABASE MODELS (using SQLAlchemy ORM)
# =============================================================================

class User(db.Model):
    """User Model"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True) # Nullable for Google users
    name = db.Column(db.String(100), nullable=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    todos = db.relationship('Todo', backref='user', lazy=True, cascade="all, delete-orphan")

    def __init__(self, email, password=None, name=None, google_id=None):
        self.email = email
        if password:
            self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.name = name
        self.google_id = google_id

class Todo(db.Model):
    """Todo Model"""
    __tablename__ = 'todos'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# =============================================================================
#  JWT TOKEN HANDLING & DECORATORS
# =============================================================================

def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

def send_todo_creation_email(user_email, user_name, todo_text):
    """Sends an email to the user when a new todo is created."""
    try:
        msg = Message(
            'New Todo Created!',
            recipients=[user_email]
        )
        msg.body = f"Hi {user_name or 'there'},\n\nYou just created a new todo: '{todo_text}'.\n\nStay productive!\n\nThe Todo App Team"
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}") # Log error but don't block the request

# =============================================================================
#  API ROUTES
# =============================================================================

# --- Authentication Routes ---

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409

    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Could not verify'}), 401

    user = User.query.filter_by(email=email).first()

    if not user or not user.password or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], "HS256")

    return jsonify({'token': token})

@app.route('/auth/google-login', methods=['POST'])
def google_login():
    """Handles Google Sign-In."""
    google_token = request.json.get('token')
    if not google_token:
        return jsonify({"message": "No token provided"}), 400

    try:
        # Verify the token with Google's tokeninfo endpoint
        token_info_url = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
        response = requests.get(token_info_url, params={'id_token': google_token})
        user_info = response.json()

        if 'error' in user_info:
            return jsonify({"message": "Invalid Google token", "error": user_info['error_description']}), 401
        
        # Check if user exists
        user = User.query.filter_by(google_id=user_info['sub']).first()
        
        if not user:
            # If not, check if an account with that email already exists
            user = User.query.filter_by(email=user_info['email']).first()
            if user:
                # Link Google ID to existing account
                user.google_id = user_info['sub']
            else:
                # Create a new user
                user = User(
                    email=user_info['email'],
                    name=user_info.get('name'),
                    google_id=user_info['sub']
                )
                db.session.add(user)
            db.session.commit()

        # Generate JWT for our application
        app_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], "HS256")
        
        return jsonify({'token': app_token})

    except Exception as e:
        return jsonify({"message": "An error occurred during Google login", "error": str(e)}), 500


# --- Todo Routes (Protected) ---

@app.route('/api/todos', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.desc()).all()
    output = []
    for todo in todos:
        todo_data = {
            'id': todo.id,
            'text': todo.text,
            'completed': todo.completed,
            'created_at': todo.created_at
        }
        output.append(todo_data)
    return jsonify({'todos': output})

@app.route('/api/todos', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    text = data.get('text')
    if not text:
        return jsonify({'message': 'Todo text cannot be empty'}), 400

    new_todo = Todo(text=text, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    # Send email notification
    send_todo_creation_email(current_user.email, current_user.name, new_todo.text)
    
    return jsonify({'message': 'Todo created!', 'id': new_todo.id}), 201

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
@token_required
def update_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message': 'No todo found!'}), 404

    data = request.get_json()
    todo.text = data.get('text', todo.text)
    todo.completed = data.get('completed', todo.completed)
    db.session.commit()
    
    return jsonify({'message': 'Todo updated!'})

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message': 'No todo found!'}), 404

    db.session.delete(todo)
    db.session.commit()
    
    return jsonify({'message': 'Todo deleted!'})

# =============================================================================
#  MAIN DRIVER
# =============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
    app.run(debug=True, port=5000)

# =============================================================================
#  SETUP & RUN INSTRUCTIONS
# =============================================================================
#
# 1. Create a virtual environment:
#    python -m venv venv
#    source venv/bin/activate  (On Windows: venv\Scripts\activate)
#
# 2. Install dependencies:
#    pip install Flask Flask-SQLAlchemy Flask-Cors Flask-Bcrypt PyJWT Flask-Mail psycopg2-binary python-dotenv requests
#
# 3. Create a PostgreSQL database (e.g., on Render or locally) and get the connection URL.
#
# 4. Create a `.env` file in the same directory as this script with the following content:
#
#    SECRET_KEY='a_very_strong_and_random_secret_key'
#    DATABASE_URL='postgresql://YOUR_DB_USER:YOUR_DB_PASSWORD@YOUR_DB_HOST/YOUR_DB_NAME'
#    GOOGLE_CLIENT_ID='YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com'
#    GOOGLE_CLIENT_SECRET='YOUR_GOOGLE_CLIENT_SECRET'
#    MAIL_USERNAME='your.email@gmail.com'
#    MAIL_PASSWORD='your_gmail_app_password' 
#    # Note: For MAIL_PASSWORD, you need to generate an "App Password" from your Google Account security settings.
#
# 5. Run the application:
#    python main_app.py
#
