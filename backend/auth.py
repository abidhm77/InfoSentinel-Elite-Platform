import os
import jwt
import datetime
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

# Mock user database - in a real application, this would be a database
users = {
    "admin@infosentinel.net": {
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "name": "Admin User"
    },
    "analyst@infosentinel.net": {
        "password": generate_password_hash("analyst123"),
        "role": "analyst",
        "name": "Security Analyst"
    },
    "viewer@infosentinel.net": {
        "password": generate_password_hash("viewer123"),
        "role": "viewer",
        "name": "Security Viewer"
    }
}

# Secret key for JWT
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'infosentinel-secret-key')

def generate_token(user_email, role):
    """Generate a JWT token for the user"""
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow(),
        'sub': user_email,
        'role': role
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['sub']
            current_role = data['role']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        # Pass the current user and role to the route
        return f(current_user, current_role, *args, **kwargs)
    
    return decorated

def role_required(roles):
    """Decorator to restrict routes based on user roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, current_role, *args, **kwargs):
            if current_role not in roles:
                return jsonify({'message': 'Permission denied!'}), 403
            return f(current_user, current_role, *args, **kwargs)
        return decorated_function
    return decorator

def authenticate_user(email, password):
    """Authenticate a user by email and password"""
    if email not in users:
        return None
    
    user = users[email]
    if check_password_hash(user['password'], password):
        return {
            'email': email,
            'role': user['role'],
            'name': user['name']
        }
    
    return None

def register_user(email, password, name, role='viewer'):
    """Register a new user"""
    if email in users:
        return False
    
    users[email] = {
        'password': generate_password_hash(password),
        'role': role,
        'name': name
    }
    
    return True