#!/bin/bash

# InfoSentinel Deployment Script
echo "===== InfoSentinel Platform Deployment ====="
echo "This script will prepare and deploy the InfoSentinel platform."

# Create deployment directory
DEPLOY_DIR="./deploy"
echo "Creating deployment directory..."
mkdir -p $DEPLOY_DIR
mkdir -p $DEPLOY_DIR/backend
mkdir -p $DEPLOY_DIR/frontend

# Install required Python packages for deployment
echo "Installing required Python packages..."
pip install flask flask-cors python-jwt werkzeug

# Copy backend files
echo "Copying backend files..."
cp backend/simple_app.py $DEPLOY_DIR/backend/app.py

# Create README file
echo "Creating documentation..."
cat > $DEPLOY_DIR/README.md << 'EOL'
# InfoSentinel Platform

InfoSentinel is a comprehensive penetration testing platform designed to identify security vulnerabilities in networks, web applications, and systems.

## Quick Start

1. Run the deployment script: `./start.sh`
2. Access the platform at: http://localhost:5000

## Features

- Security vulnerability scanning
- Detailed reporting and analytics
- User authentication system
- Dashboard with real-time statistics

## Default Credentials

- Username: admin
- Password: admin123

## License

Copyright (c) 2025 InfoSentinel
EOL

# Create start script
echo "Creating startup script..."
cat > $DEPLOY_DIR/start.sh << 'EOL'
#!/bin/bash

echo "Starting InfoSentinel Platform..."
cd backend
python app.py
EOL

# Make start script executable
chmod +x $DEPLOY_DIR/start.sh

# Copy frontend files
echo "Copying frontend files..."
cp -r frontend/public/* $DEPLOY_DIR/frontend/

# Create .env file for configuration
echo "Creating configuration file..."
cat > $DEPLOY_DIR/backend/.env << 'EOL'
# InfoSentinel Configuration
SECRET_KEY=infosentinel_production_secret_key_2025
DEBUG=False
PORT=5001
EOL

# Create a simple production-ready app.py
echo "Creating production backend..."
cat > $DEPLOY_DIR/backend/app.py << 'EOL'
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import jwt
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'infosentinel_secret_key')
app.config['DEBUG'] = os.environ.get('DEBUG', 'True').lower() == 'true'

# Mock database
users_db = {
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin123'),
        'email': 'admin@infosentinel.net',
        'role': 'admin',
        'created_at': datetime.datetime.now().isoformat()
    }
}

scans_db = [
    {
        'id': str(uuid.uuid4()),
        'target': 'example.com',
        'type': 'Web Application',
        'status': 'completed',
        'start_time': (datetime.datetime.now() - datetime.timedelta(days=2)).isoformat(),
        'end_time': (datetime.datetime.now() - datetime.timedelta(days=2, hours=-1)).isoformat(),
        'vulnerabilities_count': 12
    },
    {
        'id': str(uuid.uuid4()),
        'target': '192.168.1.0/24',
        'type': 'Network',
        'status': 'completed',
        'start_time': (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat(),
        'end_time': (datetime.datetime.now() - datetime.timedelta(days=1, hours=-2)).isoformat(),
        'vulnerabilities_count': 5
    },
    {
        'id': str(uuid.uuid4()),
        'target': 'api.example.org',
        'type': 'API',
        'status': 'in_progress',
        'start_time': datetime.datetime.now().isoformat(),
        'end_time': None,
        'vulnerabilities_count': 3
    }
]

vulnerabilities_db = [
    {
        'id': str(uuid.uuid4()),
        'scan_id': scans_db[0]['id'],
        'name': 'SQL Injection',
        'description': 'SQL injection vulnerability in login form',
        'severity': 'high',
        'cvss_score': 8.5,
        'remediation': 'Use parameterized queries or prepared statements'
    },
    {
        'id': str(uuid.uuid4()),
        'scan_id': scans_db[0]['id'],
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Reflected XSS in search functionality',
        'severity': 'medium',
        'cvss_score': 6.1,
        'remediation': 'Implement proper input validation and output encoding'
    },
    {
        'id': str(uuid.uuid4()),
        'scan_id': scans_db[1]['id'],
        'name': 'Open SSH Port',
        'description': 'SSH port open on multiple hosts',
        'severity': 'low',
        'cvss_score': 3.8,
        'remediation': 'Restrict SSH access to authorized IPs only'
    }
]

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Token is missing'
            }), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_db.get(data['username'])
            
            if not current_user:
                raise Exception('User not found')
                
        except Exception as e:
            return jsonify({
                'success': False,
                'message': 'Token is invalid or expired'
            }), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'message': 'InfoSentinel API is running'
    })

# Serve frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'message': 'No data provided'
        }), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({
            'success': False,
            'message': 'Missing username or password'
        }), 400
    
    user = users_db.get(username)
    
    if not user or not check_password_hash(user['password'], password):
        return jsonify({
            'success': False,
            'message': 'Invalid credentials'
        }), 401
    
    # Generate token
    token = jwt.encode({
        'username': user['username'],
        'exp': datetime.datetime.now() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': token,
        'user': {
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'created_at': user['created_at']
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'message': 'No data provided'
        }), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({
            'success': False,
            'message': 'Missing required fields'
        }), 400
    
    if username in users_db:
        return jsonify({
            'success': False,
            'message': 'Username already exists'
        }), 400
    
    # Check if email already exists
    for user in users_db.values():
        if user['email'] == email:
            return jsonify({
                'success': False,
                'message': 'Email already exists'
            }), 400
    
    # Create new user
    users_db[username] = {
        'username': username,
        'password': generate_password_hash(password),
        'email': email,
        'role': 'user',
        'created_at': datetime.datetime.now().isoformat()
    }
    
    return jsonify({
        'success': True,
        'message': 'Registration successful'
    })

# User profile endpoint
@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'success': True,
        'user': {
            'username': current_user['username'],
            'email': current_user['email'],
            'role': current_user['role'],
            'created_at': current_user['created_at']
        }
    })

# Dashboard statistics endpoint
@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Calculate statistics
    total_scans = len(scans_db)
    total_vulnerabilities = len(vulnerabilities_db)
    
    severity_counts = {
        'high': sum(1 for v in vulnerabilities_db if v['severity'] == 'high'),
        'medium': sum(1 for v in vulnerabilities_db if v['severity'] == 'medium'),
        'low': sum(1 for v in vulnerabilities_db if v['severity'] == 'low')
    }
    
    return jsonify({
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'severity_counts': severity_counts,
        'recent_scans': scans_db
    })

# Scans endpoints
@app.route('/api/scans', methods=['GET'])
@token_required
def get_scans(current_user):
    return jsonify({
        'success': True,
        'scans': scans_db
    })

@app.route('/api/scans/<scan_id>', methods=['GET'])
@token_required
def get_scan(current_user, scan_id):
    scan = next((s for s in scans_db if s['id'] == scan_id), None)
    
    if not scan:
        return jsonify({
            'success': False,
            'message': 'Scan not found'
        }), 404
    
    # Get vulnerabilities for this scan
    scan_vulnerabilities = [v for v in vulnerabilities_db if v['scan_id'] == scan_id]
    
    return jsonify({
        'success': True,
        'scan': scan,
        'vulnerabilities': scan_vulnerabilities
    })

@app.route('/api/scans', methods=['POST'])
@token_required
def create_scan(current_user):
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'message': 'No data provided'
        }), 400
    
    target = data.get('target')
    scan_type = data.get('type')
    
    if not target or not scan_type:
        return jsonify({
            'success': False,
            'message': 'Missing required fields'
        }), 400
    
    # Create new scan
    new_scan = {
        'id': str(uuid.uuid4()),
        'target': target,
        'type': scan_type,
        'status': 'pending',
        'start_time': datetime.datetime.now().isoformat(),
        'end_time': None,
        'vulnerabilities_count': 0
    }
    
    scans_db.append(new_scan)
    
    return jsonify({
        'success': True,
        'message': 'Scan created successfully',
        'scan': new_scan
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
EOL

echo "===== Deployment Complete ====="
echo "The InfoSentinel platform has been deployed to: $DEPLOY_DIR"
echo "To start the platform, run: cd $DEPLOY_DIR && ./start.sh"
echo "Then access the platform at: http://localhost:5001"