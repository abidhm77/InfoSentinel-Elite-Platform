from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import os
import sys
import jwt
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', template_folder='../backend/templates')
CORS(app)

# Import reporting module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))
try:
    from reporting.report_generator import ReportGenerator
    from scanners.scanner_factory import ScannerFactory
    from ai_api import ai_api  # Import the AI API blueprint
    from quantum_api import quantum_api  # Import the Quantum API blueprint
except ImportError:
    print("Warning: Could not import reporting modules. Some features may be limited.")

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'infosentinel_secret_key')
app.config['DEBUG'] = os.environ.get('DEBUG', 'True').lower() == 'true'

# Register the API blueprints
try:
    app.register_blueprint(ai_api)
    app.register_blueprint(quantum_api)
    print("API endpoints registered successfully")
except NameError:
    print("Warning: Could not register API endpoints")

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

# Report generation endpoints
@app.route('/api/reports/<scan_id>', methods=['GET'])
def generate_report(scan_id):
    """Generate a security report for a specific scan"""
    report_type = request.args.get('type', 'standard')
    
    # Find the scan in our mock database
    scan = None
    for s in scans_db:
        if s['id'] == scan_id:
            scan = s
            break
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Mock vulnerabilities for the report
    vulnerabilities = [
        {
            'id': str(uuid.uuid4()),
            'name': 'SQL Injection',
            'description': 'SQL injection vulnerability in login form',
            'severity': 'high',
            'cvss_score': 8.5,
            'location': '/login.php',
            'remediation': 'Use parameterized queries or prepared statements',
            'references': ['https://owasp.org/www-community/attacks/SQL_Injection'],
            'owasp_category': 'A1:2021-Injection'
        },
        {
            'id': str(uuid.uuid4()),
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Reflected XSS in search parameter',
            'severity': 'medium',
            'cvss_score': 6.1,
            'location': '/search?q=',
            'remediation': 'Implement proper output encoding and Content-Security-Policy',
            'references': ['https://owasp.org/www-community/attacks/xss/'],
            'owasp_category': 'A3:2021-Cross-Site Scripting'
        },
        {
            'id': str(uuid.uuid4()),
            'name': 'Missing HTTP Security Headers',
            'description': 'The application is missing important security headers',
            'severity': 'low',
            'cvss_score': 3.7,
            'location': 'HTTP Headers',
            'remediation': 'Add security headers like Content-Security-Policy, X-XSS-Protection',
            'references': ['https://owasp.org/www-project-secure-headers/'],
            'owasp_category': 'A5:2021-Security Misconfiguration'
        }
    ]
    
    try:
        # Initialize report generator
        report_generator = ReportGenerator()
        
        # Generate appropriate report based on type
        if report_type == 'executive':
            return render_template('executive_report.html', 
                                  scan=scan, 
                                  vulnerabilities=vulnerabilities,
                                  report_date=datetime.datetime.now().strftime('%Y-%m-%d'),
                                  risk_score=7.2)
        
        elif report_type == 'compliance':
            return render_template('compliance_report.html', 
                                  scan=scan, 
                                  vulnerabilities=vulnerabilities,
                                  report_date=datetime.datetime.now().strftime('%Y-%m-%d'),
                                  compliance_score=68)
        
        else:  # standard report
            return render_template('standard_report.html', 
                                  scan=scan, 
                                  vulnerabilities=vulnerabilities,
                                  report_date=datetime.datetime.now().strftime('%Y-%m-%d'),
                                  risk_score=7.2)
    except Exception as e:
        # Fallback if report generator is not available
        return jsonify({
            'scan': scan,
            'vulnerabilities': vulnerabilities,
            'report_type': report_type,
            'error': str(e)
        })

# Serve frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
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

# Import vulnerability agent
try:
    from vulnerability_agent import VulnerabilityAgent
except ImportError:
    print("Warning: Could not import VulnerabilityAgent")

@app.route('/api/scan/start', methods=['POST'])
@token_required
def start_vulnerability_scan(current_user):
    """Start a comprehensive vulnerability scan"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing target URL'}), 400
    
    target_url = data.get('url')
    scan_type = data.get('type', 'comprehensive')
    
    # Create unique scan ID
    scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Initialize AI agent with config
        agent_config = {
            'verify_ssl': data.get('verify_ssl', False),
            'timeout': data.get('timeout', 30)
        }
        agent = VulnerabilityAgent(agent_config)
        
        # Run vulnerability scan using available methods
        findings = []
        
        # Basic URL scan
        url_findings = agent.scan_url(target_url)
        findings.extend(url_findings)
        
        # Parameter scan if parameters provided
        if 'parameters' in data:
            param_findings = agent.scan_parameters(target_url, data['parameters'])
            findings.extend(param_findings)
        
        # Convert findings to JSON for database storage
        results = []
        for finding in findings:
            results.append({
                'id': finding.id if hasattr(finding, 'id') else str(uuid.uuid4()),
                'vulnerability_type': finding.vulnerability_type.value if hasattr(finding, 'vulnerability_type') else finding.type.value,
                'severity': finding.severity.value,
                'title': finding.title if hasattr(finding, 'title') else f"{finding.type.value} detected",
                'description': finding.description,
                'location': finding.location,
                'payload': finding.payload if hasattr(finding, 'payload') else '',
                'evidence': finding.evidence,
                'cvss_score': finding.cvss_score if hasattr(finding, 'cvss_score') else 5.0,
                'remediation': finding.remediation if hasattr(finding, 'remediation') else 'Review and fix vulnerability',
                'confidence': finding.confidence
            })
        
        # Store scan in database
        new_scan = {
            'id': scan_id,
            'target': target_url,
            'type': scan_type,
            'status': 'completed',
            'start_time': datetime.datetime.now().isoformat(),
            'end_time': datetime.datetime.now().isoformat(),
            'vulnerabilities_count': len(results),
            'created_by': current_user['username']
        }
        scans_db.append(new_scan)
        
        # Store vulnerabilities
        for result in results:
            result['scan_id'] = scan_id
            vulnerabilities_db.append(result)
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'completed',
            'findings_count': len(results),
            'findings': results,
            'scan_info': new_scan
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Scan failed: {str(e)}',
            'scan_id': scan_id,
            'status': 'failed'
        }), 500

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
@token_required
def get_scan_status(current_user, scan_id):
    """Get scan status and results"""
    # Find scan in database
    scan = next((s for s in scans_db if s['id'] == scan_id), None)
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Get vulnerabilities for this scan
    scan_vulnerabilities = [v for v in vulnerabilities_db if v.get('scan_id') == scan_id]
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan['status'],
        'progress': 100 if scan['status'] == 'completed' else 50,
        'target': scan['target'],
        'start_time': scan['start_time'],
        'end_time': scan.get('end_time'),
        'vulnerabilities_count': len(scan_vulnerabilities),
        'vulnerabilities': scan_vulnerabilities
    })

@app.route('/api/scan/quick', methods=['POST'])
@token_required
def quick_vulnerability_scan(current_user):
    """Quick vulnerability scan for immediate results"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing target URL'}), 400
    
    target_url = data.get('url')
    
    try:
        # Initialize agent for quick scan
        agent = VulnerabilityAgent({
            'verify_ssl': False,
            'timeout': 10  # Shorter timeout for quick scan
        })
        
        # Run quick scan with limited categories
        categories = data.get('categories', ['sql_injection', 'xss'])
        findings = agent.scan_url(target_url, categories=categories)
        
        # Convert findings to simple format
        results = []
        for finding in findings:
            results.append({
                'type': finding.type.value,
                'severity': finding.severity.value,
                'description': finding.description,
                'evidence': finding.evidence,
                'confidence': finding.confidence
            })
        
        return jsonify({
            'status': 'completed',
            'target': target_url,
            'findings_count': len(results),
            'findings': results
        })
        
    except Exception as e:
        return jsonify({'error': f'Quick scan failed: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
