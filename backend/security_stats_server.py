from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import random
import time
import datetime
import json
import uuid
import threading
import logging
from auth import authenticate_user, generate_token, token_required, role_required
from vulnerability_service import VulnerabilityService
from notification_service import NotificationService

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('security_stats_server')

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize services
vulnerability_service = VulnerabilityService()
notification_service = NotificationService()

# Mock data for security statistics
security_stats = {
    "totalScans": 1248,
    "criticalVulnerabilities": 37,
    "scansRunning": 5,
    "successRate": 94.7,
    "securityScore": 85.3  # Added security score for charts
}

# Historical data storage
historical_data = {
    "scans": [],
    "vulnerabilities": {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    },
    "successRate": [],
    "securityScore": []
}

# Store security events for incident simulation
security_events = []

# Active scans simulation
active_scans = []

# Simulate changing data over time
last_update = time.time()
last_historical_update = time.time() - 3600  # Start with data from an hour ago

def generate_historical_data():
    """Generate historical data for charts"""
    global historical_data, security_stats
    
    # Clear existing data
    historical_data = {
        "scans": [],
        "vulnerabilities": {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        },
        "successRate": [],
        "securityScore": []
    }
    
    # Generate 90 days of data (for maximum time range)
    now = datetime.datetime.now()
    base_total_scans = security_stats["totalScans"] - 500  # Start from a lower number
    
    for i in range(90, 0, -1):
        date = now - datetime.timedelta(days=i)
        date_str = date.isoformat()
        
        # Calculate daily values with some randomness but following a trend
        day_factor = (90 - i) / 90  # 0 to 1 factor representing progress through time
        
        # Scans - gradually increasing trend
        daily_scans = int(base_total_scans / 90 * (90 - i) * (0.8 + 0.4 * random.random()))
        daily_web_scans = int(daily_scans * (0.4 + 0.2 * random.random()))
        daily_network_scans = int(daily_scans * (0.3 + 0.2 * random.random()))
        daily_system_scans = daily_scans - daily_web_scans - daily_network_scans
        
        historical_data["scans"].append({
            "date": date_str,
            "total": daily_scans,
            "web": daily_web_scans,
            "network": daily_network_scans,
            "system": daily_system_scans
        })
        
        # Vulnerabilities - fluctuating with occasional spikes
        base_critical = max(1, int(security_stats["criticalVulnerabilities"] * 0.8 * day_factor))
        critical_vulns = max(0, int(base_critical * (0.7 + 0.6 * random.random())))
        # Add occasional spikes
        if random.random() < 0.1:  # 10% chance of a spike
            critical_vulns += random.randint(1, 5)
            
        high_vulns = int(critical_vulns * (1.2 + 0.8 * random.random()))
        medium_vulns = int(high_vulns * (1.5 + 0.5 * random.random()))
        low_vulns = int(medium_vulns * (1.5 + 0.5 * random.random()))
        
        historical_data["vulnerabilities"]["critical"].append({
            "date": date_str,
            "count": critical_vulns
        })
        
        historical_data["vulnerabilities"]["high"].append({
            "date": date_str,
            "count": high_vulns
        })
        
        historical_data["vulnerabilities"]["medium"].append({
            "date": date_str,
            "count": medium_vulns
        })
        
        historical_data["vulnerabilities"]["low"].append({
            "date": date_str,
            "count": low_vulns
        })
        
        # Success rate - generally high with occasional dips
        base_success_rate = 92 + 8 * day_factor  # Improving over time from 92% to 100%
        daily_success_rate = max(80, min(100, base_success_rate * (0.97 + 0.06 * random.random())))
        # Add occasional dips
        if random.random() < 0.08:  # 8% chance of a dip
            daily_success_rate -= random.uniform(5, 15)
            
        historical_data["successRate"].append({
            "date": date_str,
            "rate": round(daily_success_rate, 1)
        })
        
        # Security score - gradually improving with fluctuations
        base_score = 70 + 25 * day_factor  # Improving over time from 70 to 95
        daily_score = max(60, min(98, base_score * (0.95 + 0.1 * random.random())))
        # Add some wave pattern
        daily_score += 5 * math.sin(i / 10)
        
        historical_data["securityScore"].append({
            "date": date_str,
            "score": round(daily_score, 1)
        })

@app.route('/api/security-stats', methods=['GET'])
def get_security_stats():
    """
    Get current security statistics
    Returns dynamic security statistics that change over time
    """
    global security_stats, last_update
    
    # Update stats with some random variations every few seconds
    current_time = time.time()
    if current_time - last_update > 5:  # Update every 5 seconds
        # Simulate changing data
        security_stats["totalScans"] += random.randint(0, 3)
        security_stats["criticalVulnerabilities"] = max(0, security_stats["criticalVulnerabilities"] + 
                                                     random.choice([-1, 0, 0, 1]))
        security_stats["scansRunning"] = max(0, min(10, security_stats["scansRunning"] + 
                                                 random.choice([-1, 0, 1])))
        security_stats["successRate"] = round(min(100, max(90, security_stats["successRate"] + 
                                                       random.choice([-0.2, -0.1, 0, 0.1, 0.2]))), 1)
        
        last_update = current_time
    
    return jsonify(security_stats)

@app.route('/api/security-stats/history', methods=['GET'])
def get_historical_stats():
    """
    Get historical security statistics for charts
    Supports time range filtering
    """
    global historical_data, last_historical_update
    
    # Generate historical data if it doesn't exist or needs refresh
    current_time = time.time()
    if not historical_data["scans"] or current_time - last_historical_update > 3600:  # Refresh every hour
        try:
            import math  # Import here to avoid issues if not used
            generate_historical_data()
            last_historical_update = current_time
        except Exception as e:
            print(f"Error generating historical data: {e}")
            # If generation fails, return empty data
            return jsonify({"error": "Failed to generate historical data"}), 500
    
    # Get time range from query parameter
    time_range = request.args.get('range', '7d')
    
    # Filter data based on time range
    filtered_data = filter_data_by_range(time_range)
    
    return jsonify(filtered_data)

def filter_data_by_range(time_range):
    """Filter historical data based on time range"""
    global historical_data
    
    now = datetime.datetime.now()
    
    # Determine cutoff date based on time range
    if time_range == '24h':
        cutoff = now - datetime.timedelta(hours=24)
        # For 24h, we need hourly data which we don't have in our mock data
        # So we'll generate some random hourly data based on the latest day
        return generate_hourly_data()
    elif time_range == '7d':
        cutoff = now - datetime.timedelta(days=7)
    elif time_range == '30d':
        cutoff = now - datetime.timedelta(days=30)
    elif time_range == '90d':
        cutoff = now - datetime.timedelta(days=90)
    else:
        cutoff = now - datetime.timedelta(days=7)  # Default to 7 days
    
    cutoff_str = cutoff.isoformat()
    
    # Filter all data sets
    filtered_data = {
        "scans": [item for item in historical_data["scans"] if item["date"] >= cutoff_str],
        "vulnerabilities": {
            "critical": [item for item in historical_data["vulnerabilities"]["critical"] if item["date"] >= cutoff_str],
            "high": [item for item in historical_data["vulnerabilities"]["high"] if item["date"] >= cutoff_str],
            "medium": [item for item in historical_data["vulnerabilities"]["medium"] if item["date"] >= cutoff_str],
            "low": [item for item in historical_data["vulnerabilities"]["low"] if item["date"] >= cutoff_str]
        },
        "successRate": [item for item in historical_data["successRate"] if item["date"] >= cutoff_str],
        "securityScore": [item for item in historical_data["securityScore"] if item["date"] >= cutoff_str]
    }
    
    return filtered_data

def generate_hourly_data():
    """Generate hourly data for 24h view"""
    now = datetime.datetime.now()
    hourly_data = {
        "scans": [],
        "vulnerabilities": {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        },
        "successRate": [],
        "securityScore": []
    }
    
    # Use the latest day's data as a base
    if historical_data["scans"]:
        latest_scans = historical_data["scans"][-1]["total"]
        latest_critical = historical_data["vulnerabilities"]["critical"][-1]["count"]
        latest_high = historical_data["vulnerabilities"]["high"][-1]["count"]
        latest_medium = historical_data["vulnerabilities"]["medium"][-1]["count"]
        latest_low = historical_data["vulnerabilities"]["low"][-1]["count"]
        latest_success_rate = historical_data["successRate"][-1]["rate"]
        latest_security_score = historical_data["securityScore"][-1]["score"]
        
        # Generate 24 hours of data
        for i in range(24, 0, -1):
            hour = now - datetime.timedelta(hours=i)
            hour_str = hour.isoformat()
            
            # Add some hourly variation
            hourly_factor = 0.7 + 0.6 * random.random()
            hour_of_day_factor = 0.5 + 0.5 * math.sin((hour.hour - 6) * math.pi / 12)  # Peak at noon
            
            # Scans - more during business hours
            hourly_scans = max(1, int(latest_scans / 24 * hourly_factor * hour_of_day_factor * 1.5))
            hourly_web_scans = int(hourly_scans * 0.5)
            hourly_network_scans = int(hourly_scans * 0.3)
            hourly_system_scans = hourly_scans - hourly_web_scans - hourly_network_scans
            
            hourly_data["scans"].append({
                "date": hour_str,
                "total": hourly_scans,
                "web": hourly_web_scans,
                "network": hourly_network_scans,
                "system": hourly_system_scans
            })
            
            # Vulnerabilities - more likely to be found during active scanning hours
            hourly_critical = max(0, int(latest_critical / 24 * hourly_factor * hour_of_day_factor))
            hourly_high = max(0, int(latest_high / 24 * hourly_factor * hour_of_day_factor))
            hourly_medium = max(0, int(latest_medium / 24 * hourly_factor * hour_of_day_factor))
            hourly_low = max(0, int(latest_low / 24 * hourly_factor * hour_of_day_factor))
            
            hourly_data["vulnerabilities"]["critical"].append({
                "date": hour_str,
                "count": hourly_critical
            })
            
            hourly_data["vulnerabilities"]["high"].append({
                "date": hour_str,
                "count": hourly_high
            })
            
            hourly_data["vulnerabilities"]["medium"].append({
                "date": hour_str,
                "count": hourly_medium
            })
            
            hourly_data["vulnerabilities"]["low"].append({
                "date": hour_str,
                "count": hourly_low
            })
            
            # Success rate - slight variations
            hourly_success_rate = max(80, min(100, latest_success_rate * (0.98 + 0.04 * random.random())))
            
            hourly_data["successRate"].append({
                "date": hour_str,
                "rate": round(hourly_success_rate, 1)
            })
            
            # Security score - slight variations
            hourly_security_score = max(60, min(98, latest_security_score * (0.98 + 0.04 * random.random())))
            
            hourly_data["securityScore"].append({
                "date": hour_str,
                "score": round(hourly_security_score, 1)
            })
    
    return hourly_data

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({"status": "healthy", "service": "InfoSentinel Stats API"})

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    user = authenticate_user(data.get('email'), data.get('password'))
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = generate_token(user['email'], user['role'])
    return jsonify({
        'token': token,
        'user': {
            'email': user['email'],
            'name': user['name'],
            'role': user['role']
        }
    })

# Vulnerability endpoints
@app.route('/api/vulnerabilities', methods=['GET'])
@token_required
def get_vulnerabilities():
    return vulnerability_service.get_all_vulnerabilities()

@app.route('/api/vulnerabilities/<vuln_id>', methods=['GET'])
@token_required
def get_vulnerability(vuln_id):
    return vulnerability_service.get_vulnerability_by_id(vuln_id)

@app.route('/api/vulnerabilities/<vuln_id>/status', methods=['PUT'])
@token_required
def update_vulnerability_status(vuln_id):
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({"error": "Status is required"}), 400
    return vulnerability_service.update_vulnerability_status(vuln_id, data['status'])

# Notification endpoints
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    return notification_service.get_all_notifications()

@app.route('/api/notifications/since/<notification_id>', methods=['GET'])
@token_required
def get_notifications_since(notification_id):
    return notification_service.get_notifications_since(notification_id)

@app.route('/api/notifications/<notification_id>/read', methods=['PUT'])
@token_required
def mark_notification_as_read(notification_id):
    return notification_service.mark_as_read(notification_id)

@app.route('/api/notifications/read/all', methods=['PUT'])
@token_required
def mark_all_notifications_as_read():
    return notification_service.mark_all_as_read()

@app.route('/api/notifications/clear', methods=['DELETE'])
@token_required
def clear_all_notifications():
    return notification_service.clear_all_notifications()

# Endpoint to generate a new notification (for testing)
@app.route('/api/notifications/generate', methods=['POST'])
@token_required
def generate_notification():
    notification = notification_service.generate_new_notification()
    return jsonify(notification)

if __name__ == '__main__':
    # Initialize historical data
    try:
        import math
        generate_historical_data()
    except Exception as e:
        print(f"Warning: Could not generate initial historical data: {e}")
    
    print("Starting InfoSentinel Security Stats API...")
    print("API available at: http://localhost:5002/api/security-stats")
    print("Historical data available at: http://localhost:5002/api/security-stats/history")
    app.run(host='0.0.0.0', port=5002, debug=True)