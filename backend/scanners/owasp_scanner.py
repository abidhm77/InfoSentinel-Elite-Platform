"""
OWASP Top 10 vulnerability scanner module.
Implements professional-grade web application security testing based on OWASP Top 10.
"""
import threading
import requests
import re
import json
import time
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from database.db import get_db

class OWASPScanner:
    """Scanner for OWASP Top 10 vulnerabilities."""
    
    def __init__(self):
        """Initialize the OWASP scanner."""
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'InfoSentinel Security Scanner/1.0'
        })
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start an OWASP Top 10 scan in a separate thread.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target URL to scan
            options: Additional scan options
        """
        # Update scan status to running
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"status": "running", "start_time": datetime.utcnow()}}
        )
        
        # Start scan in a separate thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, options)
        )
        thread.daemon = True
        thread.start()
    
    def _run_scan(self, scan_id, target, options=None):
        """
        Run the actual OWASP Top 10 scan process.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target URL to scan
            options: Additional scan options
        """
        try:
            db = get_db()
            results = []
            
            # Validate target URL
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            
            # A1:2021 - Broken Access Control
            access_control_results = self._check_broken_access_control(target)
            results.extend(access_control_results)
            
            # A2:2021 - Cryptographic Failures
            crypto_results = self._check_cryptographic_failures(target)
            results.extend(crypto_results)
            
            # A3:2021 - Injection
            injection_results = self._check_injection(target)
            results.extend(injection_results)
            
            # A7:2021 - Identification and Authentication Failures
            auth_results = self._check_auth_failures(target)
            results.extend(auth_results)
            
            # A9:2021 - Security Logging and Monitoring Failures
            logging_results = self._check_logging_failures(target)
            results.extend(logging_results)
            
            # Update scan results in database
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "completed",
                        "end_time": datetime.utcnow(),
                        "results": results
                    }
                }
            )
            
        except Exception as e:
            # Update scan status to failed
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "failed",
                        "end_time": datetime.utcnow(),
                        "error": str(e)
                    }
                }
            )
    
    def _check_broken_access_control(self, target):
        """Check for broken access control vulnerabilities."""
        results = []
        
        try:
            # Test for directory traversal
            traversal_paths = ['../../../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd']
            for path in traversal_paths:
                test_url = f"{target}/{path}"
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                if 'root:' in response.text and 'bash' in response.text:
                    results.append({
                        "type": "broken_access_control",
                        "severity": "high",
                        "title": "Directory Traversal Vulnerability",
                        "description": f"The application is vulnerable to directory traversal attacks at {test_url}",
                        "remediation": "Implement proper input validation and use a whitelist approach for file access."
                    })
            
            # Test for insecure direct object references
            admin_paths = ['/admin', '/administrator', '/adminpanel', '/dashboard', '/control']
            for path in admin_paths:
                test_url = urljoin(target, path)
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200 and ('admin' in response.text.lower() or 'dashboard' in response.text.lower()):
                    results.append({
                        "type": "broken_access_control",
                        "severity": "medium",
                        "title": "Potential Admin Interface Exposed",
                        "description": f"Admin interface potentially accessible without authentication at {test_url}",
                        "remediation": "Implement proper authentication and authorization for administrative interfaces."
                    })
        
        except Exception as e:
            results.append({
                "type": "error",
                "severity": "info",
                "title": "Access Control Check Error",
                "description": f"Error during access control checks: {str(e)}",
                "remediation": "N/A"
            })
        
        return results
    
    def _check_cryptographic_failures(self, target):
        """Check for cryptographic failures."""
        results = []
        
        try:
            parsed_url = urlparse(target)
            
            # Check if HTTPS is used
            if parsed_url.scheme != 'https':
                results.append({
                    "type": "crypto_failure",
                    "severity": "high",
                    "title": "Insecure Transport Protocol",
                    "description": "The application uses HTTP instead of HTTPS",
                    "remediation": "Implement HTTPS across the entire application with proper certificate configuration."
                })
            else:
                # Check for weak SSL/TLS configuration
                # This is a simplified check - in a real scanner, you'd use tools like sslyze
                try:
                    response = requests.get(target, verify=True, timeout=10)
                    if 'Strict-Transport-Security' not in response.headers:
                        results.append({
                            "type": "crypto_failure",
                            "severity": "medium",
                            "title": "Missing HTTP Strict Transport Security",
                            "description": "HSTS header is not set, which may allow downgrade attacks",
                            "remediation": "Add the Strict-Transport-Security header with appropriate values."
                        })
                except requests.exceptions.SSLError:
                    results.append({
                        "type": "crypto_failure",
                        "severity": "high",
                        "title": "SSL/TLS Configuration Issue",
                        "description": "The server has SSL/TLS configuration issues",
                        "remediation": "Update SSL/TLS configuration to use secure protocols and ciphers."
                    })
        
        except Exception as e:
            results.append({
                "type": "error",
                "severity": "info",
                "title": "Cryptographic Check Error",
                "description": f"Error during cryptographic checks: {str(e)}",
                "remediation": "N/A"
            })
        
        return results
    
    def _check_injection(self, target):
        """Check for injection vulnerabilities."""
        results = []
        
        try:
            # SQL Injection test
            sql_payloads = ["' OR '1'='1", "1' OR '1'='1", "' OR 1=1--", "admin'--"]
            forms = self._get_forms(target)
            
            for form in forms:
                for payload in sql_payloads:
                    data = {}
                    for input_field in form.get('inputs', []):
                        if input_field['type'] in ['text', 'password', 'hidden']:
                            data[input_field['name']] = payload
                    
                    if data:
                        try:
                            if form['method'].lower() == 'post':
                                response = self.session.post(form['action'], data=data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=data, timeout=10)
                            
                            # Check for SQL error messages
                            sql_errors = [
                                'SQL syntax', 'mysql_fetch_array', 'mysqli_fetch_array',
                                'ORA-', 'Oracle error', 'PostgreSQL', 'SQLite3::'
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    results.append({
                                        "type": "injection",
                                        "severity": "high",
                                        "title": "SQL Injection Vulnerability",
                                        "description": f"Potential SQL injection in form at {form['action']}",
                                        "remediation": "Use parameterized queries or prepared statements. Implement input validation and sanitization."
                                    })
                                    break
                        except Exception:
                            pass
            
            # XSS test
            xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            for form in forms:
                for payload in xss_payloads:
                    data = {}
                    for input_field in form.get('inputs', []):
                        if input_field['type'] in ['text', 'search', 'url', 'email']:
                            data[input_field['name']] = payload
                    
                    if data:
                        try:
                            if form['method'].lower() == 'post':
                                response = self.session.post(form['action'], data=data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=data, timeout=10)
                            
                            if payload in response.text:
                                results.append({
                                    "type": "injection",
                                    "severity": "high",
                                    "title": "Cross-Site Scripting (XSS) Vulnerability",
                                    "description": f"Potential XSS vulnerability in form at {form['action']}",
                                    "remediation": "Implement proper output encoding and input validation. Consider using Content-Security-Policy."
                                })
                                break
                        except Exception:
                            pass
        
        except Exception as e:
            results.append({
                "type": "error",
                "severity": "info",
                "title": "Injection Check Error",
                "description": f"Error during injection checks: {str(e)}",
                "remediation": "N/A"
            })
        
        return results
    
    def _check_auth_failures(self, target):
        """Check for authentication and identification failures."""
        results = []
        
        try:
            # Check for login rate limiting
            login_paths = ['/login', '/signin', '/user/login', '/account/login']
            login_found = False
            
            for path in login_paths:
                login_url = urljoin(target, path)
                response = self.session.get(login_url, timeout=10)
                
                if response.status_code == 200 and ('login' in response.text.lower() or 'password' in response.text.lower()):
                    login_found = True
                    forms = self._get_forms(login_url)
                    
                    if forms:
                        form = forms[0]
                        data = {}
                        for input_field in form.get('inputs', []):
                            if input_field['type'] == 'text' or input_field['type'] == 'email':
                                data[input_field['name']] = 'test@example.com'
                            elif input_field['type'] == 'password':
                                data[input_field['name']] = 'wrongpassword'
                        
                        # Try multiple login attempts
                        if data:
                            rate_limited = False
                            for _ in range(5):
                                try:
                                    if form['method'].lower() == 'post':
                                        response = self.session.post(form['action'], data=data, timeout=10)
                                    else:
                                        response = self.session.get(form['action'], params=data, timeout=10)
                                    
                                    if response.status_code == 429 or 'rate limit' in response.text.lower() or 'too many attempts' in response.text.lower():
                                        rate_limited = True
                                        break
                                    
                                    time.sleep(1)  # Small delay between attempts
                                except Exception:
                                    break
                            
                            if not rate_limited:
                                results.append({
                                    "type": "auth_failure",
                                    "severity": "high",
                                    "title": "Missing Brute Force Protection",
                                    "description": f"The login form at {login_url} does not implement rate limiting or account lockout",
                                    "remediation": "Implement rate limiting, account lockout, and CAPTCHA after failed login attempts."
                                })
                    
                    break
            
            if not login_found:
                results.append({
                    "type": "info",
                    "severity": "info",
                    "title": "Login Form Not Found",
                    "description": "Could not locate a login form to test for authentication vulnerabilities",
                    "remediation": "N/A"
                })
            
            # Check for secure password policy
            # This would typically involve checking registration forms or password reset functionality
            
        except Exception as e:
            results.append({
                "type": "error",
                "severity": "info",
                "title": "Authentication Check Error",
                "description": f"Error during authentication checks: {str(e)}",
                "remediation": "N/A"
            })
        
        return results
    
    def _check_logging_failures(self, target):
        """Check for security logging and monitoring failures."""
        # This is a placeholder - real implementation would require more complex testing
        results = []
        
        results.append({
            "type": "logging",
            "severity": "medium",
            "title": "Security Logging Assessment",
            "description": "Manual review recommended to assess logging and monitoring capabilities",
            "remediation": "Implement comprehensive logging for security events, authentication attempts, and sensitive operations."
        })
        
        return results
    
    def _get_forms(self, url):
        """Extract forms from a web page."""
        forms = []
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get'),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
        except Exception:
            pass
        
        return forms