"""Web application security testing module.
Implements professional-grade web application security testing with real tools integration.
"""
import threading
import requests
import re
import json
import time
import subprocess
import tempfile
import os
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs

from database.db import get_db

class WebAppScanner:
    """Scanner for web application security testing."""
    
    def __init__(self):
        """Initialize the web application scanner."""
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'InfoSentinel Professional Security Scanner/2.0'
        })
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start a web application security scan in a separate thread.
        
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
        
        # Return immediate feedback
        return {
            "scan_id": scan_id,
            "status": "running",
            "target": target,
            "message": "Advanced web application penetration test initiated",
            "estimated_time": self._estimate_scan_time(target, options)
        }
    
    def _run_comprehensive_scan(self, scan_id, target, config):
        """
        Run comprehensive web application security scan with real vulnerability detection.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target URL to scan
            config: Scan configuration options
        """
        try:
            from services.database_service import db_service
            
            # Phase 1: Information Gathering (10-30%)
            db_service.update_scan_status(scan_id, 'running', 15)
            self._information_gathering(scan_id, target)
            
            # Phase 2: Vulnerability Detection (30-70%)
            db_service.update_scan_status(scan_id, 'running', 40)
            self._detect_vulnerabilities(scan_id, target)
            
            # Phase 3: Security Headers Analysis (70-80%)
            db_service.update_scan_status(scan_id, 'running', 75)
            self._analyze_security_headers(scan_id, target)
            
            # Phase 4: SSL/TLS Analysis (80-90%)
            db_service.update_scan_status(scan_id, 'running', 85)
            self._analyze_ssl_tls(scan_id, target)
            
            # Phase 5: Final Analysis (90-100%)
            db_service.update_scan_status(scan_id, 'running', 95)
            self._final_analysis(scan_id, target)
            
            # Complete scan
            db_service.update_scan_status(scan_id, 'completed', 100)
            
        except Exception as e:
            print(f"Comprehensive scan error: {e}")
            db_service.update_scan_status(scan_id, 'failed', error_message=str(e))
    
    def _information_gathering(self, scan_id, target):
        """Gather information about the target application."""
        try:
            from services.database_service import db_service
            
            # Basic HTTP request to gather server information
            response = self.session.get(target, timeout=10, verify=False)
            
            # Analyze server headers
            if 'Server' in response.headers:
                server_info = response.headers['Server']
                db_service.add_vulnerability(
                    scan_id=scan_id,
                    title='Server Information Disclosure',
                    description=f'Server header reveals technology stack: {server_info}',
                    severity='low',
                    location='HTTP Headers',
                    remediation='Configure server to hide version information',
                    tool='web_scanner'
                )
            
            # Check for technology fingerprints
            self._detect_technologies(scan_id, target, response)
            
        except Exception as e:
            print(f"Information gathering error: {e}")
    
    def _detect_vulnerabilities(self, scan_id, target):
        """Detect common web application vulnerabilities."""
        try:
            from services.database_service import db_service
            
            # Test for XSS vulnerabilities
            self._test_xss(scan_id, target)
            
            # Test for SQL injection
            self._test_sql_injection(scan_id, target)
            
            # Test for directory traversal
            self._test_directory_traversal(scan_id, target)
            
            # Test for CSRF vulnerabilities
            self._test_csrf(scan_id, target)
            
            # Test for authentication bypass
            self._test_auth_bypass(scan_id, target)
            
        except Exception as e:
            print(f"Vulnerability detection error: {e}")
    
    def _test_xss(self, scan_id, target):
        """Test for Cross-Site Scripting vulnerabilities."""
        try:
            from services.database_service import db_service
            
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>'
            ]
            
            # Test common parameters
            test_params = ['q', 'search', 'query', 'input', 'data', 'value']
            
            for param in test_params:
                for payload in xss_payloads:
                    try:
                        test_url = f"{target}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5)
                        
                        if payload in response.text and 'text/html' in response.headers.get('content-type', ''):
                            db_service.add_vulnerability(
                                scan_id=scan_id,
                                title='Cross-Site Scripting (XSS)',
                                description=f'Reflected XSS vulnerability found in parameter: {param}',
                                severity='high',
                                cvss_score=7.5,
                                location=f'Parameter: {param}',
                                remediation='Implement proper input validation and output encoding',
                                tool='web_scanner'
                            )
                            break
                    except:
                        continue
                        
        except Exception as e:
            print(f"XSS testing error: {e}")
    
    def _test_sql_injection(self, scan_id, target):
        """Test for SQL injection vulnerabilities."""
        try:
            from services.database_service import db_service
            
            sql_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ]
            
            test_params = ['id', 'user', 'username', 'email', 'search', 'query']
            
            for param in test_params:
                for payload in sql_payloads:
                    try:
                        test_url = f"{target}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for SQL error indicators
                        sql_errors = [
                            'mysql_fetch_array',
                            'ORA-01756',
                            'Microsoft OLE DB Provider',
                            'PostgreSQL query failed',
                            'SQLite/JDBCDriver',
                            'sqlite_master'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                db_service.add_vulnerability(
                                    scan_id=scan_id,
                                    title='SQL Injection',
                                    description=f'SQL injection vulnerability found in parameter: {param}',
                                    severity='critical',
                                    cvss_score=9.8,
                                    location=f'Parameter: {param}',
                                    remediation='Use parameterized queries and input validation',
                                    tool='web_scanner'
                                )
                                return
                    except:
                        continue
                        
        except Exception as e:
            print(f"SQL injection testing error: {e}")
    
    def _analyze_security_headers(self, scan_id, target):
        """Analyze HTTP security headers."""
        try:
            from services.database_service import db_service
            
            response = self.session.get(target, timeout=10)
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-XSS-Protection': 'Enables XSS filtering in browsers',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Content-Security-Policy': 'Prevents XSS and data injection attacks',
                'Strict-Transport-Security': 'Enforces HTTPS connections',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    severity = 'high' if header in ['Content-Security-Policy', 'X-Frame-Options'] else 'medium'
                    cvss_score = 6.5 if severity == 'high' else 4.0
                    
                    db_service.add_vulnerability(
                        scan_id=scan_id,
                        title=f'Missing {header} Header',
                        description=f'The {header} security header is missing. {description}',
                        severity=severity,
                        cvss_score=cvss_score,
                        location='HTTP Response Headers',
                        remediation=f'Add {header} header with appropriate values',
                        tool='web_scanner'
                    )
                    
        except Exception as e:
            print(f"Security headers analysis error: {e}")
    
    def _analyze_ssl_tls(self, scan_id, target):
        """Analyze SSL/TLS configuration."""
        try:
            from services.database_service import db_service
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed_url = urlparse(target)
            if parsed_url.scheme != 'https':
                db_service.add_vulnerability(
                    scan_id=scan_id,
                    title='Unencrypted HTTP Connection',
                    description='The application does not use HTTPS encryption',
                    severity='high',
                    cvss_score=7.0,
                    location='Transport Layer',
                    remediation='Implement HTTPS with proper SSL/TLS configuration',
                    tool='web_scanner'
                )
                return
            
            # Test SSL/TLS configuration
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check for weak ciphers
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        db_service.add_vulnerability(
                            scan_id=scan_id,
                            title='Weak SSL/TLS Cipher',
                            description=f'Weak cipher suite detected: {cipher[0]}',
                            severity='medium',
                            cvss_score=5.0,
                            location='SSL/TLS Configuration',
                            remediation='Configure strong cipher suites and disable weak ones',
                            tool='web_scanner'
                        )
                        
        except Exception as e:
            print(f"SSL/TLS analysis error: {e}")
    
    def _final_analysis(self, scan_id, target):
        """Perform final security analysis."""
        try:
            from services.database_service import db_service
            
            # Check for common security misconfigurations
            self._check_common_files(scan_id, target)
            self._check_http_methods(scan_id, target)
            
        except Exception as e:
            print(f"Final analysis error: {e}")
    
    def _check_common_files(self, scan_id, target):
        """Check for common sensitive files."""
        try:
            from services.database_service import db_service
            
            common_files = [
                '/robots.txt',
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/admin',
                '/phpmyadmin',
                '/.git/config',
                '/backup.sql',
                '/database.sql'
            ]
            
            for file_path in common_files:
                try:
                    test_url = urljoin(target, file_path)
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code == 200 and len(response.text) > 0:
                        severity = 'critical' if file_path in ['/.env', '/config.php', '/.git/config'] else 'medium'
                        cvss_score = 8.5 if severity == 'critical' else 5.0
                        
                        db_service.add_vulnerability(
                            scan_id=scan_id,
                            title='Sensitive File Exposure',
                            description=f'Sensitive file accessible: {file_path}',
                            severity=severity,
                            cvss_score=cvss_score,
                            location=file_path,
                            remediation='Remove or restrict access to sensitive files',
                            tool='web_scanner'
                        )
                except:
                    continue
                    
        except Exception as e:
            print(f"Common files check error: {e}")
    
    def _detect_technologies(self, scan_id, target, response):
        """Detect technologies used by the target application."""
        try:
            from services.database_service import db_service
            
            # Check for common technology indicators
            technologies = []
            
            # Check response headers for technology fingerprints
            headers = response.headers
            
            # Server technology detection
            if 'Server' in headers:
                server = headers['Server'].lower()
                if 'apache' in server:
                    technologies.append('Apache HTTP Server')
                elif 'nginx' in server:
                    technologies.append('Nginx')
                elif 'iis' in server:
                    technologies.append('Microsoft IIS')
            
            # Framework detection from headers
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By'].lower()
                if 'php' in powered_by:
                    technologies.append('PHP')
                elif 'asp.net' in powered_by:
                    technologies.append('ASP.NET')
            
            # Content-based technology detection
            content = response.text.lower()
            
            # JavaScript frameworks
            if 'jquery' in content:
                technologies.append('jQuery')
            if 'angular' in content:
                technologies.append('AngularJS')
            if 'react' in content:
                technologies.append('React')
            if 'vue' in content:
                technologies.append('Vue.js')
            
            # CMS detection
            if 'wp-content' in content or 'wordpress' in content:
                technologies.append('WordPress')
            if 'drupal' in content:
                technologies.append('Drupal')
            if 'joomla' in content:
                technologies.append('Joomla')
            
            # Log detected technologies as informational findings
            if technologies:
                tech_list = ', '.join(technologies)
                db_service.add_vulnerability(
                    scan_id=scan_id,
                    title='Technology Stack Detection',
                    description=f'Detected technologies: {tech_list}',
                    severity='low',
                    location='Application Stack',
                    remediation='Consider hiding version information and technology stack details',
                    tool='web_scanner'
                )
                
        except Exception as e:
            print(f"Technology detection error: {e}")
    
    def _test_directory_traversal(self, scan_id, target):
        """Test for directory traversal vulnerabilities."""
        try:
            from services.database_service import db_service
            
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd'
            ]
            
            test_params = ['file', 'path', 'page', 'include', 'doc', 'document']
            
            for param in test_params:
                for payload in traversal_payloads:
                    try:
                        test_url = f"{target}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for directory traversal indicators
                        traversal_indicators = [
                            'root:x:0:0:',
                            '[boot loader]',
                            'Windows Registry Editor',
                            '/bin/bash',
                            '/bin/sh'
                        ]
                        
                        for indicator in traversal_indicators:
                            if indicator in response.text:
                                db_service.add_vulnerability(
                                    scan_id=scan_id,
                                    title='Directory Traversal',
                                    description=f'Directory traversal vulnerability found in parameter: {param}',
                                    severity='high',
                                    cvss_score=7.5,
                                    location=f'Parameter: {param}',
                                    remediation='Implement proper input validation and file access controls',
                                    tool='web_scanner'
                                )
                                return
                    except:
                        continue
                        
        except Exception as e:
            print(f"Directory traversal testing error: {e}")
    
    def _test_csrf(self, scan_id, target):
        """Test for CSRF vulnerabilities."""
        try:
            from services.database_service import db_service
            from bs4 import BeautifulSoup
            
            # Get the main page to find forms
            response = self.session.get(target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            csrf_protected = 0
            total_forms = len(forms)
            
            for form in forms:
                # Check for CSRF tokens
                csrf_tokens = form.find_all('input', {'name': ['csrf_token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']})
                
                if csrf_tokens:
                    csrf_protected += 1
                else:
                    # Check if form has state-changing methods
                    method = form.get('method', 'get').lower()
                    if method in ['post', 'put', 'delete', 'patch']:
                        action = form.get('action', '')
                        db_service.add_vulnerability(
                            scan_id=scan_id,
                            title='Missing CSRF Protection',
                            description=f'Form without CSRF protection found: {action}',
                            severity='medium',
                            cvss_score=6.1,
                            location=f'Form action: {action}',
                            remediation='Implement CSRF tokens for all state-changing operations',
                            tool='web_scanner'
                        )
            
            # If no forms have CSRF protection, it's a broader issue
            if total_forms > 0 and csrf_protected == 0:
                db_service.add_vulnerability(
                    scan_id=scan_id,
                    title='No CSRF Protection Implemented',
                    description=f'None of the {total_forms} forms found have CSRF protection',
                    severity='medium',
                    cvss_score=6.1,
                    location='Application Forms',
                    remediation='Implement comprehensive CSRF protection across the application',
                    tool='web_scanner'
                )
                
        except Exception as e:
            print(f"CSRF testing error: {e}")
    
    def _test_auth_bypass(self, scan_id, target):
        """Test for authentication bypass vulnerabilities."""
        try:
            from services.database_service import db_service
            from urllib.parse import urljoin
            
            # Common admin/protected paths
            protected_paths = [
                '/admin',
                '/admin/',
                '/administrator',
                '/wp-admin',
                '/admin.php',
                '/admin/login',
                '/dashboard',
                '/control-panel',
                '/management',
                '/user/profile',
                '/account/settings'
            ]
            
            # Test for accessible admin areas
            for path in protected_paths:
                try:
                    test_url = urljoin(target, path)
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check if admin area is accessible without authentication
                    if response.status_code == 200:
                        # Look for admin interface indicators
                        admin_indicators = [
                            'admin panel',
                            'dashboard',
                            'control panel',
                            'administration',
                            'user management',
                            'system settings'
                        ]
                        
                        content_lower = response.text.lower()
                        if any(indicator in content_lower for indicator in admin_indicators):
                            db_service.add_vulnerability(
                                scan_id=scan_id,
                                title='Unauthenticated Admin Access',
                                description=f'Admin interface accessible without authentication: {path}',
                                severity='critical',
                                cvss_score=9.1,
                                location=path,
                                remediation='Implement proper authentication for admin interfaces',
                                tool='web_scanner'
                            )
                except:
                    continue
            
            # Test for parameter-based authentication bypass
            bypass_params = [
                'admin=1',
                'role=admin',
                'user_type=administrator',
                'is_admin=true',
                'auth=bypass',
                'debug=1'
            ]
            
            for param in bypass_params:
                try:
                    test_url = f"{target}?{param}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for signs of elevated access
                    if 'admin' in response.text.lower() and response.status_code == 200:
                        db_service.add_vulnerability(
                            scan_id=scan_id,
                            title='Parameter-based Authentication Bypass',
                            description=f'Authentication bypass possible via parameter: {param}',
                            severity='high',
                            cvss_score=8.1,
                            location=f'Parameter: {param}',
                            remediation='Remove debug parameters and implement proper access controls',
                            tool='web_scanner'
                        )
                except:
                    continue
                    
        except Exception as e:
            print(f"Authentication bypass testing error: {e}")
    
    def _check_http_methods(self, scan_id, target):
        """Check for dangerous HTTP methods."""
        try:
            from services.database_service import db_service
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
            
            for method in dangerous_methods:
                try:
                    response = self.session.request(method, target, timeout=5)
                    
                    if response.status_code not in [405, 501]:  # Method not allowed or not implemented
                        severity = 'high' if method in ['PUT', 'DELETE'] else 'medium'
                        cvss_score = 7.5 if method in ['PUT', 'DELETE'] else 5.0
                        
                        db_service.add_vulnerability(
                            scan_id=scan_id,
                            title=f'Dangerous HTTP Method Enabled: {method}',
                            description=f'The {method} HTTP method is enabled and may allow unauthorized actions',
                            severity=severity,
                            cvss_score=cvss_score,
                            location='HTTP Methods',
                            remediation=f'Disable the {method} HTTP method if not required',
                            tool='web_scanner'
                        )
                except:
                    continue
                    
        except Exception as e:
            print(f"HTTP methods check error: {e}")
    
    def _estimate_scan_time(self, target, options=None):
        """
        Estimate scan time based on target complexity and selected options.
        
        Args:
            target: Target URL to scan
            options: Scan options that may affect duration
            
        Returns:
            Estimated time in minutes
        """
        base_time = 10  # Base scan time in minutes
        
        # Add time for complex targets
        try:
            response = self.session.get(target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Count forms (each form adds 2 minutes)
            forms = len(soup.find_all('form'))
            form_time = forms * 2
            
            # Count input fields (each 10 fields add 1 minute)
            inputs = len(soup.find_all(['input', 'textarea', 'select']))
            input_time = (inputs // 10) * 1
            
            # Count links (each 20 links add 1 minute)
            links = len(soup.find_all('a', href=True))
            link_time = (links // 20) * 1
            
            total_time = base_time + form_time + input_time + link_time
            
            # Adjust for scan options
            if options:
                if options.get('deep_scan', False):
                    total_time *= 2
                if options.get('brute_force', False):
                    total_time += 15
                if options.get('full_owasp_top_10', False):
                    total_time += 20
            
            return total_time
            
        except Exception:
            # If we can't analyze the target, return a default estimate
            return 30  # Default 30 minutes
    
    def _run_scan(self, scan_id, target, options=None):
        """
        Run the actual web application security scan process.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target URL to scan
            options: Additional scan options
        """
        db = get_db()
        options = options or {}
        
        try:
            # Initialize scan results
            results = {
                "vulnerabilities": [],
                "scan_info": {
                    "target": target,
                    "start_time": datetime.utcnow().isoformat(),
                    "options": options
                }
            }
            
            # Update scan status
            self._update_scan_status(scan_id, "Reconnaissance phase", 10)
            
            # 1. Reconnaissance phase
            target_info = self._perform_reconnaissance(target)
            results["target_info"] = target_info
            
            # 2. Vulnerability scanning phases
            self._update_scan_status(scan_id, "Testing for SQL Injection vulnerabilities", 20)
            sql_vulns = self._scan_sql_injection(target, target_info)
            results["vulnerabilities"].extend(sql_vulns)
            
            self._update_scan_status(scan_id, "Testing for XSS vulnerabilities", 35)
            xss_vulns = self._scan_xss(target, target_info)
            results["vulnerabilities"].extend(xss_vulns)
            
            self._update_scan_status(scan_id, "Testing for CSRF vulnerabilities", 50)
            csrf_vulns = self._scan_csrf(target, target_info)
            results["vulnerabilities"].extend(csrf_vulns)
            
            self._update_scan_status(scan_id, "Testing for authentication weaknesses", 65)
            auth_vulns = self._scan_authentication(target, target_info)
            results["vulnerabilities"].extend(auth_vulns)
            
            self._update_scan_status(scan_id, "Testing for misconfiguration issues", 80)
            config_vulns = self._scan_misconfigurations(target, target_info)
            results["vulnerabilities"].extend(config_vulns)
            
            # 3. Finalize results
            self._update_scan_status(scan_id, "Finalizing report", 95)
            
            # Calculate risk scores
            risk_score = self._calculate_risk_score(results["vulnerabilities"])
            results["risk_score"] = risk_score
            
            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(results["vulnerabilities"])
            
            # Complete scan
            end_time = datetime.utcnow()
            results["scan_info"]["end_time"] = end_time.isoformat()
            results["scan_info"]["duration"] = (end_time - datetime.fromisoformat(results["scan_info"]["start_time"])).total_seconds()
            
            # Update database with results
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "completed",
                        "progress": 100,
                        "results": results,
                        "end_time": end_time,
                        "risk_score": risk_score
                    }
                }
            )
            
            # Add vulnerabilities to the vulnerabilities collection
            if results["vulnerabilities"]:
                for vuln in results["vulnerabilities"]:
                    vuln["scan_id"] = scan_id
                    vuln["discovered_at"] = datetime.utcnow()
                    db.vulnerabilities.insert_one(vuln)
                    
        except Exception as e:
            # Handle scan errors
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "failed",
                        "error": str(e),
                        "end_time": datetime.utcnow()
                    }
                }
            )
    
    def _update_scan_status(self, scan_id, message, progress, current_phase=None):
        """Update scan status in the database."""
        db = get_db()
        update_data = {
            "message": message,
            "progress": progress,
            "status": "running"
        }
        
        if current_phase:
            update_data["current_phase"] = current_phase
            
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": update_data}
        )
    
    def _perform_reconnaissance(self, target):
        """Gather information about the target."""
        target_info = {
            "url": target,
            "server": None,
            "technologies": [],
            "forms": [],
            "endpoints": [],
            "headers": {}
        }
        
        try:
            # Get basic server info
            response = self.session.get(target, timeout=10, verify=False)
            target_info["status_code"] = response.status_code
            target_info["headers"] = dict(response.headers)
            
            # Extract server info
            if "Server" in response.headers:
                target_info["server"] = response.headers["Server"]
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all("form")
            for form in forms:
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").upper(),
                    "inputs": []
                }
                
                # Get form inputs
                for input_field in form.find_all(["input", "textarea", "select"]):
                    input_data = {
                        "name": input_field.get("name", ""),
                        "type": input_field.get("type", "text"),
                        "id": input_field.get("id", ""),
                        "required": input_field.has_attr("required")
                    }
                    form_data["inputs"].append(input_data)
                
                target_info["forms"].append(form_data)
            
            # Find endpoints (links)
            base_url = urlparse(target)
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("http"):
                    target_info["endpoints"].append(href)
                elif not href.startswith("#"):
                    # Resolve relative URLs
                    full_url = urljoin(target, href)
                    target_info["endpoints"].append(full_url)
            
            # Remove duplicates
            target_info["endpoints"] = list(set(target_info["endpoints"]))
            
            # Detect technologies
            if soup.find("meta", {"name": "generator"}):
                generator = soup.find("meta", {"name": "generator"})["content"]
                target_info["technologies"].append(generator)
            
            # Check for common frameworks
            if soup.find_all(attrs={"class": re.compile(r"wp-")}):
                target_info["technologies"].append("WordPress")
            if "drupal" in response.text.lower():
                target_info["technologies"].append("Drupal")
            if "joomla" in response.text.lower():
                target_info["technologies"].append("Joomla")
            if soup.find_all(attrs={"ng-"}):
                target_info["technologies"].append("AngularJS")
            if "react" in response.text.lower():
                target_info["technologies"].append("React")
            
            return target_info
            
        except Exception as e:
            return {"url": target, "error": str(e)}
    
    def _scan_sql_injection(self, target, target_info):
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []
        
        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR 1=1#",
            "') OR ('1'='1",
            "admin' --",
            "1' OR '1' = '1",
            "1 OR 1=1",
            "' UNION SELECT 1,2,3,4,5 --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL --"
        ]
        
        # Test forms for SQL injection
        for form in target_info.get("forms", []):
            form_url = urljoin(target, form["action"]) if form["action"] else target
            method = form["method"]
            
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "password", "number"]:
                    for payload in payloads:
                        # Create form data with the payload
                        form_data = {}
                        for inp in form["inputs"]:
                            if inp["name"] == input_field["name"]:
                                form_data[inp["name"]] = payload
                            elif inp["name"]:
                                form_data[inp["name"]] = "test"
                        
                        try:
                            # Send the request
                            if method == "GET":
                                response = self.session.get(form_url, params=form_data, timeout=10)
                            else:
                                response = self.session.post(form_url, data=form_data, timeout=10)
                            
                            # Check for SQL error messages
                            sql_errors = [
                                "SQL syntax", "mysql_fetch", "ORA-", "Oracle error",
                                "SQL Server", "SQLite", "PostgreSQL", "mysqli_", "pg_",
                                "ODBC", "syntax error", "unclosed quotation mark"
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    vulnerabilities.append({
                                        "type": "sql_injection",
                                        "severity": "high",
                                        "url": form_url,
                                        "method": method,
                                        "parameter": input_field["name"],
                                        "payload": payload,
                                        "evidence": error,
                                        "description": f"SQL Injection vulnerability detected in {input_field['name']} parameter",
                                        "remediation": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
                                    })
                                    break
                        
                        except Exception:
                            continue
        
        return vulnerabilities
    
    def _scan_xss(self, target, target_info):
        """Test for Cross-Site Scripting vulnerabilities."""
        vulnerabilities = []
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">Click me</a>"
        ]
        
        # Test forms for XSS
        for form in target_info.get("forms", []):
            form_url = urljoin(target, form["action"]) if form["action"] else target
            method = form["method"]
            
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "url", "textarea"]:
                    for payload in payloads:
                        # Create form data with the payload
                        form_data = {}
                        for inp in form["inputs"]:
                            if inp["name"] == input_field["name"]:
                                form_data[inp["name"]] = payload
                            elif inp["name"]:
                                form_data[inp["name"]] = "test"
                        
                        try:
                            # Send the request
                            if method == "GET":
                                response = self.session.get(form_url, params=form_data, timeout=10)
                            else:
                                response = self.session.post(form_url, data=form_data, timeout=10)
                            
                            # Check if the payload is reflected in the response
                            if payload in response.text:
                                vulnerabilities.append({
                                    "type": "xss",
                                    "severity": "high",
                                    "url": form_url,
                                    "method": method,
                                    "parameter": input_field["name"],
                                    "payload": payload,
                                    "evidence": payload,
                                    "description": f"Cross-Site Scripting vulnerability detected in {input_field['name']} parameter",
                                    "remediation": "Encode all user-supplied data before reflecting it in responses. Use Content-Security-Policy headers."
                                })
                                break
                        
                        except Exception:
                            continue
        
        return vulnerabilities
    
    def _scan_csrf(self, target, target_info):
        """Test for Cross-Site Request Forgery vulnerabilities."""
        vulnerabilities = []
        
        # Check forms for CSRF tokens
        for form in target_info.get("forms", []):
            if form["method"] == "POST":
                form_url = urljoin(target, form["action"]) if form["action"] else target
                
                # Check if the form has a CSRF token
                has_csrf_token = False
                for input_field in form["inputs"]:
                    name = input_field["name"].lower()
                    if "csrf" in name or "token" in name or "_token" in name:
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vulnerabilities.append({
                        "type": "csrf",
                        "severity": "medium",
                        "url": form_url,
                        "method": "POST",
                        "evidence": "No CSRF token found in form",
                        "description": "Form does not contain a CSRF token, making it vulnerable to Cross-Site Request Forgery attacks",
                        "remediation": "Implement anti-CSRF tokens in all forms that perform state-changing actions."
                    })
        
        return vulnerabilities
    
    def _scan_authentication(self, target, target_info):
        """Test for authentication weaknesses."""
        vulnerabilities = []
        
        # Check for login forms
        login_forms = []
        for form in target_info.get("forms", []):
            # Identify potential login forms
            password_field = False
            username_field = False
            
            for input_field in form["inputs"]:
                if input_field["type"] == "password":
                    password_field = True
                if input_field["type"] == "text" or input_field["type"] == "email":
                    username_field = True
            
            if password_field and username_field:
                login_forms.append(form)
        
        # Check login forms for security issues
        for form in login_forms:
            form_url = urljoin(target, form["action"]) if form["action"] else target
            
            # Check if the login form is served over HTTPS
            if not form_url.startswith("https://"):
                vulnerabilities.append({
                    "type": "insecure_login",
                    "severity": "high",
                    "url": form_url,
                    "evidence": "Login form submitted over HTTP",
                    "description": "Login form is not served over HTTPS, credentials can be intercepted",
                    "remediation": "Ensure all authentication forms are served over HTTPS."
                })
            
            # Check for autocomplete on password fields
            for input_field in form["inputs"]:
                if input_field["type"] == "password" and not input_field.get("autocomplete") == "off":
                    vulnerabilities.append({
                        "type": "password_autocomplete",
                        "severity": "low",
                        "url": form_url,
                        "parameter": input_field["name"],
                        "evidence": "Password field without autocomplete=off",
                        "description": "Password field allows autocomplete, which may store passwords in the browser",
                        "remediation": "Add autocomplete='off' to password fields."
                    })
        
        return vulnerabilities
    
    def _scan_misconfigurations(self, target, target_info):
        """Test for security misconfigurations."""
        vulnerabilities = []
        
        # Check security headers
        headers = target_info.get("headers", {})
        
        # Check for missing security headers
        security_headers = {
            "Strict-Transport-Security": {
                "severity": "medium",
                "description": "Missing HTTP Strict Transport Security header",
                "remediation": "Add the Strict-Transport-Security header to enforce HTTPS."
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "Missing Content Security Policy header",
                "remediation": "Implement a Content Security Policy to prevent XSS and data injection attacks."
            },
            "X-Frame-Options": {
                "severity": "low",
                "description": "Missing X-Frame-Options header",
                "remediation": "Add X-Frame-Options header to prevent clickjacking attacks."
            },
            "X-Content-Type-Options": {
                "severity": "low",
                "description": "Missing X-Content-Type-Options header",
                "remediation": "Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing."
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "Missing X-XSS-Protection header",
                "remediation": "Add X-XSS-Protection: 1; mode=block header to enable browser's XSS protection."
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": "missing_security_header",
                    "severity": info["severity"],
                    "url": target,
                    "header": header,
                    "description": info["description"],
                    "remediation": info["remediation"]
                })
        
        # Check for information disclosure
        if "X-Powered-By" in headers or "Server" in headers:
            server_info = headers.get("X-Powered-By", "") or headers.get("Server", "")
            vulnerabilities.append({
                "type": "information_disclosure",
                "severity": "low",
                "url": target,
                "evidence": f"Server: {server_info}",
                "description": "Server is revealing version information through headers",
                "remediation": "Configure the server to suppress version information in HTTP headers."
            })
        
        return vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities):
        """Calculate overall risk score based on vulnerabilities."""
        if not vulnerabilities:
            return 0
        
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }
        
        total_weight = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low").lower()
            total_weight += severity_weights.get(severity, 1)
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10  # If all were critical
        normalized_score = min(100, (total_weight / max_possible) * 100) if max_possible > 0 else 0
        
        return round(normalized_score, 1)
    
    def _generate_recommendations(self, vulnerabilities):
        """Generate security recommendations based on found vulnerabilities."""
        if not vulnerabilities:
            return ["No vulnerabilities were found. Continue to maintain security best practices."]
        
        recommendations = []
        recommendation_map = {
            "sql_injection": "Implement parameterized queries and input validation to prevent SQL injection attacks.",
            "xss": "Implement proper output encoding and Content-Security-Policy headers to prevent Cross-Site Scripting.",
            "csrf": "Add anti-CSRF tokens to all forms that perform state-changing actions.",
            "insecure_login": "Ensure all authentication forms are served over HTTPS.",
            "password_autocomplete": "Add autocomplete='off' to password fields to prevent browser storage of credentials.",
            "missing_security_header": "Implement recommended security headers to enhance application security posture.",
            "information_disclosure": "Configure servers to suppress version information in HTTP headers."
        }
        
        # Add recommendations based on vulnerability types
        vuln_types = set(v.get("type", "") for v in vulnerabilities)
        for vuln_type in vuln_types:
            if vuln_type in recommendation_map:
                recommendations.append(recommendation_map[vuln_type])
        
        # Add general recommendations
        recommendations.append("Implement a regular security testing program to identify and address vulnerabilities.")
        recommendations.append("Keep all software components and libraries up to date with security patches.")
        
        return recommendations
    
    def _run_nikto_scan(self, target):
        """Run Nikto scan against the target."""
        vulnerabilities = []
        try:
            # Create temporary file for Nikto output
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Run Nikto scan
            cmd = ['nikto', '-h', target, '-o', temp_filename, '-Format', 'txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if os.path.exists(temp_filename):
                with open(temp_filename, 'r') as f:
                    nikto_output = f.read()
                
                # Parse Nikto output for vulnerabilities
                vulnerabilities.extend(self._parse_nikto_output(nikto_output, target))
                
                # Clean up temporary file
                os.unlink(temp_filename)
                
        except subprocess.TimeoutExpired:
            print(f"Nikto scan timed out for {target}")
        except FileNotFoundError:
            print("Nikto not found. Please install Nikto for enhanced web scanning.")
        except Exception as e:
            print(f"Error running Nikto scan: {e}")
        
        return vulnerabilities
    
    def _parse_nikto_output(self, output, target):
        """Parse Nikto output to extract vulnerabilities."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+ ' in line and any(keyword in line.lower() for keyword in 
                ['vulnerable', 'outdated', 'disclosure', 'injection', 'xss', 'directory']):
                
                # Extract vulnerability details
                description = line.strip().replace('+ ', '')
                severity = 'medium'
                
                # Determine severity based on keywords
                if any(keyword in line.lower() for keyword in ['injection', 'xss', 'authentication']):
                    severity = 'high'
                elif any(keyword in line.lower() for keyword in ['disclosure', 'directory']):
                    severity = 'low'
                
                vulnerability = {
                    'type': 'nikto_finding',
                    'title': 'Nikto Security Finding',
                    'description': description,
                    'severity': severity,
                    'target': target,
                    'tool': 'nikto',
                    'timestamp': datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _crawl_website(self, base_url, max_pages=20):
        """
        Crawl the website to discover pages.
        
        Args:
            base_url: Base URL of the website
            max_pages: Maximum number of pages to crawl
        
        Returns:
            List of discovered URLs
        """
        discovered_urls = set([base_url])
        urls_to_visit = [base_url]
        visited_urls = set()
        
        while urls_to_visit and len(discovered_urls) < max_pages:
            url = urls_to_visit.pop(0)
            if url in visited_urls:
                continue
            
            try:
                response = self.session.get(url, timeout=10)
                visited_urls.add(url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('#') or href.startswith('javascript:'):
                            continue
                        
                        # Convert relative URL to absolute URL
                        absolute_url = urljoin(url, href)
                        
                        # Only include URLs from the same domain
                        if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                            if absolute_url not in discovered_urls:
                                discovered_urls.add(absolute_url)
                                urls_to_visit.append(absolute_url)
            
            except Exception:
                continue
        
        return list(discovered_urls)
    
    def _test_xss(self, base_url, discovered_urls):
        """
        Test for XSS vulnerabilities.
        
        Args:
            base_url: Base URL of the website
            discovered_urls: List of discovered URLs
        
        Returns:
            List of XSS vulnerabilities
        """
        results = []
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        # Test forms for XSS
        for url in discovered_urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        form_action = form.get('action', '')
                        form_method = form.get('method', 'get').lower()
                        form_url = urljoin(url, form_action)
                        
                        # Test each input field with XSS payloads
                        for input_field in form.find_all('input'):
                            input_type = input_field.get('type', '').lower()
                            input_name = input_field.get('name', '')
                            
                            if input_type in ['text', 'search', 'url', 'email', 'hidden'] and input_name:
                                for payload in xss_payloads:
                                    data = {input_name: payload}
                                    
                                    try:
                                        if form_method == 'post':
                                            response = self.session.post(form_url, data=data, timeout=10)
                                        else:
                                            response = self.session.get(form_url, params=data, timeout=10)
                                        
                                        if payload in response.text:
                                            results.append({
                                                "type": "xss",
                                                "severity": "high",
                                                "url": form_url,
                                                "parameter": input_name,
                                                "payload": payload,
                                                "description": f"XSS vulnerability found in {input_name} parameter of form at {form_url}",
                                                "remediation": "Implement proper input validation and output encoding. Consider using Content-Security-Policy."
                                            })
                                            break
                                    except Exception:
                                        continue
            
            except Exception:
                continue
        
        return results
    
    def _test_sql_injection(self, base_url, discovered_urls):
        """
        Test for SQL injection vulnerabilities.
        
        Args:
            base_url: Base URL of the website
            discovered_urls: List of discovered URLs
        
        Returns:
            List of SQL injection vulnerabilities
        """
        results = []
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "' OR 1=1--",
            "admin'--"
        ]
        
        sql_errors = [
            "SQL syntax",
            "mysql_fetch_array",
            "mysqli_fetch_array",
            "ORA-",
            "Oracle error",
            "PostgreSQL",
            "SQLite3::"
        ]
        
        # Test forms for SQL injection
        for url in discovered_urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        form_action = form.get('action', '')
                        form_method = form.get('method', 'get').lower()
                        form_url = urljoin(url, form_action)
                        
                        # Test each input field with SQL injection payloads
                        for input_field in form.find_all('input'):
                            input_type = input_field.get('type', '').lower()
                            input_name = input_field.get('name', '')
                            
                            if input_type in ['text', 'search', 'url', 'email', 'hidden', 'password'] and input_name:
                                for payload in sqli_payloads:
                                    data = {input_name: payload}
                                    
                                    try:
                                        if form_method == 'post':
                                            response = self.session.post(form_url, data=data, timeout=10)
                                        else:
                                            response = self.session.get(form_url, params=data, timeout=10)
                                        
                                        # Check for SQL error messages
                                        for error in sql_errors:
                                            if error.lower() in response.text.lower():
                                                results.append({
                                                    "type": "sql_injection",
                                                    "severity": "high",
                                                    "url": form_url,
                                                    "parameter": input_name,
                                                    "payload": payload,
                                                    "description": f"SQL injection vulnerability found in {input_name} parameter of form at {form_url}",
                                                    "remediation": "Use parameterized queries or prepared statements. Implement input validation and sanitization."
                                                })
                                                break
                                    except Exception:
                                        continue
            
            except Exception:
                continue
        
        return results
    
    def _test_csrf(self, base_url, discovered_urls):
        """
        Test for CSRF vulnerabilities.
        
        Args:
            base_url: Base URL of the website
            discovered_urls: List of discovered URLs
        
        Returns:
            List of CSRF vulnerabilities
        """
        results = []
        
        # Test forms for CSRF protection
        for url in discovered_urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        form_method = form.get('method', 'get').lower()
                        
                        # Only check POST forms for CSRF
                        if form_method == 'post':
                            csrf_token_found = False
                            
                            # Check for common CSRF token field names
                            csrf_field_names = ['csrf', 'csrf_token', '_csrf', 'token', 'authenticity_token']
                            
                            for input_field in form.find_all('input'):
                                input_name = input_field.get('name', '').lower()
                                
                                if any(token_name in input_name for token_name in csrf_field_names):
                                    csrf_token_found = True
                                    break
                            
                            if not csrf_token_found:
                                form_action = form.get('action', '')
                                form_url = urljoin(url, form_action)
                                
                                results.append({
                                    "type": "csrf",
                                    "severity": "medium",
                                    "url": form_url,
                                    "description": f"Potential CSRF vulnerability found in form at {form_url}",
                                    "remediation": "Implement CSRF tokens for all state-changing operations. Use the SameSite cookie attribute."
                                })
            
            except Exception:
                continue
        
        return results
    
    def _test_security_headers(self, url):
        """
        Test for security headers.
        
        Args:
            url: URL to test
        
        Returns:
            List of security header issues
        """
        results = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Check for Content-Security-Policy
            if 'Content-Security-Policy' not in headers:
                results.append({
                    "type": "security_header",
                    "severity": "medium",
                    "header": "Content-Security-Policy",
                    "description": "Content-Security-Policy header is missing",
                    "remediation": "Implement Content-Security-Policy header to prevent XSS and data injection attacks."
                })
            
            # Check for X-XSS-Protection
            if 'X-XSS-Protection' not in headers:
                results.append({
                    "type": "security_header",
                    "severity": "low",
                    "header": "X-XSS-Protection",
                    "description": "X-XSS-Protection header is missing",
                    "remediation": "Implement X-XSS-Protection header to enable browser's XSS filter."
                })
            
            # Check for X-Content-Type-Options
            if 'X-Content-Type-Options' not in headers:
                results.append({
                    "type": "security_header",
                    "severity": "low",
                    "header": "X-Content-Type-Options",
                    "description": "X-Content-Type-Options header is missing",
                    "remediation": "Implement X-Content-Type-Options header to prevent MIME type sniffing."
                })
            
            # Check for X-Frame-Options
            if 'X-Frame-Options' not in headers:
                results.append({
                    "type": "security_header",
                    "severity": "medium",
                    "header": "X-Frame-Options",
                    "description": "X-Frame-Options header is missing",
                    "remediation": "Implement X-Frame-Options header to prevent clickjacking attacks."
                })
            
            # Check for Strict-Transport-Security
            if 'Strict-Transport-Security' not in headers and url.startswith('https://'):
                results.append({
                    "type": "security_header",
                    "severity": "medium",
                    "header": "Strict-Transport-Security",
                    "description": "Strict-Transport-Security header is missing",
                    "remediation": "Implement Strict-Transport-Security header to enforce HTTPS."
                })
        
        except Exception:
            pass
        
        return results
    
    def _test_sensitive_data_exposure(self, base_url, discovered_urls):
        """
        Test for sensitive data exposure.
        
        Args:
            base_url: Base URL of the website
            discovered_urls: List of discovered URLs
        
        Returns:
            List of sensitive data exposure issues
        """
        results = []
        
        # Patterns to look for
        patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            "social_security": r'\b\d{3}-\d{2}-\d{4}\b',
            "api_key": r'(?:api|access|auth|client|secret|token)_?(?:key|secret|token)?["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            "password": r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\']{8,})["\']?'
        }
        
        for url in discovered_urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Check for sensitive data in response
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, response.text)
                        if matches:
                            results.append({
                                "type": "sensitive_data",
                                "severity": "high",
                                "url": url,
                                "data_type": pattern_name,
                                "description": f"Potential {pattern_name} exposure found at {url}",
                                "remediation": "Ensure sensitive data is not exposed in responses. Use proper data masking and encryption."
                            })
            
            except Exception:
                continue
        
        return results