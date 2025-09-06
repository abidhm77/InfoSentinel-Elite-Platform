"""
Web application vulnerability scanner module.
"""
import threading
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin

from database.db import get_db

class WebScanner:
    """Scanner for web application vulnerabilities."""
    
    def __init__(self):
        """Initialize the web scanner."""
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'PenTest-Platform/1.0'
        }
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start a web application scan in a separate thread.
        
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
        Run the actual scan process.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target URL to scan
            options: Additional scan options
        """
        db = get_db()
        options = options or {}
        self.vulnerabilities = []
        
        try:
            # Validate target URL
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            
            # Basic reachability check
            self._check_target_reachability(scan_id, target)
            
            # Run various security checks
            self._check_ssl_security(scan_id, target)
            self._check_http_headers(scan_id, target)
            self._check_common_vulnerabilities(scan_id, target)
            
            # Update scan status to completed
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "completed",
                        "end_time": datetime.utcnow(),
                        "vulnerability_count": len(self.vulnerabilities)
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
    
    def _check_target_reachability(self, scan_id, target):
        """Check if target is reachable."""
        try:
            response = requests.get(target, headers=self.headers, timeout=10, verify=False)
            if response.status_code >= 400:
                self._add_vulnerability(
                    scan_id,
                    "Target Unreachable",
                    f"Target returned status code {response.status_code}",
                    "medium",
                    {"url": target, "status_code": response.status_code}
                )
        except requests.exceptions.RequestException as e:
            self._add_vulnerability(
                scan_id,
                "Target Unreachable",
                f"Failed to connect to target: {str(e)}",
                "high",
                {"url": target, "error": str(e)}
            )
    
    def _check_ssl_security(self, scan_id, target):
        """Check SSL/TLS security configuration."""
        if not target.startswith('https://'):
            self._add_vulnerability(
                scan_id,
                "Insecure Protocol",
                "Target is using HTTP instead of HTTPS",
                "high",
                {"url": target}
            )
            return
        
        try:
            response = requests.get(target, headers=self.headers, timeout=10, verify=True)
            # Further SSL checks would be implemented here
        except requests.exceptions.SSLError as e:
            self._add_vulnerability(
                scan_id,
                "SSL Certificate Error",
                f"Invalid SSL certificate: {str(e)}",
                "high",
                {"url": target, "error": str(e)}
            )
    
    def _check_http_headers(self, scan_id, target):
        """Check for security-related HTTP headers."""
        try:
            response = requests.get(target, headers=self.headers, timeout=10, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    self._add_vulnerability(
                        scan_id,
                        f"Missing Security Header: {header}",
                        message,
                        "medium",
                        {"url": target, "headers": dict(headers)}
                    )
                    
        except requests.exceptions.RequestException:
            # Error already logged in reachability check
            pass
    
    def _check_common_vulnerabilities(self, scan_id, target):
        """Check for common web vulnerabilities."""
        # This would include checks for:
        # - XSS vulnerabilities
        # - SQL Injection
        # - CSRF
        # - Directory traversal
        # - etc.
        
        # For demonstration, we'll just add a placeholder
        self._add_vulnerability(
            scan_id,
            "Potential XSS Vulnerability",
            "Input parameters are not properly sanitized",
            "high",
            {"url": target, "details": "Simulated vulnerability for demonstration"}
        )
    
    def _add_vulnerability(self, scan_id, title, description, severity, details):
        """
        Add a vulnerability to the database.
        
        Args:
            scan_id: ID of the scan
            title: Vulnerability title
            description: Vulnerability description
            severity: Severity level (low, medium, high, critical)
            details: Additional vulnerability details
        """
        vulnerability = {
            "scan_id": scan_id,
            "title": title,
            "description": description,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow()
        }
        
        # Add to local list
        self.vulnerabilities.append(vulnerability)
        
        # Add to database
        db = get_db()
        db.vulnerabilities.insert_one(vulnerability)