"""
System vulnerability scanner module.
"""
import threading
import time
from datetime import datetime
import paramiko
import socket

from database.db import get_db

class SystemScanner:
    """Scanner for system vulnerabilities."""
    
    def __init__(self):
        """Initialize the system scanner."""
        self.vulnerabilities = []
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start a system scan in a separate thread.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target IP or hostname to scan
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
            target: Target IP or hostname to scan
            options: Additional scan options
        """
        db = get_db()
        options = options or {}
        self.vulnerabilities = []
        
        try:
            # Check SSH configuration if credentials are provided
            if 'username' in options and 'password' in options:
                self._check_ssh_security(
                    scan_id, 
                    target, 
                    options['username'], 
                    options['password'],
                    options.get('port', 22)
                )
            
            # Check for common system vulnerabilities
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
    
    def _check_ssh_security(self, scan_id, target, username, password, port=22):
        """
        Check SSH security configuration.
        
        Args:
            scan_id: ID of the scan
            target: Target to scan
            username: SSH username
            password: SSH password
            port: SSH port
        """
        try:
            # Try to connect with provided credentials
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set connection timeout
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=10
            )
            
            # Check SSH version
            transport = client.get_transport()
            ssh_version = transport.remote_version
            
            # Check for weak SSH configuration
            if 'ssh-1' in ssh_version.lower():
                self._add_vulnerability(
                    scan_id,
                    "Insecure SSH Version",
                    "Server is using the insecure SSH-1 protocol",
                    "critical",
                    {"target": target, "ssh_version": ssh_version}
                )
            
            # Check for password authentication
            self._add_vulnerability(
                scan_id,
                "Password Authentication Enabled",
                "SSH server allows password authentication which is less secure than key-based authentication",
                "medium",
                {"target": target, "port": port}
            )
            
            # Run system commands to check security configuration
            self._check_system_configuration(scan_id, client)
            
            client.close()
            
        except paramiko.AuthenticationException:
            self._add_vulnerability(
                scan_id,
                "Invalid SSH Credentials",
                "The provided SSH credentials are invalid",
                "info",
                {"target": target, "port": port, "username": username}
            )
        except (socket.error, paramiko.SSHException) as e:
            self._add_vulnerability(
                scan_id,
                "SSH Connection Error",
                f"Failed to connect to SSH server: {str(e)}",
                "medium",
                {"target": target, "port": port, "error": str(e)}
            )
    
    def _check_system_configuration(self, scan_id, ssh_client):
        """
        Check system security configuration.
        
        Args:
            scan_id: ID of the scan
            ssh_client: Connected SSH client
        """
        # Check for outdated packages
        try:
            stdin, stdout, stderr = ssh_client.exec_command(
                "if command -v apt-get > /dev/null; then apt list --upgradable 2>/dev/null; "
                "elif command -v yum > /dev/null; then yum check-update; "
                "elif command -v dnf > /dev/null; then dnf check-update; "
                "fi"
            )
            
            updates = stdout.read().decode('utf-8')
            if updates and len(updates.strip().split('\n')) > 2:
                self._add_vulnerability(
                    scan_id,
                    "Outdated System Packages",
                    "System has outdated packages that may contain security vulnerabilities",
                    "high",
                    {"details": "Multiple packages need updates"}
                )
        except Exception:
            pass
        
        # Check for weak password policies
        try:
            stdin, stdout, stderr = ssh_client.exec_command("grep -i 'password' /etc/pam.d/common-password 2>/dev/null || grep -i 'password' /etc/pam.d/system-auth 2>/dev/null")
            
            password_policy = stdout.read().decode('utf-8')
            if not any(x in password_policy for x in ['minlen=', 'remember=']):
                self._add_vulnerability(
                    scan_id,
                    "Weak Password Policy",
                    "System does not have strong password requirements configured",
                    "medium",
                    {"details": "No minimum length or password history requirements found"}
                )
        except Exception:
            pass
        
        # Check for unnecessary running services
        try:
            stdin, stdout, stderr = ssh_client.exec_command(
                "if command -v systemctl > /dev/null; then systemctl list-units --type=service --state=running; "
                "elif command -v service > /dev/null; then service --status-all 2>&1 | grep '+'; "
                "fi"
            )
            
            services = stdout.read().decode('utf-8')
            risky_services = ['telnet', 'rsh', 'rlogin', 'rexec', 'tftp', 'xinetd', 'nis']
            
            for service in risky_services:
                if service in services.lower():
                    self._add_vulnerability(
                        scan_id,
                        f"Insecure Service Running: {service}",
                        f"The {service} service is running which is considered insecure",
                        "high",
                        {"service": service}
                    )
        except Exception:
            pass
    
    def _check_common_vulnerabilities(self, scan_id, target):
        """
        Check for common system vulnerabilities.
        
        Args:
            scan_id: ID of the scan
            target: Target being scanned
        """
        # This would include checks for:
        # - OS version and patch level
        # - User account security
        # - File permissions
        # - etc.
        
        # For demonstration, we'll just add a placeholder
        self._add_vulnerability(
            scan_id,
            "Potential Privilege Escalation Vulnerability",
            "System may be vulnerable to common privilege escalation techniques",
            "high",
            {"target": target, "details": "Simulated vulnerability for demonstration"}
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