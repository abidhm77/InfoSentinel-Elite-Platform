"""Enhanced network vulnerability scanner with real Nmap integration."""
import threading
import time
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import socket
import nmap
import logging

from database.db import get_db
from services.websocket_service import emit_scan_progress, emit_vulnerability_found, emit_scan_complete
from tasks.scan_tasks import process_nmap_results

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Enhanced scanner for network vulnerabilities using real Nmap."""
    
    def __init__(self, socketio=None):
        """Initialize the network scanner."""
        self.vulnerabilities = []
        self.nm = nmap.PortScanner()
        self.socketio = socketio
        self.scan_phases = [
            "Initializing scan",
            "Host discovery",
            "Port scanning",
            "Service detection",
            "Vulnerability assessment",
            "Finalizing results"
        ]
        self.current_phase = 0
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start a network scan in a separate thread.
        
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
        Run the enhanced scan process with real-time updates.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target IP or hostname to scan
            options: Additional scan options including intensity, threads, etc.
        """
        db = get_db()
        options = options or {}
        self.vulnerabilities = []
        
        try:
            logger.info(f"Starting enhanced network scan for {target}")
            
            # Phase 1: Initialize scan
            self._update_progress(scan_id, 0, "Initializing scan")
            self._validate_target(target)
            time.sleep(1)
            
            # Phase 2: Host discovery
            self._update_progress(scan_id, 15, "Host discovery")
            self._perform_host_discovery(scan_id, target, options)
            
            # Phase 3: Port scanning
            self._update_progress(scan_id, 30, "Port scanning")
            self._perform_enhanced_port_scan(scan_id, target, options)
            
            # Phase 4: Service detection
            self._update_progress(scan_id, 60, "Service detection")
            self._perform_service_detection(scan_id, target, options)
            
            # Phase 5: Vulnerability assessment
            self._update_progress(scan_id, 80, "Vulnerability assessment")
            self._perform_vulnerability_assessment(scan_id, target, options)
            
            # Phase 6: Finalize results
            self._update_progress(scan_id, 95, "Finalizing results")
            self._finalize_scan_results(scan_id)
            
            # Complete scan
            self._update_progress(scan_id, 100, "Scan completed")
            
            # Update scan status to completed
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "completed",
                        "end_time": datetime.utcnow(),
                        "vulnerability_count": len(self.vulnerabilities),
                        "progress": 100
                    }
                }
            )
            
            # Emit completion event
            if self.socketio:
                emit_scan_complete(self.socketio, scan_id, {
                    "vulnerabilities": len(self.vulnerabilities),
                    "target": target,
                    "duration": "Completed"
                })
            
            logger.info(f"Network scan completed for {target}. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Network scan failed for {target}: {str(e)}")
            
            # Update scan status to failed
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "failed",
                        "end_time": datetime.utcnow(),
                        "error": str(e),
                        "progress": 0
                    }
                }
            )
            
            # Emit error event
            if self.socketio:
                from services.websocket_service import emit_scan_error
                emit_scan_error(self.socketio, scan_id, str(e))
    
    def _update_progress(self, scan_id, progress, phase):
        """Update scan progress and emit to WebSocket clients."""
        db = get_db()
        
        # Update database
        db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "progress": progress,
                    "current_phase": phase,
                    "last_updated": datetime.utcnow()
                }
            }
        )
        
        # Emit to WebSocket clients
        if self.socketio:
            emit_scan_progress(self.socketio, scan_id, {
                "progress": progress,
                "phase": phase,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        logger.info(f"Scan {scan_id} progress: {progress}% - {phase}")
    
    def _perform_host_discovery(self, scan_id, target, options):
        """Perform host discovery using Nmap."""
        try:
            # Use ping scan to discover hosts
            self.nm.scan(hosts=target, arguments='-sn')
            
            hosts_up = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hosts_up.append(host)
            
            logger.info(f"Host discovery found {len(hosts_up)} hosts up")
            
        except Exception as e:
            logger.error(f"Host discovery failed: {str(e)}")
    
    def _perform_enhanced_port_scan(self, scan_id, target, options):
        """Perform enhanced port scanning with configurable options."""
        try:
            # Get scan intensity from options
            intensity = options.get('intensity', 'normal')
            max_threads = options.get('max_threads', 5)
            
            # Configure scan arguments based on intensity
            if intensity == 'light':
                arguments = '-sS -T2 --top-ports 100'
            elif intensity == 'normal':
                arguments = '-sS -T3 --top-ports 1000'
            elif intensity == 'deep':
                arguments = '-sS -T4 -p-'
            elif intensity == 'extreme':
                arguments = '-sS -sU -T5 -p- --script vuln'
            else:
                arguments = '-sS -T3 --top-ports 1000'
            
            # Add threading option
            arguments += f' --min-parallelism {max_threads}'
            
            logger.info(f"Starting port scan with arguments: {arguments}")
            
            # Perform the scan
            self.nm.scan(hosts=target, arguments=arguments)
            
            # Process results
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    for protocol in self.nm[host].all_protocols():
                        ports = self.nm[host][protocol].keys()
                        for port in ports:
                            port_state = self.nm[host][protocol][port]['state']
                            if port_state == 'open':
                                service = self.nm[host][protocol][port].get('name', 'unknown')
                                product = self.nm[host][protocol][port].get('product', '')
                                version = self.nm[host][protocol][port].get('version', '')
                                
                                logger.info(f"Found open port: {host}:{port} ({service})")
                                
                                # Check for service vulnerabilities
                                self._check_service_vulnerability(scan_id, host, port, service, product, version)
            
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
    
    def _perform_service_detection(self, scan_id, target, options):
        """Perform detailed service detection."""
        try:
            # Service version detection
            self.nm.scan(hosts=target, arguments='-sV --version-intensity 5')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    for protocol in self.nm[host].all_protocols():
                        ports = self.nm[host][protocol].keys()
                        for port in ports:
                            if self.nm[host][protocol][port]['state'] == 'open':
                                service_info = self.nm[host][protocol][port]
                                
                                # Extract detailed service information
                                service_name = service_info.get('name', 'unknown')
                                product = service_info.get('product', '')
                                version = service_info.get('version', '')
                                extrainfo = service_info.get('extrainfo', '')
                                
                                logger.info(f"Service detected: {host}:{port} - {service_name} {product} {version}")
                                
        except Exception as e:
            logger.error(f"Service detection failed: {str(e)}")
    
    def _perform_vulnerability_assessment(self, scan_id, target, options):
        """Perform vulnerability assessment using Nmap scripts."""
        try:
            # Run vulnerability scripts
            vuln_scripts = [
                'vuln',
                'auth',
                'brute',
                'discovery',
                'dos',
                'exploit',
                'fuzzer',
                'intrusive',
                'malware',
                'safe',
                'version'
            ]
            
            # Select scripts based on options
            selected_scripts = options.get('scripts', ['vuln', 'safe'])
            script_args = ','.join([s for s in selected_scripts if s in vuln_scripts])
            
            if script_args:
                logger.info(f"Running vulnerability scripts: {script_args}")
                self.nm.scan(hosts=target, arguments=f'--script {script_args}')
                
                # Process script results
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        for protocol in self.nm[host].all_protocols():
                            ports = self.nm[host][protocol].keys()
                            for port in ports:
                                port_info = self.nm[host][protocol][port]
                                if 'script' in port_info:
                                    for script_name, script_output in port_info['script'].items():
                                        if 'VULNERABLE' in script_output.upper():
                                            self._process_script_vulnerability(scan_id, host, port, script_name, script_output)
            
        except Exception as e:
            logger.error(f"Vulnerability assessment failed: {str(e)}")
    
    def _process_script_vulnerability(self, scan_id, host, port, script_name, script_output):
        """Process vulnerability found by Nmap script."""
        try:
            # Determine severity based on script output
            severity = 'medium'
            if any(keyword in script_output.upper() for keyword in ['CRITICAL', 'HIGH', 'SEVERE']):
                severity = 'high'
            elif any(keyword in script_output.upper() for keyword in ['LOW', 'INFO']):
                severity = 'low'
            
            vulnerability = {
                'title': f'{script_name.replace("-", " ").title()} Vulnerability',
                'description': f'Vulnerability detected on {host}:{port} by {script_name}',
                'severity': severity,
                'host': host,
                'port': port,
                'script': script_name,
                'details': script_output[:500]  # Limit output length
            }
            
            self._add_vulnerability(scan_id, vulnerability['title'], vulnerability['description'], 
                                  vulnerability['severity'], vulnerability)
            
            # Emit vulnerability found event
            if self.socketio:
                emit_vulnerability_found(self.socketio, scan_id, vulnerability)
            
        except Exception as e:
            logger.error(f"Error processing script vulnerability: {str(e)}")
    
    def _finalize_scan_results(self, scan_id):
        """Finalize scan results and generate summary."""
        try:
            db = get_db()
            
            # Generate scan summary
            summary = {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': {
                    'high': len([v for v in self.vulnerabilities if v.get('severity') == 'high']),
                    'medium': len([v for v in self.vulnerabilities if v.get('severity') == 'medium']),
                    'low': len([v for v in self.vulnerabilities if v.get('severity') == 'low'])
                },
                'scan_type': 'network',
                'completion_time': datetime.utcnow().isoformat()
            }
            
            # Update scan with summary
            db.scans.update_one(
                {"_id": scan_id},
                {"$set": {"summary": summary}}
            )
            
            logger.info(f"Scan {scan_id} finalized with summary: {summary}")
            
        except Exception as e:
            logger.error(f"Error finalizing scan results: {str(e)}")
    
    def _validate_target(self, target):
        """
        Validate that the target is a valid IP address or hostname.
        
        Args:
            target: Target to validate
            
        Raises:
            ValueError: If target is invalid
        """
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Invalid target: {target}")
    
    def _perform_port_scan(self, scan_id, target, options):
        """
        Perform a port scan on the target.
        
        Args:
            scan_id: ID of the scan
            target: Target to scan
            options: Scan options
        """
        # Determine ports to scan
        ports = options.get('ports', '21-25,80,443,3306,3389,8080,8443')
        
        # Determine scan type
        scan_arguments = options.get('scan_arguments', '-sV')
        
        try:
            # Run the scan
            self.nm.scan(hosts=target, ports=ports, arguments=scan_arguments)
            
            # Process results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = sorted(self.nm[host][proto].keys())
                    for port in lport:
                        service = self.nm[host][proto][port]
                        if service['state'] == 'open':
                            # Check for vulnerable services
                            self._check_service_vulnerability(
                                scan_id, 
                                host, 
                                port, 
                                service.get('name', 'unknown'),
                                service.get('product', ''),
                                service.get('version', '')
                            )
        except Exception as e:
            self._add_vulnerability(
                scan_id,
                "Port Scan Error",
                f"Error during port scan: {str(e)}",
                "medium",
                {"target": target, "error": str(e)}
            )
    
    def _check_service_vulnerability(self, scan_id, host, port, service_name, product, version):
        """
        Check if a service is potentially vulnerable.
        
        Args:
            scan_id: ID of the scan
            host: Host being scanned
            port: Port number
            service_name: Name of the service
            product: Product name
            version: Version number
        """
        # Check for common vulnerable services
        vulnerable_services = {
            'ftp': {
                'title': 'Insecure FTP Service',
                'description': 'FTP transfers data in cleartext and is considered insecure.',
                'severity': 'medium'
            },
            'telnet': {
                'title': 'Insecure Telnet Service',
                'description': 'Telnet transfers data in cleartext and is considered insecure.',
                'severity': 'high'
            },
            'smtp': {
                'title': 'Open SMTP Relay',
                'description': 'SMTP server might be configured as an open relay.',
                'severity': 'medium'
            },
            'mysql': {
                'title': 'Database Exposed',
                'description': 'MySQL database port is exposed to the network.',
                'severity': 'high'
            },
            'microsoft-ds': {
                'title': 'Windows File Sharing Exposed',
                'description': 'SMB/CIFS file sharing is exposed to the network.',
                'severity': 'medium'
            }
        }
        
        if service_name.lower() in vulnerable_services:
            vuln_info = vulnerable_services[service_name.lower()]
            self._add_vulnerability(
                scan_id,
                vuln_info['title'],
                vuln_info['description'],
                vuln_info['severity'],
                {
                    "host": host,
                    "port": port,
                    "service": service_name,
                    "product": product,
                    "version": version
                }
            )
        
        # Check for outdated versions with known vulnerabilities
        # This would typically check against a CVE database
        if version and service_name:
            self._add_vulnerability(
                scan_id,
                f"Potentially Vulnerable {service_name.upper()} Service",
                f"Service {service_name} ({product} {version}) may have known vulnerabilities.",
                "medium",
                {
                    "host": host,
                    "port": port,
                    "service": service_name,
                    "product": product,
                    "version": version
                }
            )
    
    def _check_common_vulnerabilities(self, scan_id, target):
        """
        Check for common network vulnerabilities.
        
        Args:
            scan_id: ID of the scan
            target: Target being scanned
        """
        # This would include checks for:
        # - Firewall detection
        # - Open ports analysis
        # - Network service vulnerabilities
        # - etc.
        
        # For demonstration, we'll just add a placeholder
        self._add_vulnerability(
            scan_id,
            "Potential Firewall Misconfiguration",
            "Multiple sensitive ports are accessible from external networks",
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