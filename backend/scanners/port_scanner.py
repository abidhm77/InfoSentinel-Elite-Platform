"""
Advanced port scanner module for network reconnaissance.
Implements professional-grade port scanning and service enumeration.
"""
import socket
import threading
import queue
import time
from datetime import datetime
import nmap
import json

from database.db import get_db

class PortScanner:
    """Advanced port scanner for network reconnaissance."""
    
    def __init__(self):
        """Initialize the port scanner."""
        self.results = []
        self.nm = nmap.PortScanner()
        self.common_ports = {
            21: "FTP", 
            22: "SSH", 
            23: "Telnet", 
            25: "SMTP", 
            53: "DNS", 
            80: "HTTP", 
            110: "POP3", 
            111: "RPC", 
            135: "RPC", 
            139: "NetBIOS", 
            143: "IMAP", 
            443: "HTTPS", 
            445: "SMB", 
            993: "IMAPS", 
            995: "POP3S", 
            1723: "PPTP", 
            3306: "MySQL", 
            3389: "RDP", 
            5900: "VNC", 
            8080: "HTTP-Proxy"
        }
    
    def start_scan(self, scan_id, target, options=None):
        """
        Start a port scan in a separate thread.
        
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
        Run the actual port scan process.
        
        Args:
            scan_id: Unique identifier for the scan
            target: Target IP or hostname to scan
            options: Additional scan options
        """
        try:
            db = get_db()
            results = []
            
            # Parse options
            if not options:
                options = {}
            
            port_range = options.get('port_range', '1-1000')
            scan_type = options.get('scan_type', 'SYN')
            service_detection = options.get('service_detection', True)
            
            # Perform basic port scan
            if scan_type == 'connect':
                basic_results = self._tcp_connect_scan(target, port_range)
            else:  # Default to SYN scan using nmap
                basic_results = self._syn_scan(target, port_range)
            
            results.extend(basic_results)
            
            # Perform service detection if enabled
            if service_detection and basic_results:
                open_ports = [result['port'] for result in basic_results if result['state'] == 'open']
                if open_ports:
                    service_results = self._detect_services(target, open_ports)
                    results.extend(service_results)
            
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
    
    def _tcp_connect_scan(self, target, port_range):
        """
        Perform a TCP connect scan.
        
        Args:
            target: Target IP or hostname
            port_range: Range of ports to scan (e.g., '1-1000')
        
        Returns:
            List of results
        """
        results = []
        
        # Parse port range
        start_port, end_port = map(int, port_range.split('-'))
        
        # Create a queue for ports
        port_queue = queue.Queue()
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        # Create lock for thread-safe results
        results_lock = threading.Lock()
        
        # Worker function for threading
        def worker():
            while not port_queue.empty():
                try:
                    port = port_queue.get(block=False)
                except queue.Empty:
                    break
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        service = self.common_ports.get(port, "Unknown")
                        with results_lock:
                            results.append({
                                "type": "port_scan",
                                "port": port,
                                "state": "open",
                                "service": service,
                                "method": "connect"
                            })
                except Exception:
                    pass
                
                port_queue.task_done()
        
        # Start worker threads
        threads = []
        for _ in range(min(100, end_port - start_port + 1)):
            t = threading.Thread(target=worker)
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        return results
    
    def _syn_scan(self, target, port_range):
        """
        Perform a SYN scan using nmap.
        
        Args:
            target: Target IP or hostname
            port_range: Range of ports to scan (e.g., '1-1000')
        
        Returns:
            List of results
        """
        results = []
        
        try:
            # Run nmap scan
            self.nm.scan(target, port_range, arguments='-sS -T4')
            
            # Process results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = sorted(self.nm[host][proto].keys())
                    for port in lport:
                        state = self.nm[host][proto][port]['state']
                        if state == 'open':
                            service = self.nm[host][proto][port]['name']
                            if not service:
                                service = self.common_ports.get(port, "Unknown")
                            
                            results.append({
                                "type": "port_scan",
                                "port": port,
                                "state": state,
                                "service": service,
                                "method": "syn"
                            })
        except Exception as e:
            results.append({
                "type": "error",
                "error": str(e),
                "message": "Error during SYN scan"
            })
        
        return results
    
    def _detect_services(self, target, ports):
        """
        Detect services running on open ports.
        
        Args:
            target: Target IP or hostname
            ports: List of open ports
        
        Returns:
            List of results
        """
        results = []
        
        try:
            # Convert ports list to string for nmap
            ports_str = ','.join(map(str, ports))
            
            # Run nmap service detection
            self.nm.scan(target, ports_str, arguments='-sV')
            
            # Process results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = sorted(self.nm[host][proto].keys())
                    for port in lport:
                        service = self.nm[host][proto][port].get('name', 'Unknown')
                        product = self.nm[host][proto][port].get('product', '')
                        version = self.nm[host][proto][port].get('version', '')
                        
                        # Check for potential vulnerabilities based on service and version
                        vulnerabilities = self._check_service_vulnerabilities(service, product, version)
                        
                        results.append({
                            "type": "service_detection",
                            "port": port,
                            "service": service,
                            "product": product,
                            "version": version,
                            "vulnerabilities": vulnerabilities
                        })
        except Exception as e:
            results.append({
                "type": "error",
                "error": str(e),
                "message": "Error during service detection"
            })
        
        return results
    
    def _check_service_vulnerabilities(self, service, product, version):
        """
        Check for known vulnerabilities in detected services.
        
        Args:
            service: Service name
            product: Product name
            version: Version string
        
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        # This is a simplified version - in a real scanner, you'd use a vulnerability database
        if service == 'http' and product.lower() == 'apache':
            if version.startswith('2.4.') and int(version.split('.')[2]) < 50:
                vulnerabilities.append({
                    "name": "Apache HTTP Server Potential Vulnerabilities",
                    "description": f"Apache {version} may contain known vulnerabilities",
                    "severity": "medium",
                    "recommendation": "Update to the latest version of Apache HTTP Server"
                })
        
        elif service == 'ssh' and product.lower() == 'openssh':
            if version.startswith('7.') and int(version.split('.')[1]) < 9:
                vulnerabilities.append({
                    "name": "OpenSSH Potential Vulnerabilities",
                    "description": f"OpenSSH {version} may contain known vulnerabilities",
                    "severity": "medium",
                    "recommendation": "Update to the latest version of OpenSSH"
                })
        
        elif service == 'ftp' and product.lower() == 'vsftpd':
            if version.startswith('2.') and int(version.split('.')[1]) < 3:
                vulnerabilities.append({
                    "name": "VSFTPD Potential Vulnerabilities",
                    "description": f"VSFTPD {version} may contain known vulnerabilities",
                    "severity": "high",
                    "recommendation": "Update to the latest version of VSFTPD"
                })
        
        return vulnerabilities