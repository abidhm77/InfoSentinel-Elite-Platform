#!/usr/bin/env python3
"""
InfoSentinel Security Tools Integration
Real penetration testing backend with Nmap and OWASP ZAP integration
"""

import asyncio
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
import nmap
from zapv2 import ZAPv2
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress
import socket
import threading
import time
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanTarget:
    """Represents a scan target"""
    target: str
    scan_type: str
    ports: Optional[str] = None
    scan_options: Optional[Dict] = None

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    id: str
    name: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: float
    cve_id: Optional[str] = None
    host: str = ""
    port: int = 0
    service: str = ""
    solution: str = ""
    references: List[str] = None
    discovered_at: datetime = None

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.discovered_at is None:
            self.discovered_at = datetime.now()

@dataclass
class ScanResult:
    """Represents scan results"""
    scan_id: str
    target: str
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    hosts_discovered: List[Dict] = None
    vulnerabilities: List[Vulnerability] = None
    services: List[Dict] = None
    scan_type: str = "comprehensive"
    progress: int = 0
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.hosts_discovered is None:
            self.hosts_discovered = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.services is None:
            self.services = []

class SecurityToolsManager:
    """Manages integration with security tools"""
    
    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}
        self.nmap_scanner = nmap.PortScanner()
        self.zap_proxy = None
        self.zap_api_key = "your-zap-api-key"  # Should be from environment
        self.zap_proxy_url = "http://127.0.0.1:8080"
        
    def initialize_zap(self) -> bool:
        """Initialize OWASP ZAP connection"""
        try:
            self.zap_proxy = ZAPv2(
                apikey=self.zap_api_key,
                proxies={'http': self.zap_proxy_url, 'https': self.zap_proxy_url}
            )
            # Test connection
            version = self.zap_proxy.core.version
            logger.info(f"Connected to OWASP ZAP version: {version}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to OWASP ZAP: {e}")
            return False
    
    def validate_target(self, target: str) -> bool:
        """Validate scan target"""
        try:
            # Check if it's a valid IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Check if it's a valid hostname
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False
    
    def start_nmap_scan(self, scan_target: ScanTarget) -> str:
        """Start Nmap scan"""
        scan_id = str(uuid.uuid4())
        
        if not self.validate_target(scan_target.target):
            raise ValueError(f"Invalid target: {scan_target.target}")
        
        # Create scan result object
        scan_result = ScanResult(
            scan_id=scan_id,
            target=scan_target.target,
            status=ScanStatus.PENDING,
            start_time=datetime.now(),
            scan_type=scan_target.scan_type
        )
        
        self.active_scans[scan_id] = scan_result
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._execute_nmap_scan,
            args=(scan_id, scan_target)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _execute_nmap_scan(self, scan_id: str, scan_target: ScanTarget):
        """Execute Nmap scan in background"""
        scan_result = self.active_scans[scan_id]
        
        try:
            scan_result.status = ScanStatus.RUNNING
            scan_result.progress = 10
            
            # Determine scan arguments based on scan type
            nmap_args = self._get_nmap_arguments(scan_target.scan_type)
            
            logger.info(f"Starting Nmap scan for {scan_target.target} with args: {nmap_args}")
            
            # Execute Nmap scan
            scan_result.progress = 25
            self.nmap_scanner.scan(
                hosts=scan_target.target,
                ports=scan_target.ports or '1-1000',
                arguments=nmap_args
            )
            
            scan_result.progress = 75
            
            # Process results
            self._process_nmap_results(scan_id)
            
            scan_result.status = ScanStatus.COMPLETED
            scan_result.progress = 100
            scan_result.end_time = datetime.now()
            
            logger.info(f"Nmap scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Nmap scan {scan_id} failed: {e}")
            scan_result.status = ScanStatus.FAILED
            scan_result.error_message = str(e)
            scan_result.end_time = datetime.now()
    
    def _get_nmap_arguments(self, scan_type: str) -> str:
        """Get Nmap arguments based on scan type"""
        scan_profiles = {
            'quick': '-T4 -F',
            'comprehensive': '-T4 -A -v',
            'stealth': '-sS -T2',
            'aggressive': '-T5 -A -O -sV --script vuln',
            'udp': '-sU -T4',
            'tcp_connect': '-sT -T4',
            'syn_scan': '-sS -T4'
        }
        
        return scan_profiles.get(scan_type, '-T4 -A')
    
    def _process_nmap_results(self, scan_id: str):
        """Process Nmap scan results"""
        scan_result = self.active_scans[scan_id]
        
        for host in self.nmap_scanner.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nmap_scanner[host].hostname(),
                'state': self.nmap_scanner[host].state(),
                'protocols': list(self.nmap_scanner[host].all_protocols()),
                'os': self._extract_os_info(host),
                'ports': []
            }
            
            # Process ports and services
            for protocol in self.nmap_scanner[host].all_protocols():
                ports = self.nmap_scanner[host][protocol].keys()
                for port in ports:
                    port_info = self.nmap_scanner[host][protocol][port]
                    
                    service_info = {
                        'port': port,
                        'protocol': protocol,
                        'state': port_info['state'],
                        'name': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
                    
                    host_info['ports'].append(service_info)
                    scan_result.services.append(service_info)
                    
                    # Check for potential vulnerabilities
                    vulnerabilities = self._check_service_vulnerabilities(
                        host, port, service_info
                    )
                    scan_result.vulnerabilities.extend(vulnerabilities)
            
            scan_result.hosts_discovered.append(host_info)
    
    def _extract_os_info(self, host: str) -> Dict:
        """Extract OS information from Nmap results"""
        try:
            if 'osmatch' in self.nmap_scanner[host]:
                os_matches = self.nmap_scanner[host]['osmatch']
                if os_matches:
                    return {
                        'name': os_matches[0].get('name', 'Unknown'),
                        'accuracy': os_matches[0].get('accuracy', 0),
                        'line': os_matches[0].get('line', '')
                    }
        except Exception as e:
            logger.warning(f"Failed to extract OS info for {host}: {e}")
        
        return {'name': 'Unknown', 'accuracy': 0, 'line': ''}
    
    def _check_service_vulnerabilities(self, host: str, port: int, service_info: Dict) -> List[Vulnerability]:
        """Check for known vulnerabilities in discovered services"""
        vulnerabilities = []
        
        # Common vulnerability checks based on service and version
        service_name = service_info.get('name', '').lower()
        version = service_info.get('version', '')
        
        # Example vulnerability checks
        if service_name == 'ssh' and version:
            if 'OpenSSH 7.4' in version:
                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    name="OpenSSH User Enumeration",
                    description="OpenSSH 7.4 is vulnerable to user enumeration attacks",
                    severity=VulnerabilitySeverity.MEDIUM,
                    cvss_score=5.3,
                    cve_id="CVE-2018-15473",
                    host=host,
                    port=port,
                    service=service_name,
                    solution="Update OpenSSH to the latest version",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"]
                )
                vulnerabilities.append(vuln)
        
        elif service_name == 'http' or service_name == 'https':
            # Check for common web vulnerabilities
            if 'Apache' in service_info.get('product', ''):
                version_num = self._extract_version_number(version)
                if version_num and version_num < "2.4.41":
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        name="Apache HTTP Server Vulnerability",
                        description="Outdated Apache version with known vulnerabilities",
                        severity=VulnerabilitySeverity.HIGH,
                        cvss_score=7.5,
                        host=host,
                        port=port,
                        service=service_name,
                        solution="Update Apache to version 2.4.41 or later"
                    )
                    vulnerabilities.append(vuln)
        
        elif service_name == 'ftp':
            if 'vsftpd 2.3.4' in version:
                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    name="vsftpd 2.3.4 Backdoor",
                    description="vsftpd 2.3.4 contains a backdoor vulnerability",
                    severity=VulnerabilitySeverity.CRITICAL,
                    cvss_score=10.0,
                    cve_id="CVE-2011-2523",
                    host=host,
                    port=port,
                    service=service_name,
                    solution="Update vsftpd to a secure version",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_version_number(self, version_string: str) -> Optional[str]:
        """Extract version number from version string"""
        import re
        match = re.search(r'(\d+\.\d+\.\d+)', version_string)
        return match.group(1) if match else None
    
    def start_zap_scan(self, scan_target: ScanTarget) -> str:
        """Start OWASP ZAP web application scan"""
        if not self.zap_proxy:
            if not self.initialize_zap():
                raise RuntimeError("OWASP ZAP is not available")
        
        scan_id = str(uuid.uuid4())
        
        # Validate target is a URL
        if not (scan_target.target.startswith('http://') or scan_target.target.startswith('https://')):
            raise ValueError("ZAP scan requires a valid URL")
        
        # Create scan result object
        scan_result = ScanResult(
            scan_id=scan_id,
            target=scan_target.target,
            status=ScanStatus.PENDING,
            start_time=datetime.now(),
            scan_type="web_application"
        )
        
        self.active_scans[scan_id] = scan_result
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._execute_zap_scan,
            args=(scan_id, scan_target)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _execute_zap_scan(self, scan_id: str, scan_target: ScanTarget):
        """Execute OWASP ZAP scan in background"""
        scan_result = self.active_scans[scan_id]
        
        try:
            scan_result.status = ScanStatus.RUNNING
            scan_result.progress = 10
            
            target_url = scan_target.target
            
            # Spider the target
            logger.info(f"Starting ZAP spider for {target_url}")
            spider_id = self.zap_proxy.spider.scan(target_url)
            
            # Wait for spider to complete
            while int(self.zap_proxy.spider.status(spider_id)) < 100:
                time.sleep(2)
                progress = int(self.zap_proxy.spider.status(spider_id))
                scan_result.progress = 10 + (progress * 0.3)  # 10-40%
            
            scan_result.progress = 40
            
            # Active scan
            logger.info(f"Starting ZAP active scan for {target_url}")
            ascan_id = self.zap_proxy.ascan.scan(target_url)
            
            # Wait for active scan to complete
            while int(self.zap_proxy.ascan.status(ascan_id)) < 100:
                time.sleep(5)
                progress = int(self.zap_proxy.ascan.status(ascan_id))
                scan_result.progress = 40 + (progress * 0.5)  # 40-90%
            
            scan_result.progress = 90
            
            # Process results
            self._process_zap_results(scan_id, target_url)
            
            scan_result.status = ScanStatus.COMPLETED
            scan_result.progress = 100
            scan_result.end_time = datetime.now()
            
            logger.info(f"ZAP scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"ZAP scan {scan_id} failed: {e}")
            scan_result.status = ScanStatus.FAILED
            scan_result.error_message = str(e)
            scan_result.end_time = datetime.now()
    
    def _process_zap_results(self, scan_id: str, target_url: str):
        """Process OWASP ZAP scan results"""
        scan_result = self.active_scans[scan_id]
        
        # Get alerts (vulnerabilities)
        alerts = self.zap_proxy.core.alerts(baseurl=target_url)
        
        for alert in alerts:
            severity_map = {
                'High': VulnerabilitySeverity.HIGH,
                'Medium': VulnerabilitySeverity.MEDIUM,
                'Low': VulnerabilitySeverity.LOW,
                'Informational': VulnerabilitySeverity.INFO
            }
            
            severity = severity_map.get(alert.get('risk', 'Low'), VulnerabilitySeverity.LOW)
            
            # Calculate CVSS score based on severity
            cvss_scores = {
                VulnerabilitySeverity.CRITICAL: 9.0,
                VulnerabilitySeverity.HIGH: 7.5,
                VulnerabilitySeverity.MEDIUM: 5.0,
                VulnerabilitySeverity.LOW: 2.5,
                VulnerabilitySeverity.INFO: 0.0
            }
            
            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                name=alert.get('alert', 'Unknown Vulnerability'),
                description=alert.get('desc', ''),
                severity=severity,
                cvss_score=cvss_scores[severity],
                host=alert.get('url', target_url),
                service="web",
                solution=alert.get('solution', ''),
                references=[alert.get('reference', '')] if alert.get('reference') else []
            )
            
            scan_result.vulnerabilities.append(vuln)
        
        # Get discovered URLs
        urls = self.zap_proxy.core.urls(baseurl=target_url)
        for url in urls:
            service_info = {
                'url': url,
                'method': 'GET',
                'status': 'discovered'
            }
            scan_result.services.append(service_info)
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get scan status and results"""
        if scan_id not in self.active_scans:
            return None
        
        scan_result = self.active_scans[scan_id]
        
        # Convert to dictionary for JSON serialization
        result_dict = {
            'scan_id': scan_result.scan_id,
            'target': scan_result.target,
            'status': scan_result.status.value,
            'progress': scan_result.progress,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'scan_type': scan_result.scan_type,
            'hosts_discovered': len(scan_result.hosts_discovered),
            'vulnerabilities_found': len(scan_result.vulnerabilities),
            'services_found': len(scan_result.services),
            'error_message': scan_result.error_message
        }
        
        return result_dict
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Get detailed scan results"""
        if scan_id not in self.active_scans:
            return None
        
        scan_result = self.active_scans[scan_id]
        
        # Convert vulnerabilities to dictionaries
        vulnerabilities = []
        for vuln in scan_result.vulnerabilities:
            vuln_dict = asdict(vuln)
            vuln_dict['severity'] = vuln.severity.value
            vuln_dict['discovered_at'] = vuln.discovered_at.isoformat()
            vulnerabilities.append(vuln_dict)
        
        result_dict = {
            'scan_id': scan_result.scan_id,
            'target': scan_result.target,
            'status': scan_result.status.value,
            'progress': scan_result.progress,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'scan_type': scan_result.scan_type,
            'hosts_discovered': scan_result.hosts_discovered,
            'vulnerabilities': vulnerabilities,
            'services': scan_result.services,
            'error_message': scan_result.error_message
        }
        
        return result_dict
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id not in self.active_scans:
            return False
        
        scan_result = self.active_scans[scan_id]
        if scan_result.status == ScanStatus.RUNNING:
            scan_result.status = ScanStatus.CANCELLED
            scan_result.end_time = datetime.now()
            return True
        
        return False
    
    def get_active_scans(self) -> List[Dict]:
        """Get list of all active scans"""
        active_scans = []
        for scan_id, scan_result in self.active_scans.items():
            if scan_result.status in [ScanStatus.PENDING, ScanStatus.RUNNING]:
                active_scans.append(self.get_scan_status(scan_id))
        
        return active_scans
    
    def cleanup_old_scans(self, max_age_hours: int = 24):
        """Clean up old scan results"""
        current_time = datetime.now()
        scan_ids_to_remove = []
        
        for scan_id, scan_result in self.active_scans.items():
            age = current_time - scan_result.start_time
            if age.total_seconds() > (max_age_hours * 3600):
                scan_ids_to_remove.append(scan_id)
        
        for scan_id in scan_ids_to_remove:
            del self.active_scans[scan_id]
            logger.info(f"Cleaned up old scan: {scan_id}")

# Global instance
security_tools = SecurityToolsManager()

if __name__ == "__main__":
    # Example usage
    tools = SecurityToolsManager()
    
    # Test Nmap scan
    target = ScanTarget(
        target="127.0.0.1",
        scan_type="quick",
        ports="22,80,443"
    )
    
    scan_id = tools.start_nmap_scan(target)
    print(f"Started scan: {scan_id}")
    
    # Monitor progress
    while True:
        status = tools.get_scan_status(scan_id)
        if status:
            print(f"Progress: {status['progress']}% - Status: {status['status']}")
            if status['status'] in ['completed', 'failed', 'cancelled']:
                break
        time.sleep(2)
    
    # Get results
    results = tools.get_scan_results(scan_id)
    if results:
        print(f"Scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        for vuln in results['vulnerabilities']:
            print(f"- {vuln['name']} ({vuln['severity']})")