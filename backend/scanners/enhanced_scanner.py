"""Enhanced penetration testing scanner with real tools integration."""
import subprocess
import tempfile
import os
import json
import threading
import time
from datetime import datetime
import xml.etree.ElementTree as ET
import requests
from urllib.parse import urlparse

from database.db import get_db

class EnhancedScanner:
    """Professional-grade scanner integrating multiple security tools."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.scan_phases = [
            "Initializing scan",
            "Network discovery", 
            "Port scanning",
            "Web application testing",
            "Vulnerability assessment",
            "Generating report"
        ]
        self.current_phase = 0
    
    def start_comprehensive_scan(self, scan_id, target, scan_type="comprehensive"):
        """Start a comprehensive security scan."""
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"status": "running", "start_time": datetime.utcnow()}}
        )
        
        thread = threading.Thread(
            target=self._run_comprehensive_scan,
            args=(scan_id, target, scan_type)
        )
        thread.daemon = True
        thread.start()
    
    def _run_comprehensive_scan(self, scan_id, target, scan_type):
        """Execute comprehensive security scan."""
        try:
            self._update_progress(scan_id, 10, "Initializing scan")
            
            # Phase 1: Network Discovery with Nmap
            self._update_progress(scan_id, 20, "Network discovery")
            nmap_results = self._run_nmap_scan(target)
            
            # Phase 2: Web Application Testing
            if self._is_web_target(target):
                self._update_progress(scan_id, 40, "Web application testing")
                nikto_results = self._run_nikto_scan(target)
                zap_results = self._run_zap_scan(target)
                self.vulnerabilities.extend(nikto_results)
                self.vulnerabilities.extend(zap_results)
            
            # Phase 3: SQL Injection Testing
            self._update_progress(scan_id, 60, "SQL injection testing")
            sqlmap_results = self._run_sqlmap_scan(target)
            self.vulnerabilities.extend(sqlmap_results)
            
            # Phase 4: SSL/TLS Testing
            self._update_progress(scan_id, 80, "SSL/TLS assessment")
            ssl_results = self._run_ssl_scan(target)
            self.vulnerabilities.extend(ssl_results)
            
            # Phase 5: Finalize
            self._update_progress(scan_id, 100, "Generating report")
            self._finalize_scan(scan_id)
            
        except Exception as e:
            self._handle_scan_error(scan_id, str(e))
    
    def _run_nmap_scan(self, target):
        """Run comprehensive Nmap scan."""
        vulnerabilities = []
        try:
            # Aggressive scan with script scanning
            cmd = ['nmap', '-A', '-sC', '-sV', '--script=vuln', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                vulnerabilities.extend(self._parse_nmap_output(result.stdout, target))
            
        except subprocess.TimeoutExpired:
            print(f"Nmap scan timed out for {target}")
        except FileNotFoundError:
            print("Nmap not found. Please install Nmap.")
        except Exception as e:
            print(f"Error running Nmap: {e}")
        
        return vulnerabilities
    
    def _run_nikto_scan(self, target):
        """Run Nikto web vulnerability scan."""
        vulnerabilities = []
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            cmd = ['nikto', '-h', target, '-o', temp_filename, '-Format', 'txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if os.path.exists(temp_filename):
                with open(temp_filename, 'r') as f:
                    nikto_output = f.read()
                vulnerabilities.extend(self._parse_nikto_output(nikto_output, target))
                os.unlink(temp_filename)
                
        except subprocess.TimeoutExpired:
            print(f"Nikto scan timed out for {target}")
        except FileNotFoundError:
            print("Nikto not found. Please install Nikto.")
        except Exception as e:
            print(f"Error running Nikto: {e}")
        
        return vulnerabilities
    
    def _run_zap_scan(self, target):
        """Run OWASP ZAP scan."""
        vulnerabilities = []
        try:
            # Basic ZAP spider and active scan
            cmd = ['zap-baseline.py', '-t', target, '-J', 'zap-report.json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if os.path.exists('zap-report.json'):
                with open('zap-report.json', 'r') as f:
                    zap_data = json.load(f)
                vulnerabilities.extend(self._parse_zap_output(zap_data, target))
                os.unlink('zap-report.json')
                
        except subprocess.TimeoutExpired:
            print(f"ZAP scan timed out for {target}")
        except FileNotFoundError:
            print("OWASP ZAP not found. Please install ZAP.")
        except Exception as e:
            print(f"Error running ZAP: {e}")
        
        return vulnerabilities
    
    def _run_sqlmap_scan(self, target):
        """Run SQLMap for SQL injection testing."""
        vulnerabilities = []
        try:
            if self._is_web_target(target):
                cmd = ['sqlmap', '-u', target, '--batch', '--risk=2', '--level=2']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if 'vulnerable' in result.stdout.lower():
                    vulnerability = {
                        'type': 'sql_injection',
                        'title': 'SQL Injection Vulnerability',
                        'description': 'SQLMap detected potential SQL injection vulnerability',
                        'severity': 'high',
                        'target': target,
                        'tool': 'sqlmap',
                        'details': result.stdout[:500],
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    vulnerabilities.append(vulnerability)
                    
        except subprocess.TimeoutExpired:
            print(f"SQLMap scan timed out for {target}")
        except FileNotFoundError:
            print("SQLMap not found. Please install SQLMap.")
        except Exception as e:
            print(f"Error running SQLMap: {e}")
        
        return vulnerabilities
    
    def _run_ssl_scan(self, target):
        """Run SSL/TLS security assessment."""
        vulnerabilities = []
        try:
            # Use testssl.sh if available
            cmd = ['testssl.sh', '--jsonfile', 'ssl-report.json', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if os.path.exists('ssl-report.json'):
                with open('ssl-report.json', 'r') as f:
                    ssl_data = json.load(f)
                vulnerabilities.extend(self._parse_ssl_output(ssl_data, target))
                os.unlink('ssl-report.json')
                
        except subprocess.TimeoutExpired:
            print(f"SSL scan timed out for {target}")
        except FileNotFoundError:
            print("testssl.sh not found. Skipping SSL assessment.")
        except Exception as e:
            print(f"Error running SSL scan: {e}")
        
        return vulnerabilities
    
    def _parse_nmap_output(self, output, target):
        """Parse Nmap output for vulnerabilities."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if any(keyword in line.lower() for keyword in 
                   ['vulnerable', 'exploit', 'cve-', 'security']):
                
                severity = 'medium'
                if 'critical' in line.lower() or 'high' in line.lower():
                    severity = 'high'
                elif 'low' in line.lower():
                    severity = 'low'
                
                vulnerability = {
                    'type': 'nmap_finding',
                    'title': 'Network Security Finding',
                    'description': line.strip(),
                    'severity': severity,
                    'target': target,
                    'tool': 'nmap',
                    'timestamp': datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_nikto_output(self, output, target):
        """Parse Nikto output for vulnerabilities."""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+ ' in line and any(keyword in line.lower() for keyword in 
                ['vulnerable', 'outdated', 'disclosure', 'injection', 'xss']):
                
                description = line.strip().replace('+ ', '')
                severity = 'medium'
                
                if any(keyword in line.lower() for keyword in ['injection', 'xss']):
                    severity = 'high'
                elif 'disclosure' in line.lower():
                    severity = 'low'
                
                vulnerability = {
                    'type': 'web_vulnerability',
                    'title': 'Web Application Security Issue',
                    'description': description,
                    'severity': severity,
                    'target': target,
                    'tool': 'nikto',
                    'timestamp': datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_zap_output(self, zap_data, target):
        """Parse OWASP ZAP output for vulnerabilities."""
        vulnerabilities = []
        
        if 'site' in zap_data:
            for site in zap_data['site']:
                if 'alerts' in site:
                    for alert in site['alerts']:
                        severity_map = {'High': 'high', 'Medium': 'medium', 'Low': 'low'}
                        severity = severity_map.get(alert.get('riskdesc', 'Medium'), 'medium')
                        
                        vulnerability = {
                            'type': 'web_vulnerability',
                            'title': alert.get('name', 'ZAP Finding'),
                            'description': alert.get('desc', 'No description'),
                            'severity': severity,
                            'target': target,
                            'tool': 'zap',
                            'solution': alert.get('solution', ''),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_ssl_output(self, ssl_data, target):
        """Parse SSL scan output for vulnerabilities."""
        vulnerabilities = []
        
        # Parse testssl.sh JSON output
        for finding in ssl_data:
            if finding.get('severity') in ['HIGH', 'CRITICAL', 'MEDIUM']:
                severity_map = {'HIGH': 'high', 'CRITICAL': 'high', 'MEDIUM': 'medium'}
                severity = severity_map.get(finding.get('severity'), 'low')
                
                vulnerability = {
                    'type': 'ssl_vulnerability',
                    'title': f"SSL/TLS Issue: {finding.get('id', 'Unknown')}",
                    'description': finding.get('finding', 'SSL/TLS security issue detected'),
                    'severity': severity,
                    'target': target,
                    'tool': 'testssl',
                    'timestamp': datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_web_target(self, target):
        """Check if target is a web application."""
        return target.startswith('http://') or target.startswith('https://')
    
    def _update_progress(self, scan_id, progress, phase):
        """Update scan progress in database."""
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "progress": progress,
                "current_phase": phase,
                "last_updated": datetime.utcnow()
            }}
        )
    
    def _finalize_scan(self, scan_id):
        """Finalize scan and save results."""
        db = get_db()
        
        # Save vulnerabilities
        for vuln in self.vulnerabilities:
            vuln['scan_id'] = scan_id
            db.vulnerabilities.insert_one(vuln)
        
        # Update scan status
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "completed",
                "end_time": datetime.utcnow(),
                "vulnerability_count": len(self.vulnerabilities),
                "progress": 100
            }}
        )
    
    def _handle_scan_error(self, scan_id, error_message):
        """Handle scan errors."""
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "failed",
                "error_message": error_message,
                "end_time": datetime.utcnow()
            }}
        )