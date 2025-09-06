#!/usr/bin/env python3
"""
Nikto Integration Module
Provides enhanced web server vulnerability scanning capabilities
"""

import subprocess
import json
import logging
import threading
import time
import os
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    INFORMATION_DISCLOSURE = "information_disclosure"
    CONFIGURATION_ERROR = "configuration_error"
    SECURITY_HEADER_MISSING = "security_header_missing"
    OUTDATED_SOFTWARE = "outdated_software"
    DANGEROUS_FILE = "dangerous_file"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INJECTION_POSSIBLE = "injection_possible"
    DIRECTORY_LISTING = "directory_listing"

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class NiktoVulnerability:
    """Represents a vulnerability found by Nikto"""
    id: str
    url: str
    method: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    osvdb_id: str = ""
    cve_id: str = ""
    references: List[str] = None
    response_code: int = 0
    response_size: int = 0
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class NiktoScanResult:
    """Represents complete Nikto scan results"""
    target_url: str
    scan_start: datetime
    scan_end: datetime
    total_items_tested: int
    vulnerabilities: List[NiktoVulnerability]
    server_info: Dict
    scan_statistics: Dict
    status: str
    error_message: str = ""
    
    def __post_init__(self):
        if not hasattr(self, 'server_info') or self.server_info is None:
            self.server_info = {}
        if not hasattr(self, 'scan_statistics') or self.scan_statistics is None:
            self.scan_statistics = {}

class NiktoIntegration:
    """Nikto integration for web server vulnerability scanning"""
    
    def __init__(self):
        self.nikto_path = self._find_nikto_path()
        self.temp_dir = tempfile.mkdtemp(prefix="nikto_")
        self.active_scans = {}
        
        # Nikto scan profiles
        self.scan_profiles = {
            "quick": {
                "description": "Quick scan with basic tests",
                "options": ["-Tuning", "1,2,3"]
            },
            "standard": {
                "description": "Standard comprehensive scan",
                "options": ["-Tuning", "1,2,3,4,5,6,7,8,9"]
            },
            "comprehensive": {
                "description": "Comprehensive scan with all tests",
                "options": ["-Tuning", "0"]
            },
            "cgi": {
                "description": "Focus on CGI vulnerabilities",
                "options": ["-Tuning", "2"]
            },
            "sql_injection": {
                "description": "Focus on SQL injection tests",
                "options": ["-Tuning", "3"]
            },
            "xss": {
                "description": "Focus on XSS vulnerabilities",
                "options": ["-Tuning", "4"]
            }
        }
    
    def _find_nikto_path(self) -> str:
        """Find Nikto executable path"""
        possible_paths = [
            "/usr/bin/nikto",
            "/usr/local/bin/nikto",
            "/opt/nikto/program/nikto.pl",
            "nikto",
            "nikto.pl"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "-Version"], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=10)
                if result.returncode == 0 or "Nikto" in result.stdout:
                    logger.info(f"Found Nikto at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        raise RuntimeError("Nikto not found. Please install Nikto web scanner.")
    
    def scan_website(self, scan_id: str, target_url: str, 
                    profile: str = "standard", options: Dict = None) -> str:
        """Start Nikto web server scan"""
        options = options or {}
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_nikto_scan,
            args=(scan_id, target_url, profile, options)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_nikto_scan(self, scan_id: str, target_url: str, 
                       profile: str, options: Dict):
        """Execute Nikto scan"""
        try:
            self.active_scans[scan_id] = {
                "status": "running",
                "start_time": datetime.now(),
                "target": target_url,
                "profile": profile,
                "progress": 0
            }
            
            # Build Nikto command
            cmd = self._build_nikto_command(target_url, profile, options)
            
            logger.info(f"Starting Nikto scan: {' '.join(cmd)}")
            
            start_time = datetime.now()
            
            # Execute Nikto
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.temp_dir
            )
            
            # Monitor progress
            output_lines = []
            while process.poll() is None:
                line = process.stdout.readline()
                if line:
                    output_lines.append(line.strip())
                    # Update progress based on output
                    if "Testing:" in line or "+" in line:
                        self.active_scans[scan_id]["progress"] += 1
                time.sleep(0.1)
            
            # Get remaining output
            remaining_stdout, stderr = process.communicate()
            output_lines.extend(remaining_stdout.split('\n'))
            
            end_time = datetime.now()
            
            # Parse results
            if process.returncode == 0:
                results = self._parse_nikto_output(
                    output_lines, target_url, start_time, end_time
                )
                self.active_scans[scan_id].update({
                    "status": "completed",
                    "progress": 100,
                    "results": results,
                    "end_time": end_time
                })
            else:
                logger.error(f"Nikto scan failed: {stderr}")
                self.active_scans[scan_id].update({
                    "status": "failed",
                    "error": stderr,
                    "end_time": end_time
                })
                
        except Exception as e:
            logger.error(f"Nikto scan error: {e}")
            self.active_scans[scan_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
    
    def _build_nikto_command(self, target_url: str, profile: str, 
                           options: Dict) -> List[str]:
        """Build Nikto command with options"""
        cmd = [self.nikto_path]
        
        # Target URL
        cmd.extend(["-host", target_url])
        
        # Output format
        output_file = os.path.join(self.temp_dir, f"nikto_output_{int(time.time())}.xml")
        cmd.extend(["-Format", "xml", "-output", output_file])
        
        # Scan profile
        if profile in self.scan_profiles:
            cmd.extend(self.scan_profiles[profile]["options"])
        
        # Custom options
        if options.get("port"):
            cmd.extend(["-port", str(options["port"])])
        
        if options.get("ssl", False):
            cmd.append("-ssl")
        
        if options.get("timeout"):
            cmd.extend(["-timeout", str(options["timeout"])])
        
        if options.get("user_agent"):
            cmd.extend(["-useragent", options["user_agent"]])
        
        if options.get("cookies"):
            cmd.extend(["-Cookies", options["cookies"]])
        
        if options.get("headers"):
            for header, value in options["headers"].items():
                cmd.extend(["-H", f"{header}: {value}"])
        
        # Authentication
        if options.get("auth_username") and options.get("auth_password"):
            auth_string = f"{options['auth_username']}:{options['auth_password']}"
            cmd.extend(["-id", auth_string])
        
        # Proxy settings
        if options.get("proxy"):
            cmd.extend(["-useproxy", options["proxy"]])
        
        # Disable interactive prompts
        cmd.append("-ask")
        cmd.append("no")
        
        return cmd
    
    def _parse_nikto_output(self, output_lines: List[str], target_url: str,
                          start_time: datetime, end_time: datetime) -> NiktoScanResult:
        """Parse Nikto output and extract vulnerabilities"""
        vulnerabilities = []
        server_info = {}
        scan_statistics = {
            "items_tested": 0,
            "vulnerabilities_found": 0
        }
        
        current_vuln = None
        
        for line in output_lines:
            line = line.strip()
            
            # Extract server information
            if "Server:" in line:
                server_info["server"] = line.split("Server:")[1].strip()
            elif "Target IP:" in line:
                server_info["target_ip"] = line.split("Target IP:")[1].strip()
            elif "Target Hostname:" in line:
                server_info["hostname"] = line.split("Target Hostname:")[1].strip()
            
            # Count tested items
            elif "Testing:" in line:
                scan_statistics["items_tested"] += 1
            
            # Parse vulnerabilities (lines starting with +)
            elif line.startswith("+"):
                vuln_info = self._parse_vulnerability_line(line, target_url)
                if vuln_info:
                    vulnerabilities.append(vuln_info)
                    scan_statistics["vulnerabilities_found"] += 1
            
            # Parse OSVDB references
            elif "OSVDB-" in line:
                if current_vuln:
                    osvdb_id = line.split("OSVDB-")[1].split(":")[0].strip()
                    current_vuln.osvdb_id = osvdb_id
        
        return NiktoScanResult(
            target_url=target_url,
            scan_start=start_time,
            scan_end=end_time,
            total_items_tested=scan_statistics["items_tested"],
            vulnerabilities=vulnerabilities,
            server_info=server_info,
            scan_statistics=scan_statistics,
            status="completed"
        )
    
    def _parse_vulnerability_line(self, line: str, target_url: str) -> Optional[NiktoVulnerability]:
        """Parse a single vulnerability line from Nikto output"""
        try:
            # Remove the leading '+' and clean up
            line = line[1:].strip()
            
            # Extract URL and description
            if ":" in line:
                url_part, description = line.split(":", 1)
                url = url_part.strip()
                description = description.strip()
            else:
                url = "/"
                description = line
            
            # Determine vulnerability type and severity
            vuln_type, severity = self._classify_vulnerability(description)
            
            # Extract method (GET, POST, etc.)
            method = "GET"  # Default
            if "POST" in description.upper():
                method = "POST"
            elif "PUT" in description.upper():
                method = "PUT"
            
            # Generate unique ID
            vuln_id = f"nikto_{hash(url + description) % 10000}"
            
            return NiktoVulnerability(
                id=vuln_id,
                url=f"{target_url.rstrip('/')}{url}" if not url.startswith('http') else url,
                method=method,
                description=description,
                vulnerability_type=vuln_type,
                severity=severity
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse vulnerability line: {line} - {e}")
            return None
    
    def _classify_vulnerability(self, description: str) -> tuple:
        """Classify vulnerability type and severity based on description"""
        desc_lower = description.lower()
        
        # Critical vulnerabilities
        if any(keyword in desc_lower for keyword in [
            "sql injection", "command injection", "code execution",
            "remote file inclusion", "authentication bypass"
        ]):
            return VulnerabilityType.INJECTION_POSSIBLE, SeverityLevel.CRITICAL
        
        # High severity
        elif any(keyword in desc_lower for keyword in [
            "directory traversal", "file disclosure", "admin",
            "password", "credential", "backdoor"
        ]):
            return VulnerabilityType.AUTHENTICATION_BYPASS, SeverityLevel.HIGH
        
        # Medium severity
        elif any(keyword in desc_lower for keyword in [
            "outdated", "version", "vulnerable", "security header",
            "configuration", "misconfiguration"
        ]):
            if "header" in desc_lower:
                return VulnerabilityType.SECURITY_HEADER_MISSING, SeverityLevel.MEDIUM
            elif "version" in desc_lower or "outdated" in desc_lower:
                return VulnerabilityType.OUTDATED_SOFTWARE, SeverityLevel.MEDIUM
            else:
                return VulnerabilityType.CONFIGURATION_ERROR, SeverityLevel.MEDIUM
        
        # Low severity
        elif any(keyword in desc_lower for keyword in [
            "directory listing", "information disclosure", "banner",
            "server information", "file found"
        ]):
            if "directory" in desc_lower and "listing" in desc_lower:
                return VulnerabilityType.DIRECTORY_LISTING, SeverityLevel.LOW
            else:
                return VulnerabilityType.INFORMATION_DISCLOSURE, SeverityLevel.LOW
        
        # Default classification
        return VulnerabilityType.INFORMATION_DISCLOSURE, SeverityLevel.LOW
    
    def get_scan_profiles(self) -> Dict[str, Dict]:
        """Get available scan profiles"""
        return self.scan_profiles
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a running scan"""
        return self.active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "cancelled"
            return True
        return False
    
    def scan_multiple_targets(self, scan_id: str, target_urls: List[str],
                            profile: str = "standard") -> str:
        """Scan multiple targets with the same profile"""
        
        def run_multi_scan():
            try:
                self.active_scans[scan_id] = {
                    "status": "running",
                    "start_time": datetime.now(),
                    "targets": target_urls,
                    "profile": profile,
                    "progress": 0,
                    "completed_targets": 0,
                    "total_targets": len(target_urls),
                    "results": []
                }
                
                for i, target_url in enumerate(target_urls):
                    target_scan_id = f"{scan_id}_target_{i}"
                    
                    # Run individual scan
                    self._run_nikto_scan(target_scan_id, target_url, profile, {})
                    
                    # Wait for completion
                    while self.active_scans.get(target_scan_id, {}).get("status") == "running":
                        time.sleep(1)
                    
                    # Collect results
                    target_result = self.active_scans.get(target_scan_id, {})
                    if target_result.get("results"):
                        self.active_scans[scan_id]["results"].append(target_result["results"])
                    
                    # Update progress
                    self.active_scans[scan_id]["completed_targets"] += 1
                    progress = int((i + 1) / len(target_urls) * 100)
                    self.active_scans[scan_id]["progress"] = progress
                
                self.active_scans[scan_id]["status"] = "completed"
                self.active_scans[scan_id]["end_time"] = datetime.now()
                
            except Exception as e:
                logger.error(f"Multi-target Nikto scan error: {e}")
                self.active_scans[scan_id].update({
                    "status": "failed",
                    "error": str(e),
                    "end_time": datetime.now()
                })
        
        thread = threading.Thread(target=run_multi_scan)
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to cleanup Nikto temp directory: {e}")

# Global instance
nikto_integration = NiktoIntegration()