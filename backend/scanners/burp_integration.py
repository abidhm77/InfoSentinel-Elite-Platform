#!/usr/bin/env python3
"""
Burp Suite Integration Module
Provides professional web application testing via Burp Suite API
"""

import requests
import json
import logging
import threading
import time
import base64
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import urllib.parse

logger = logging.getLogger(__name__)

class BurpScanType(Enum):
    CRAWL_AND_AUDIT = "crawl_and_audit"
    CRAWL_ONLY = "crawl_only"
    AUDIT_ONLY = "audit_only"
    PASSIVE_AUDIT = "passive_audit"

class VulnerabilityConfidence(Enum):
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"

class VulnerabilitySeverity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class BurpVulnerability:
    """Represents a vulnerability found by Burp Suite"""
    issue_id: str
    issue_name: str
    issue_type: str
    url: str
    severity: VulnerabilitySeverity
    confidence: VulnerabilityConfidence
    description: str
    remediation: str = ""
    vulnerability_classifications: List[str] = None
    request_response: Dict = None
    
    def __post_init__(self):
        if self.vulnerability_classifications is None:
            self.vulnerability_classifications = []
        if self.request_response is None:
            self.request_response = {}

@dataclass
class BurpScanResult:
    """Represents complete Burp Suite scan results"""
    scan_id: str
    target_url: str
    scan_type: BurpScanType
    scan_start: datetime
    scan_end: Optional[datetime]
    status: str
    vulnerabilities: List[BurpVulnerability]
    crawl_statistics: Dict
    audit_statistics: Dict
    error_message: str = ""

class BurpSuiteIntegration:
    """Burp Suite Professional API integration"""
    
    def __init__(self, api_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.active_scans = {}
        
        # Set up authentication if API key is provided
        if self.api_key:
            self.session.headers.update({
                'X-API-Key': self.api_key
            })
        
        # Burp Suite issue type mappings
        self.issue_type_mappings = {
            "1048832": "SQL injection",
            "2097408": "Cross-site scripting (reflected)",
            "2097920": "Cross-site scripting (stored)",
            "1049344": "OS command injection",
            "5244416": "Directory traversal",
            "16777472": "File path manipulation",
            "33554688": "LDAP injection",
            "67109120": "XPath injection",
            "134218240": "XML injection",
            "268435968": "SSI injection",
            "536871424": "Cross-site request forgery",
            "1073742336": "Clickjacking",
            "2147484160": "DOM-based XSS",
            "4294967808": "WebSocket URL poisoning"
        }
    
    def test_connection(self) -> bool:
        """Test connection to Burp Suite API"""
        try:
            response = self.session.get(f"{self.api_url}/burp/versions")
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Failed to connect to Burp Suite API: {e}")
            return False
    
    def start_scan(self, scan_id: str, target_url: str, 
                  scan_type: BurpScanType = BurpScanType.CRAWL_AND_AUDIT,
                  options: Dict = None) -> str:
        """Start Burp Suite scan"""
        options = options or {}
        
        if not self.test_connection():
            raise RuntimeError("Cannot connect to Burp Suite API")
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_burp_scan,
            args=(scan_id, target_url, scan_type, options)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_burp_scan(self, scan_id: str, target_url: str,
                      scan_type: BurpScanType, options: Dict):
        """Execute Burp Suite scan"""
        try:
            self.active_scans[scan_id] = {
                "status": "running",
                "start_time": datetime.now(),
                "target": target_url,
                "scan_type": scan_type.value,
                "progress": 0,
                "burp_task_id": None
            }
            
            # Start the appropriate scan type
            if scan_type == BurpScanType.CRAWL_AND_AUDIT:
                burp_task_id = self._start_crawl_and_audit(target_url, options)
            elif scan_type == BurpScanType.CRAWL_ONLY:
                burp_task_id = self._start_crawl_only(target_url, options)
            elif scan_type == BurpScanType.AUDIT_ONLY:
                burp_task_id = self._start_audit_only(target_url, options)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
            
            self.active_scans[scan_id]["burp_task_id"] = burp_task_id
            
            # Monitor scan progress
            self._monitor_scan_progress(scan_id, burp_task_id)
            
            # Get final results
            results = self._get_scan_results(burp_task_id, target_url, scan_type)
            
            self.active_scans[scan_id].update({
                "status": "completed",
                "progress": 100,
                "results": results,
                "end_time": datetime.now()
            })
            
        except Exception as e:
            logger.error(f"Burp Suite scan error: {e}")
            self.active_scans[scan_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
    
    def _start_crawl_and_audit(self, target_url: str, options: Dict) -> str:
        """Start crawl and audit scan"""
        scan_config = {
            "urls": [target_url],
            "application_logins": options.get("logins", []),
            "resource_pool": options.get("resource_pool", "default")
        }
        
        # Add scan configuration
        if options.get("scan_configuration_library_id"):
            scan_config["scan_configuration_library_id"] = options["scan_configuration_library_id"]
        
        response = self.session.post(
            f"{self.api_url}/burp/scanner/scans/active",
            json=scan_config
        )
        
        if response.status_code != 201:
            raise RuntimeError(f"Failed to start Burp scan: {response.text}")
        
        return response.json()["task_id"]
    
    def _start_crawl_only(self, target_url: str, options: Dict) -> str:
        """Start crawl-only scan"""
        crawl_config = {
            "urls": [target_url],
            "application_logins": options.get("logins", []),
            "resource_pool": options.get("resource_pool", "default")
        }
        
        response = self.session.post(
            f"{self.api_url}/burp/spider/scans",
            json=crawl_config
        )
        
        if response.status_code != 201:
            raise RuntimeError(f"Failed to start Burp crawl: {response.text}")
        
        return response.json()["task_id"]
    
    def _start_audit_only(self, target_url: str, options: Dict) -> str:
        """Start audit-only scan"""
        # For audit-only, we need to provide specific URLs or use existing site map
        audit_config = {
            "urls": options.get("audit_urls", [target_url]),
            "resource_pool": options.get("resource_pool", "default")
        }
        
        response = self.session.post(
            f"{self.api_url}/burp/scanner/scans/active",
            json=audit_config
        )
        
        if response.status_code != 201:
            raise RuntimeError(f"Failed to start Burp audit: {response.text}")
        
        return response.json()["task_id"]
    
    def _monitor_scan_progress(self, scan_id: str, burp_task_id: str):
        """Monitor scan progress until completion"""
        while True:
            try:
                # Get scan status
                response = self.session.get(
                    f"{self.api_url}/burp/scanner/scans/{burp_task_id}"
                )
                
                if response.status_code == 200:
                    scan_status = response.json()
                    status = scan_status.get("scan_status", "unknown")
                    
                    # Update progress
                    if "scan_metrics" in scan_status:
                        metrics = scan_status["scan_metrics"]
                        crawl_progress = metrics.get("crawl_requests_made", 0)
                        audit_progress = metrics.get("audit_requests_made", 0)
                        total_progress = min(90, (crawl_progress + audit_progress) // 10)
                        self.active_scans[scan_id]["progress"] = total_progress
                    
                    # Check if scan is complete
                    if status in ["succeeded", "failed", "cancelled"]:
                        break
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring scan progress: {e}")
                break
    
    def _get_scan_results(self, burp_task_id: str, target_url: str,
                         scan_type: BurpScanType) -> BurpScanResult:
        """Get scan results from Burp Suite"""
        try:
            # Get scan issues
            response = self.session.get(
                f"{self.api_url}/burp/scanner/scans/{burp_task_id}"
            )
            
            if response.status_code != 200:
                raise RuntimeError(f"Failed to get scan results: {response.text}")
            
            scan_data = response.json()
            
            # Get detailed issues
            issues_response = self.session.get(
                f"{self.api_url}/burp/scanner/scans/{burp_task_id}/issues"
            )
            
            vulnerabilities = []
            if issues_response.status_code == 200:
                issues_data = issues_response.json()
                vulnerabilities = self._parse_burp_issues(issues_data.get("issues", []))
            
            return BurpScanResult(
                scan_id=burp_task_id,
                target_url=target_url,
                scan_type=scan_type,
                scan_start=datetime.now(),  # Would be better to get from scan_data
                scan_end=datetime.now(),
                status="completed",
                vulnerabilities=vulnerabilities,
                crawl_statistics=scan_data.get("scan_metrics", {}),
                audit_statistics=scan_data.get("audit_metrics", {})
            )
            
        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            return BurpScanResult(
                scan_id=burp_task_id,
                target_url=target_url,
                scan_type=scan_type,
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                status="failed",
                vulnerabilities=[],
                crawl_statistics={},
                audit_statistics={},
                error_message=str(e)
            )
    
    def _parse_burp_issues(self, issues: List[Dict]) -> List[BurpVulnerability]:
        """Parse Burp Suite issues into vulnerability objects"""
        vulnerabilities = []
        
        for issue in issues:
            try:
                # Map severity
                severity_map = {
                    "high": VulnerabilitySeverity.HIGH,
                    "medium": VulnerabilitySeverity.MEDIUM,
                    "low": VulnerabilitySeverity.LOW,
                    "information": VulnerabilitySeverity.INFO
                }
                severity = severity_map.get(issue.get("severity", "low").lower(), VulnerabilitySeverity.LOW)
                
                # Map confidence
                confidence_map = {
                    "certain": VulnerabilityConfidence.CERTAIN,
                    "firm": VulnerabilityConfidence.FIRM,
                    "tentative": VulnerabilityConfidence.TENTATIVE
                }
                confidence = confidence_map.get(issue.get("confidence", "tentative").lower(), VulnerabilityConfidence.TENTATIVE)
                
                # Get issue type name
                issue_type_id = str(issue.get("type_index", ""))
                issue_type = self.issue_type_mappings.get(issue_type_id, issue.get("issue_type", "Unknown"))
                
                vulnerability = BurpVulnerability(
                    issue_id=str(issue.get("serial_number", "")),
                    issue_name=issue.get("issue_name", "Unknown Issue"),
                    issue_type=issue_type,
                    url=issue.get("url", ""),
                    severity=severity,
                    confidence=confidence,
                    description=issue.get("issue_detail", ""),
                    remediation=issue.get("remediation_detail", ""),
                    vulnerability_classifications=issue.get("vulnerability_classifications", []),
                    request_response={
                        "request": issue.get("request", ""),
                        "response": issue.get("response", "")
                    }
                )
                
                vulnerabilities.append(vulnerability)
                
            except Exception as e:
                logger.warning(f"Failed to parse Burp issue: {e}")
                continue
        
        return vulnerabilities
    
    def get_scan_configurations(self) -> List[Dict]:
        """Get available scan configurations from Burp Suite"""
        try:
            response = self.session.get(f"{self.api_url}/burp/configuration/scanconfigurations")
            if response.status_code == 200:
                return response.json().get("configurations", [])
        except Exception as e:
            logger.error(f"Failed to get scan configurations: {e}")
        return []
    
    def create_application_login(self, login_config: Dict) -> str:
        """Create application login configuration"""
        try:
            response = self.session.post(
                f"{self.api_url}/burp/configuration/applicationlogins",
                json=login_config
            )
            if response.status_code == 201:
                return response.json().get("id", "")
        except Exception as e:
            logger.error(f"Failed to create application login: {e}")
        return ""
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a running scan"""
        return self.active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            burp_task_id = self.active_scans[scan_id].get("burp_task_id")
            if burp_task_id:
                try:
                    response = self.session.delete(
                        f"{self.api_url}/burp/scanner/scans/{burp_task_id}"
                    )
                    if response.status_code == 200:
                        self.active_scans[scan_id]["status"] = "cancelled"
                        return True
                except Exception as e:
                    logger.error(f"Failed to cancel Burp scan: {e}")
            
            self.active_scans[scan_id]["status"] = "cancelled"
            return True
        return False
    
    def export_scan_report(self, scan_id: str, report_format: str = "html") -> Optional[bytes]:
        """Export scan report in specified format"""
        if scan_id not in self.active_scans:
            return None
        
        burp_task_id = self.active_scans[scan_id].get("burp_task_id")
        if not burp_task_id:
            return None
        
        try:
            # Request report generation
            report_config = {
                "report_type": report_format,
                "include_false_positives": False
            }
            
            response = self.session.post(
                f"{self.api_url}/burp/scanner/scans/{burp_task_id}/report",
                json=report_config
            )
            
            if response.status_code == 200:
                return response.content
            
        except Exception as e:
            logger.error(f"Failed to export scan report: {e}")
        
        return None
    
    def get_site_map(self, target_url: str) -> List[Dict]:
        """Get site map for target URL"""
        try:
            response = self.session.get(
                f"{self.api_url}/burp/target/sitemap",
                params={"urlprefix": target_url}
            )
            
            if response.status_code == 200:
                return response.json().get("messages", [])
            
        except Exception as e:
            logger.error(f"Failed to get site map: {e}")
        
        return []
    
    def send_to_repeater(self, request_data: Dict) -> bool:
        """Send request to Burp Repeater"""
        try:
            response = self.session.post(
                f"{self.api_url}/burp/repeater/simple",
                json=request_data
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send to repeater: {e}")
            return False
    
    def get_proxy_history(self, target_url: str = None) -> List[Dict]:
        """Get proxy history, optionally filtered by target URL"""
        try:
            params = {}
            if target_url:
                params["urlprefix"] = target_url
            
            response = self.session.get(
                f"{self.api_url}/burp/proxy/history",
                params=params
            )
            
            if response.status_code == 200:
                return response.json().get("messages", [])
            
        except Exception as e:
            logger.error(f"Failed to get proxy history: {e}")
        
        return []

# Factory function to create Burp Suite integration
def create_burp_integration(api_url: str = None, api_key: str = None) -> BurpSuiteIntegration:
    """Create Burp Suite integration instance"""
    default_url = "http://127.0.0.1:1337"
    return BurpSuiteIntegration(api_url or default_url, api_key)

# Global instance (will need configuration)
burp_integration = None

def initialize_burp_integration(api_url: str = None, api_key: str = None):
    """Initialize global Burp Suite integration"""
    global burp_integration
    burp_integration = create_burp_integration(api_url, api_key)
    return burp_integration