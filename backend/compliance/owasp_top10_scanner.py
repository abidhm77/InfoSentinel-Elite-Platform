#!/usr/bin/env python3
"""
OWASP Top 10 automated testing framework for InfoSentinel.
Implements comprehensive testing for OWASP Top 10 vulnerabilities.
"""
import requests
import re
import json
import time
import random
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class OwaspCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 – Cryptographic Failures"
    A03_INJECTION = "A03:2021 – Injection"
    A04_INSECURE_DESIGN = "A04:2021 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 – Vulnerable and Outdated Components"
    A07_IDENTIFICATION_AUTH_FAILURES = "A07:2021 – Identification and Authentication Failures"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021 – Software and Data Integrity Failures"
    A09_SECURITY_LOGGING_MONITORING = "A09:2021 – Security Logging and Monitoring Failures"
    A10_SERVER_SIDE_REQUEST_FORGERY = "A10:2021 – Server-Side Request Forgery (SSRF)"

@dataclass
class OwaspTestResult:
    """Result of an OWASP test."""
    category: OwaspCategory
    test_name: str
    severity: str
    vulnerable: bool
    evidence: str
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

class OwaspTop10Scanner:
    """
    Comprehensive OWASP Top 10 vulnerability scanner.
    """
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        """
        Initialize the OWASP Top 10 scanner.
        
        Args:
            target_url: Base URL of the target application
            session: Optional requests session for authentication
        """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'InfoSentinel-OWASP-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        # Test payloads and patterns
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        self.command_injection_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        self.results = []
    
    def scan_all_categories(self) -> List[OwaspTestResult]:
        """
        Perform comprehensive OWASP Top 10 scanning.
        
        Returns:
            List of test results
        """
        logger.info(f"Starting OWASP Top 10 scan for {self.target_url}")
        
        # A01: Broken Access Control
        self.results.extend(self._test_broken_access_control())
        
        # A02: Cryptographic Failures
        self.results.extend(self._test_cryptographic_failures())
        
        # A03: Injection
        self.results.extend(self._test_injection_vulnerabilities())
        
        # A04: Insecure Design
        self.results.extend(self._test_insecure_design())
        
        # A05: Security Misconfiguration
        self.results.extend(self._test_security_misconfiguration())
        
        # A06: Vulnerable and Outdated Components
        self.results.extend(self._test_vulnerable_components())
        
        # A07: Identification and Authentication Failures
        self.results.extend(self._test_auth_failures())
        
        # A08: Software and Data Integrity Failures
        self.results.extend(self._test_integrity_failures())
        
        # A09: Security Logging and Monitoring Failures
        self.results.extend(self._test_logging_monitoring())
        
        # A10: Server-Side Request Forgery
        self.results.extend(self._test_ssrf())
        
        logger.info(f"OWASP Top 10 scan completed. Found {len([r for r in self.results if r.vulnerable])} vulnerabilities")
        
        return self.results
    
    def _test_broken_access_control(self) -> List[OwaspTestResult]:
        """Test for A01: Broken Access Control vulnerabilities."""
        results = []
        
        # Test for directory traversal
        for payload in self.path_traversal_payloads:
            try:
                test_url = f"{self.target_url}/file?path={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if self._check_path_traversal_response(response):
                    results.append(OwaspTestResult(
                        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
                        test_name="Directory Traversal",
                        severity="high",
                        vulnerable=True,
                        evidence=f"Path traversal successful with payload: {payload}",
                        description="Application allows access to files outside the intended directory",
                        remediation="Implement proper input validation and use secure file access methods",
                        cwe_id="CWE-22",
                        cvss_score=7.5
                    ))
                    break
            except Exception as e:
                logger.debug(f"Error testing path traversal: {str(e)}")
        
        # Test for insecure direct object references
        results.extend(self._test_idor())
        
        # Test for privilege escalation
        results.extend(self._test_privilege_escalation())
        
        # Test for forced browsing
        results.extend(self._test_forced_browsing())
        
        return results
    
    def _test_cryptographic_failures(self) -> List[OwaspTestResult]:
        """Test for A02: Cryptographic Failures."""
        results = []
        
        # Test for weak SSL/TLS configuration
        results.extend(self._test_ssl_tls_configuration())
        
        # Test for sensitive data exposure
        results.extend(self._test_sensitive_data_exposure())
        
        # Test for weak encryption
        results.extend(self._test_weak_encryption())
        
        return results
    
    def _test_injection_vulnerabilities(self) -> List[OwaspTestResult]:
        """Test for A03: Injection vulnerabilities."""
        results = []
        
        # Test for SQL injection
        results.extend(self._test_sql_injection())
        
        # Test for XSS
        results.extend(self._test_xss())
        
        # Test for command injection
        results.extend(self._test_command_injection())
        
        # Test for LDAP injection
        results.extend(self._test_ldap_injection())
        
        return results
    
    def _test_insecure_design(self) -> List[OwaspTestResult]:
        """Test for A04: Insecure Design."""
        results = []
        
        # Test for business logic flaws
        results.extend(self._test_business_logic_flaws())
        
        # Test for insufficient rate limiting
        results.extend(self._test_rate_limiting())
        
        # Test for insecure workflows
        results.extend(self._test_insecure_workflows())
        
        return results
    
    def _test_security_misconfiguration(self) -> List[OwaspTestResult]:
        """Test for A05: Security Misconfiguration."""
        results = []
        
        # Test for default credentials
        results.extend(self._test_default_credentials())
        
        # Test for information disclosure
        results.extend(self._test_information_disclosure())
        
        # Test for security headers
        results.extend(self._test_security_headers())
        
        # Test for directory listing
        results.extend(self._test_directory_listing())
        
        return results
    
    def _test_vulnerable_components(self) -> List[OwaspTestResult]:
        """Test for A06: Vulnerable and Outdated Components."""
        results = []
        
        # Test for known vulnerable libraries
        results.extend(self._test_vulnerable_libraries())
        
        # Test for outdated software versions
        results.extend(self._test_outdated_versions())
        
        return results
    
    def _test_auth_failures(self) -> List[OwaspTestResult]:
        """Test for A07: Identification and Authentication Failures."""
        results = []
        
        # Test for weak passwords
        results.extend(self._test_weak_passwords())
        
        # Test for session management issues
        results.extend(self._test_session_management())
        
        # Test for authentication bypass
        results.extend(self._test_auth_bypass())
        
        return results
    
    def _test_integrity_failures(self) -> List[OwaspTestResult]:
        """Test for A08: Software and Data Integrity Failures."""
        results = []
        
        # Test for insecure deserialization
        results.extend(self._test_insecure_deserialization())
        
        # Test for supply chain attacks
        results.extend(self._test_supply_chain())
        
        return results
    
    def _test_logging_monitoring(self) -> List[OwaspTestResult]:
        """Test for A09: Security Logging and Monitoring Failures."""
        results = []
        
        # Test for insufficient logging
        results.extend(self._test_insufficient_logging())
        
        # Test for log injection
        results.extend(self._test_log_injection())
        
        return results
    
    def _test_ssrf(self) -> List[OwaspTestResult]:
        """Test for A10: Server-Side Request Forgery."""
        results = []
        
        # Test for SSRF vulnerabilities
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/"
        ]
        
        for payload in ssrf_payloads:
            try:
                test_url = f"{self.target_url}/fetch?url={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if self._check_ssrf_response(response, payload):
                    results.append(OwaspTestResult(
                        category=OwaspCategory.A10_SERVER_SIDE_REQUEST_FORGERY,
                        test_name="Server-Side Request Forgery",
                        severity="high",
                        vulnerable=True,
                        evidence=f"SSRF successful with payload: {payload}",
                        description="Application makes requests to arbitrary URLs specified by user input",
                        remediation="Implement URL validation and use allowlists for external requests",
                        cwe_id="CWE-918",
                        cvss_score=8.5
                    ))
                    break
            except Exception as e:
                logger.debug(f"Error testing SSRF: {str(e)}")
        
        return results
    
    def _test_sql_injection(self) -> List[OwaspTestResult]:
        """Test for SQL injection vulnerabilities."""
        results = []
        
        # Common SQL injection test points
        test_params = ['id', 'user', 'search', 'q', 'name', 'email']
        
        for param in test_params:
            for payload in self.sql_payloads:
                try:
                    test_url = f"{self.target_url}/search?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if self._check_sql_injection_response(response):
                        results.append(OwaspTestResult(
                            category=OwaspCategory.A03_INJECTION,
                            test_name="SQL Injection",
                            severity="critical",
                            vulnerable=True,
                            evidence=f"SQL injection in parameter '{param}' with payload: {payload}",
                            description="Application is vulnerable to SQL injection attacks",
                            remediation="Use parameterized queries and input validation",
                            cwe_id="CWE-89",
                            cvss_score=9.8
                        ))
                        return results  # Stop after first successful injection
                except Exception as e:
                    logger.debug(f"Error testing SQL injection: {str(e)}")
        
        return results
    
    def _test_xss(self) -> List[OwaspTestResult]:
        """Test for Cross-Site Scripting vulnerabilities."""
        results = []
        
        # Test reflected XSS
        for payload in self.xss_payloads:
            try:
                test_url = f"{self.target_url}/search?q={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text and 'text/html' in response.headers.get('content-type', ''):
                    results.append(OwaspTestResult(
                        category=OwaspCategory.A03_INJECTION,
                        test_name="Reflected XSS",
                        severity="high",
                        vulnerable=True,
                        evidence=f"XSS payload reflected: {payload}",
                        description="Application reflects user input without proper encoding",
                        remediation="Implement output encoding and Content Security Policy",
                        cwe_id="CWE-79",
                        cvss_score=7.2
                    ))
                    break
            except Exception as e:
                logger.debug(f"Error testing XSS: {str(e)}")
        
        # Test stored XSS (if forms are available)
        results.extend(self._test_stored_xss())
        
        return results
    
    def _test_command_injection(self) -> List[OwaspTestResult]:
        """Test for command injection vulnerabilities."""
        results = []
        
        for payload in self.command_injection_payloads:
            try:
                test_url = f"{self.target_url}/ping?host=127.0.0.1{payload}"
                response = self.session.get(test_url, timeout=10)
                
                if self._check_command_injection_response(response):
                    results.append(OwaspTestResult(
                        category=OwaspCategory.A03_INJECTION,
                        test_name="Command Injection",
                        severity="critical",
                        vulnerable=True,
                        evidence=f"Command injection successful with payload: {payload}",
                        description="Application executes system commands with user input",
                        remediation="Avoid system calls with user input or use proper input validation",
                        cwe_id="CWE-78",
                        cvss_score=9.8
                    ))
                    break
            except Exception as e:
                logger.debug(f"Error testing command injection: {str(e)}")
        
        return results
    
    def _test_security_headers(self) -> List[OwaspTestResult]:
        """Test for missing security headers."""
        results = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                results.append(OwaspTestResult(
                    category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    test_name="Missing Security Headers",
                    severity="medium",
                    vulnerable=True,
                    evidence=f"Missing headers: {', '.join(missing_headers)}",
                    description="Application lacks important security headers",
                    remediation="Implement all recommended security headers",
                    cwe_id="CWE-16",
                    cvss_score=5.3
                ))
        
        except Exception as e:
            logger.debug(f"Error testing security headers: {str(e)}")
        
        return results
    
    def _test_ssl_tls_configuration(self) -> List[OwaspTestResult]:
        """Test SSL/TLS configuration."""
        results = []
        
        if not self.target_url.startswith('https://'):
            results.append(OwaspTestResult(
                category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                test_name="Insecure Protocol",
                severity="high",
                vulnerable=True,
                evidence="Application not using HTTPS",
                description="Application transmits data over unencrypted HTTP",
                remediation="Implement HTTPS with proper SSL/TLS configuration",
                cwe_id="CWE-319",
                cvss_score=7.4
            ))
        
        return results
    
    def _test_session_management(self) -> List[OwaspTestResult]:
        """Test session management vulnerabilities."""
        results = []
        
        try:
            # Test for session fixation
            response = self.session.get(self.target_url, timeout=10)
            
            # Check for insecure session cookies
            for cookie in response.cookies:
                issues = []
                
                if not cookie.secure and self.target_url.startswith('https://'):
                    issues.append("Missing Secure flag")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                
                if issues:
                    results.append(OwaspTestResult(
                        category=OwaspCategory.A07_IDENTIFICATION_AUTH_FAILURES,
                        test_name="Insecure Session Cookies",
                        severity="medium",
                        vulnerable=True,
                        evidence=f"Cookie '{cookie.name}' has issues: {', '.join(issues)}",
                        description="Session cookies lack proper security attributes",
                        remediation="Set Secure and HttpOnly flags on session cookies",
                        cwe_id="CWE-614",
                        cvss_score=5.4
                    ))
        
        except Exception as e:
            logger.debug(f"Error testing session management: {str(e)}")
        
        return results
    
    # Helper methods for response analysis
    def _check_sql_injection_response(self, response: requests.Response) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"SQLite.*error",
            r"sqlite3.OperationalError",
            r"Microsoft.*ODBC.*SQL Server",
            r"OLE DB.*SQL Server",
            r"Oracle error",
            r"Oracle.*ORA-\d+",
            r"Microsoft JET Database Engine",
            r"Access Database Engine"
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_path_traversal_response(self, response: requests.Response) -> bool:
        """Check if response indicates path traversal vulnerability."""
        traversal_indicators = [
            "root:x:0:0:",  # /etc/passwd
            "[boot loader]",  # Windows boot.ini
            "# localhost name resolution",  # Windows hosts file
            "127.0.0.1\tlocalhost"  # hosts file
        ]
        
        for indicator in traversal_indicators:
            if indicator in response.text:
                return True
        
        return False
    
    def _check_command_injection_response(self, response: requests.Response) -> bool:
        """Check if response indicates command injection vulnerability."""
        command_indicators = [
            "uid=",  # Unix id command
            "gid=",  # Unix id command
            "Directory of",  # Windows dir command
            "Volume in drive",  # Windows dir command
            "total ",  # Unix ls -la command
            "drwx"  # Unix ls -la permissions
        ]
        
        for indicator in command_indicators:
            if indicator in response.text:
                return True
        
        return False
    
    def _check_ssrf_response(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates SSRF vulnerability."""
        # Check for internal service responses
        if "localhost" in payload or "127.0.0.1" in payload:
            if response.status_code == 200 and len(response.text) > 0:
                return True
        
        # Check for AWS metadata service
        if "169.254.169.254" in payload:
            if "ami-id" in response.text or "instance-id" in response.text:
                return True
        
        return False
    
    # Additional test methods (simplified implementations)
    def _test_idor(self) -> List[OwaspTestResult]:
        """Test for Insecure Direct Object References."""
        # Implementation would test for IDOR vulnerabilities
        return []
    
    def _test_privilege_escalation(self) -> List[OwaspTestResult]:
        """Test for privilege escalation vulnerabilities."""
        # Implementation would test for privilege escalation
        return []
    
    def _test_forced_browsing(self) -> List[OwaspTestResult]:
        """Test for forced browsing vulnerabilities."""
        # Implementation would test for forced browsing
        return []
    
    def _test_sensitive_data_exposure(self) -> List[OwaspTestResult]:
        """Test for sensitive data exposure."""
        # Implementation would test for sensitive data exposure
        return []
    
    def _test_weak_encryption(self) -> List[OwaspTestResult]:
        """Test for weak encryption."""
        # Implementation would test for weak encryption
        return []
    
    def _test_ldap_injection(self) -> List[OwaspTestResult]:
        """Test for LDAP injection."""
        # Implementation would test for LDAP injection
        return []
    
    def _test_stored_xss(self) -> List[OwaspTestResult]:
        """Test for stored XSS vulnerabilities."""
        # Implementation would test for stored XSS
        return []
    
    def _test_business_logic_flaws(self) -> List[OwaspTestResult]:
        """Test for business logic flaws."""
        # Implementation would test for business logic flaws
        return []
    
    def _test_rate_limiting(self) -> List[OwaspTestResult]:
        """Test for insufficient rate limiting."""
        # Implementation would test for rate limiting
        return []
    
    def _test_insecure_workflows(self) -> List[OwaspTestResult]:
        """Test for insecure workflows."""
        # Implementation would test for insecure workflows
        return []
    
    def _test_default_credentials(self) -> List[OwaspTestResult]:
        """Test for default credentials."""
        # Implementation would test for default credentials
        return []
    
    def _test_information_disclosure(self) -> List[OwaspTestResult]:
        """Test for information disclosure."""
        # Implementation would test for information disclosure
        return []
    
    def _test_directory_listing(self) -> List[OwaspTestResult]:
        """Test for directory listing vulnerabilities."""
        # Implementation would test for directory listing
        return []
    
    def _test_vulnerable_libraries(self) -> List[OwaspTestResult]:
        """Test for vulnerable libraries."""
        # Implementation would test for vulnerable libraries
        return []
    
    def _test_outdated_versions(self) -> List[OwaspTestResult]:
        """Test for outdated software versions."""
        # Implementation would test for outdated versions
        return []
    
    def _test_weak_passwords(self) -> List[OwaspTestResult]:
        """Test for weak password policies."""
        # Implementation would test for weak passwords
        return []
    
    def _test_auth_bypass(self) -> List[OwaspTestResult]:
        """Test for authentication bypass."""
        # Implementation would test for auth bypass
        return []
    
    def _test_insecure_deserialization(self) -> List[OwaspTestResult]:
        """Test for insecure deserialization."""
        # Implementation would test for insecure deserialization
        return []
    
    def _test_supply_chain(self) -> List[OwaspTestResult]:
        """Test for supply chain vulnerabilities."""
        # Implementation would test for supply chain issues
        return []
    
    def _test_insufficient_logging(self) -> List[OwaspTestResult]:
        """Test for insufficient logging."""
        # Implementation would test for insufficient logging
        return []
    
    def _test_log_injection(self) -> List[OwaspTestResult]:
        """Test for log injection vulnerabilities."""
        # Implementation would test for log injection
        return []
    
    def generate_owasp_report(self) -> Dict:
        """
        Generate comprehensive OWASP Top 10 compliance report.
        
        Returns:
            OWASP compliance report
        """
        if not self.results:
            return {'error': 'No scan results available'}
        
        # Categorize results
        categories = {}
        for result in self.results:
            category = result.category.value
            if category not in categories:
                categories[category] = {
                    'total_tests': 0,
                    'vulnerabilities': 0,
                    'findings': []
                }
            
            categories[category]['total_tests'] += 1
            if result.vulnerable:
                categories[category]['vulnerabilities'] += 1
                categories[category]['findings'].append({
                    'test_name': result.test_name,
                    'severity': result.severity,
                    'evidence': result.evidence,
                    'cwe_id': result.cwe_id,
                    'cvss_score': result.cvss_score
                })
        
        # Calculate compliance score
        total_categories = len(OwaspCategory)
        compliant_categories = len([cat for cat in categories.values() if cat['vulnerabilities'] == 0])
        compliance_score = (compliant_categories / total_categories) * 100
        
        # Generate recommendations
        recommendations = self._generate_owasp_recommendations(categories)
        
        return {
            'target_url': self.target_url,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'owasp_version': '2021',
            'compliance_score': round(compliance_score, 1),
            'summary': {
                'total_categories_tested': len(categories),
                'categories_with_vulnerabilities': len([cat for cat in categories.values() if cat['vulnerabilities'] > 0]),
                'total_vulnerabilities': sum(cat['vulnerabilities'] for cat in categories.values()),
                'critical_vulnerabilities': len([r for r in self.results if r.vulnerable and r.severity == 'critical']),
                'high_vulnerabilities': len([r for r in self.results if r.vulnerable and r.severity == 'high']),
                'medium_vulnerabilities': len([r for r in self.results if r.vulnerable and r.severity == 'medium'])
            },
            'categories': categories,
            'recommendations': recommendations,
            'next_steps': self._generate_next_steps(categories)
        }
    
    def _generate_owasp_recommendations(self, categories: Dict) -> List[str]:
        """Generate OWASP-specific recommendations."""
        recommendations = []
        
        for category, data in categories.items():
            if data['vulnerabilities'] > 0:
                if 'Injection' in category:
                    recommendations.append("Implement input validation and parameterized queries to prevent injection attacks")
                elif 'Access Control' in category:
                    recommendations.append("Implement proper access controls and authorization checks")
                elif 'Cryptographic' in category:
                    recommendations.append("Use strong encryption and secure communication protocols")
                elif 'Security Misconfiguration' in category:
                    recommendations.append("Review and harden security configurations across all systems")
                elif 'Authentication' in category:
                    recommendations.append("Strengthen authentication mechanisms and session management")
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security assessments and penetration testing",
            "Implement security awareness training for development teams",
            "Establish secure development lifecycle (SDLC) practices",
            "Monitor and log security events for threat detection"
        ])
        
        return recommendations
    
    def _generate_next_steps(self, categories: Dict) -> List[str]:
        """Generate next steps based on findings."""
        next_steps = []
        
        critical_vulns = sum(1 for r in self.results if r.vulnerable and r.severity == 'critical')
        high_vulns = sum(1 for r in self.results if r.vulnerable and r.severity == 'high')
        
        if critical_vulns > 0:
            next_steps.append(f"IMMEDIATE: Address {critical_vulns} critical vulnerabilities within 24 hours")
        
        if high_vulns > 0:
            next_steps.append(f"URGENT: Address {high_vulns} high-severity vulnerabilities within 1 week")
        
        next_steps.extend([
            "Implement automated security testing in CI/CD pipeline",
            "Schedule regular OWASP Top 10 compliance assessments",
            "Review and update security policies and procedures",
            "Consider implementing Web Application Firewall (WAF)"
        ])
        
        return next_steps