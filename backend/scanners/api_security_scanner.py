import requests
import json
import time
import logging
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

class APISecurityScanner:
    """Advanced API Security Scanner with comprehensive testing capabilities"""
    
    def __init__(self):
        self.name = "API Security Scanner"
        self.description = "Comprehensive API security testing including OWASP API Security Top 10"
        self.supported_types = ['api-security']
        
    def scan(self, target: str, options: Dict[str, Any] = None, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive API security scan"""
        options = options or {}
        config = config or {}
        
        results = {
            'target': target,
            'scan_type': 'api-security',
            'start_time': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'summary': {},
            'recommendations': []
        }
        
        try:
            # Phase 1: API Discovery
            self._update_progress(10, "Discovering API endpoints...")
            endpoints = self._discover_endpoints(target, config)
            
            # Phase 2: Authentication Testing
            self._update_progress(25, "Testing authentication mechanisms...")
            auth_issues = self._test_authentication(target, endpoints, config)
            results['vulnerabilities'].extend(auth_issues)
            
            # Phase 3: Authorization Testing
            self._update_progress(40, "Testing authorization controls...")
            authz_issues = self._test_authorization(target, endpoints, config)
            results['vulnerabilities'].extend(authz_issues)
            
            # Phase 4: Input Validation Testing
            self._update_progress(55, "Testing input validation...")
            input_issues = self._test_input_validation(target, endpoints, config)
            results['vulnerabilities'].extend(input_issues)
            
            # Phase 5: Rate Limiting Testing
            self._update_progress(70, "Testing rate limiting...")
            rate_issues = self._test_rate_limiting(target, endpoints, config)
            results['vulnerabilities'].extend(rate_issues)
            
            # Phase 6: Security Headers Testing
            self._update_progress(85, "Testing security headers...")
            header_issues = self._test_security_headers(target, endpoints)
            results['vulnerabilities'].extend(header_issues)
            
            # Phase 7: Final Analysis
            self._update_progress(100, "Finalizing scan results...")
            results['summary'] = self._generate_summary(results['vulnerabilities'])
            results['recommendations'] = self._generate_recommendations(results['vulnerabilities'])
            
        except Exception as e:
            logger.error(f"API Security scan failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _discover_endpoints(self, target: str, config: Dict[str, Any]) -> List[str]:
        """Discover API endpoints through various methods"""
        endpoints = []
        
        # Common API endpoints to test
        common_endpoints = [
            '/api/v1/users',
            '/api/v1/auth/login',
            '/api/v1/auth/register',
            '/api/v1/profile',
            '/api/v1/settings',
            '/api/v1/data',
            '/api/v1/upload',
            '/api/v1/search',
            '/api/v1/admin',
            '/api/health',
            '/api/docs',
            '/swagger.json',
            '/openapi.json'
        ]
        
        for endpoint in common_endpoints:
            url = urljoin(target, endpoint)
            try:
                response = requests.get(url, timeout=config.get('timeout', 30))
                if response.status_code != 404:
                    endpoints.append(url)
            except:
                continue
        
        return endpoints
    
    def _test_authentication(self, target: str, endpoints: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test authentication mechanisms"""
        issues = []
        
        # Test for broken authentication
        for endpoint in endpoints:
            # Test without authentication
            try:
                response = requests.get(endpoint, timeout=config.get('timeout', 30))
                if response.status_code == 200:
                    issues.append({
                        'title': 'Broken Authentication',
                        'description': f'Endpoint {endpoint} accessible without authentication',
                        'severity': 'high',
                        'url': endpoint,
                        'proof_of_concept': f'GET request to {endpoint} returned {response.status_code}',
                        'remediation': 'Implement proper authentication for all API endpoints'
                    })
            except:
                continue
        
        return issues
    
    def _test_authorization(self, target: str, endpoints: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test authorization controls"""
        issues = []
        
        # Test for broken object level authorization (BOLA)
        for endpoint in endpoints:
            if '/users/' in endpoint or '/data/' in endpoint:
                # Test IDOR vulnerabilities
                for user_id in [1, 2, 3, 9999]:
                    test_url = endpoint.replace('/1/', f'/{user_id}/')
                    try:
                        response = requests.get(test_url, timeout=config.get('timeout', 30))
                        if response.status_code == 200:
                            issues.append({
                                'title': 'Broken Object Level Authorization',
                                'description': f'Potential IDOR vulnerability in {test_url}',
                                'severity': 'high',
                                'url': test_url,
                                'proof_of_concept': f'Access to user {user_id} data possible',
                                'remediation': 'Implement proper authorization checks for object-level access'
                            })
                    except:
                        continue
        
        return issues
    
    def _test_input_validation(self, target: str, endpoints: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test input validation"""
        issues = []
        
        # Test for SQL injection
        payloads = [
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "1' OR 1=1#",
            "1' UNION SELECT * FROM users--"
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                try:
                    response = requests.get(f"{endpoint}?id={payload}", timeout=config.get('timeout', 30))
                    if any(keyword in response.text.lower() for keyword in ['mysql', 'sqlite', 'postgresql', 'sqlserver']):
                        issues.append({
                            'title': 'SQL Injection',
                            'description': f'SQL injection vulnerability in {endpoint}',
                            'severity': 'critical',
                            'url': endpoint,
                            'parameter': 'id',
                            'proof_of_concept': f'Payload: {payload}',
                            'remediation': 'Use parameterized queries and input validation'
                        })
                except:
                    continue
        
        return issues
    
    def _test_rate_limiting(self, target: str, endpoints: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test rate limiting"""
        issues = []
        
        for endpoint in endpoints:
            # Send multiple rapid requests
            start_time = time.time()
            responses = []
            
            for i in range(50):
                try:
                    response = requests.get(endpoint, timeout=5)
                    responses.append(response.status_code)
                except:
                    break
            
            # Check if all requests succeeded (indicating no rate limiting)
            if len(responses) == 50 and all(code == 200 for code in responses):
                issues.append({
                    'title': 'Missing Rate Limiting',
                    'description': f'No rate limiting detected on {endpoint}',
                    'severity': 'medium',
                    'url': endpoint,
                    'proof_of_concept': '50 rapid requests succeeded without restriction',
                    'remediation': 'Implement rate limiting to prevent abuse'
                })
        
        return issues
    
    def _test_security_headers(self, target: str, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Test security headers"""
        issues = []
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=30)
                missing_headers = [h for h in required_headers if h not in response.headers]
                
                if missing_headers:
                    issues.append({
                        'title': 'Missing Security Headers',
                        'description': f'Missing security headers on {endpoint}',
                        'severity': 'medium',
                        'url': endpoint,
                        'proof_of_concept': f'Missing headers: {", ".join(missing_headers)}',
                        'remediation': 'Add appropriate security headers to API responses'
                    })
            except:
                continue
        
        return issues
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'scan_coverage': 'comprehensive'
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(v.get('title') == 'Broken Authentication' for v in vulnerabilities):
            recommendations.append('Implement robust authentication mechanisms using OAuth 2.0 or JWT tokens')
        
        if any(v.get('title') == 'Broken Object Level Authorization' for v in vulnerabilities):
            recommendations.append('Implement proper authorization checks for all object-level access')
        
        if any(v.get('title') == 'SQL Injection' for v in vulnerabilities):
            recommendations.append('Use parameterized queries and implement comprehensive input validation')
        
        if any(v.get('title') == 'Missing Rate Limiting' for v in vulnerabilities):
            recommendations.append('Implement rate limiting to prevent API abuse and DDoS attacks')
        
        if any(v.get('title') == 'Missing Security Headers' for v in vulnerabilities):
            recommendations.append('Add comprehensive security headers to all API responses')
        
        recommendations.append('Regularly update API dependencies and perform security audits')
        recommendations.append('Implement comprehensive logging and monitoring for API security events')
        
        return recommendations
    
    def _update_progress(self, progress: int, message: str):
        """Update scan progress"""
        # This would be implemented to update the database
        logger.info(f"API Security Scan: {progress}% - {message}")