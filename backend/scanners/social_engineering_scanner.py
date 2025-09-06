import json
import logging
import requests
import dns.resolver
from typing import Dict, List, Any
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class SocialEngineeringScanner:
    """Advanced Social Engineering Security Scanner"""
    
    def __init__(self):
        self.name = "Social Engineering Scanner"
        self.description = "Comprehensive social engineering security assessment including phishing, domain spoofing, and email security"
        self.supported_types = ['social-engineering']
        
    def scan(self, target: str, options: Dict[str, Any] = None, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive social engineering security scan"""
        options = options or {}
        config = config or {}
        
        results = {
            'target': target,
            'scan_type': 'social-engineering',
            'start_time': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'summary': {},
            'recommendations': [],
            'domain_analysis': {}
        }
        
        try:
            # Phase 1: Domain Analysis
            self._update_progress(15, "Analyzing domain security...")
            results['domain_analysis'] = self._analyze_domain(target)
            
            # Phase 2: Email Security
            self._update_progress(35, "Checking email security...")
            email_issues = self._check_email_security(target)
            results['vulnerabilities'].extend(email_issues)
            
            # Phase 3: DNS Security
            self._update_progress(55, "Analyzing DNS security...")
            dns_issues = self._check_dns_security(target)
            results['vulnerabilities'].extend(dns_issues)
            
            # Phase 4: Phishing Detection
            self._update_progress(75, "Checking phishing vulnerabilities...")
            phishing_issues = self._check_phishing_vulnerabilities(target)
            results['vulnerabilities'].extend(phishing_issues)
            
            # Phase 5: Brand Protection
            self._update_progress(90, "Checking brand protection...")
            brand_issues = self._check_brand_protection(target)
            results['vulnerabilities'].extend(brand_issues)
            
            # Phase 6: Final Analysis
            self._update_progress(100, "Finalizing scan results...")
            results['summary'] = self._generate_summary(results['vulnerabilities'])
            results['recommendations'] = self._generate_recommendations(results['vulnerabilities'])
            
        except Exception as e:
            logger.error(f"Social Engineering scan failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _analyze_domain(self, target: str) -> Dict[str, Any]:
        """Analyze domain security configuration"""
        domain_info = {
            'target': target,
            'dns_records': {},
            'ssl_info': {},
            'domain_age': None,
            'typosquatting_domains': []
        }
        
        try:
            # DNS Records Analysis
            domain_info['dns_records'] = self._get_dns_records(target)
            
            # SSL Certificate Analysis
            domain_info['ssl_info'] = self._get_ssl_info(target)
            
            # Domain Age Check
            domain_info['domain_age'] = self._get_domain_age(target)
            
            # Typosquatting Detection
            domain_info['typosquatting_domains'] = self._generate_typosquatting_domains(target)
            
        except Exception as e:
            logger.error(f"Domain analysis error: {str(e)}")
            
        return domain_info
    
    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records for the domain"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                records[record_type] = []
        
        return records
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        ssl_info = {}
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': [x[1] for x in cert.get('subjectAltName', [])]
                    }
        except Exception as e:
            ssl_info['error'] = str(e)
            
        return ssl_info
    
    def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days"""
        try:
            import whois
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                age = (datetime.now() - creation_date).days
                return age
        except:
            pass
        return None
    
    def _generate_typosquatting_domains(self, domain: str) -> List[str]:
        """Generate potential typosquatting domains"""
        typos = []
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            base = domain_parts[0]
            tld = '.'.join(domain_parts[1:])
            
            # Common typosquatting patterns
            patterns = [
                # Character omissions
                base[:-1] + tld,
                base[1:] + tld,
                # Character substitutions
                base.replace('o', '0') + tld,
                base.replace('l', '1') + tld,
                # Character additions
                base + 's' + tld,
                base + 'z' + tld,
                # Common misspellings
                base.replace('google', 'gogle') + tld,
                base.replace('facebook', 'facebok') + tld,
            ]
            
            typos = [f"{pattern}.{tld}" for pattern in patterns if pattern != base]
            
        return typos[:10]
    
    def _check_email_security(self, target: str) -> List[Dict[str, Any]]:
        """Check email security configurations"""
        issues = []
        
        # SPF Record Check
        spf_record = self._check_spf_record(target)
        if not spf_record:
            issues.append({
                'title': 'Missing SPF Record',
                'description': f'Domain {target} lacks SPF (Sender Policy Framework) record',
                'severity': 'high',
                'proof_of_concept': f'No SPF record found for {target}',
                'remediation': f'Add SPF TXT record to DNS for {target}'
            })
        
        # DMARC Record Check
        dmarc_record = self._check_dmarc_record(target)
        if not dmarc_record:
            issues.append({
                'title': 'Missing DMARC Record',
                'description': f'Domain {target} lacks DMARC (Domain-based Message Authentication) record',
                'severity': 'high',
                'proof_of_concept': f'No DMARC record found for {target}',
                'remediation': f'Add DMARC TXT record to DNS for {target}'
            })
        
        # DKIM Record Check
        dkim_record = self._check_dkim_record(target)
        if not dkim_record:
            issues.append({
                'title': 'Missing DKIM Record',
                'description': f'Domain {target} lacks DKIM (DomainKeys Identified Mail) record',
                'severity': 'medium',
                'proof_of_concept': f'No DKIM record found for {target}',
                'remediation': f'Configure DKIM signing for {target}'
            })
        
        return issues
    
    def _check_spf_record(self, domain: str) -> bool:
        """Check if domain has SPF record"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for answer in answers:
                if 'v=spf1' in str(answer):
                    return True
        except:
            pass
        return False
    
    def _check_dmarc_record(self, domain: str) -> bool:
        """Check if domain has DMARC record"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                if 'v=DMARC1' in str(answer):
                    return True
        except:
            pass
        return False
    
    def _check_dkim_record(self, domain: str) -> bool:
        """Check if domain has DKIM record"""
        try:
            # Try common DKIM selectors
            selectors = ['default', 'google', 'mail', 'selector1', 'selector2']
            for selector in selectors:
                dkim_domain = f"{selector}._domainkey.{domain}"
                try:
                    answers = dns.resolver.resolve(dkim_domain, 'TXT')
                    for answer in answers:
                        if 'v=DKIM1' in str(answer):
                            return True
                except:
                    continue
        except:
            pass
        return False
    
    def _check_dns_security(self, target: str) -> List[Dict[str, Any]]:
        """Check DNS security configurations"""
        issues = []
        
        # DNSSEC Check
        dnssec_enabled = self._check_dnssec(target)
        if not dnssec_enabled:
            issues.append({
                'title': 'DNSSEC Not Enabled',
                'description': f'Domain {target} does not have DNSSEC enabled',
                'severity': 'medium',
                'proof_of_concept': f'No DNSSEC records found for {target}',
                'remediation': f'Enable DNSSEC for {target} domain'
            })
        
        # CAA Record Check
        caa_record = self._check_caa_record(target)
        if not caa_record:
            issues.append({
                'title': 'Missing CAA Record',
                'description': f'Domain {target} lacks CAA (Certificate Authority Authorization) record',
                'severity': 'medium',
                'proof_of_concept': f'No CAA record found for {target}',
                'remediation': f'Add CAA record to DNS for {target}'
            })
        
        return issues
    
    def _check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled"""
        try:
            import dns.dnssec
            answer = dns.resolver.resolve(domain, 'A', want_dnssec=True)
            return bool(answer.response.flags & dns.flags.AD)
        except:
            pass
        return False
    
    def _check_caa_record(self, domain: str) -> bool:
        """Check if domain has CAA record"""
        try:
            answers = dns.resolver.resolve(domain, 'CAA')
            return len(answers) > 0
        except:
            pass
        return False
    
    def _check_phishing_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Check for phishing-related vulnerabilities"""
        issues = []
        
        # Subdomain takeover check
        takeover_vulnerable = self._check_subdomain_takeover(target)
        if takeover_vulnerable:
            issues.append({
                'title': 'Subdomain Takeover Risk',
                'description': f'Domain {target} has subdomains vulnerable to takeover',
                'severity': 'high',
                'proof_of_concept': f'Unclaimed subdomains detected for {target}',
                'remediation': f'Remove or secure unused subdomains for {target}'
            })
        
        # Open redirect check
        open_redirects = self._check_open_redirects(target)
        for redirect in open_redirects:
            issues.append({
                'title': 'Open Redirect Vulnerability',
                'description': f'Website {target} has open redirect vulnerability',
                'severity': 'medium',
                'proof_of_concept': f'Open redirect found: {redirect}',
                'remediation': f'Validate redirect URLs on {target}'
            })
        
        return issues
    
    def _check_subdomain_takeover(self, domain: str) -> bool:
        """Check for subdomain takeover vulnerabilities"""
        try:
            # Common subdomain enumeration
            subdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'dev', 'test', 'staging']
            for subdomain in subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    dns.resolver.resolve(full_domain, 'A')
                except dns.resolver.NXDOMAIN:
                    # Check if subdomain can be claimed
                    return True
        except:
            pass
        return False
    
    def _check_open_redirects(self, domain: str) -> List[str]:
        """Check for open redirect vulnerabilities"""
        redirects = []
        try:
            # Check common redirect parameters
            redirect_params = ['redirect', 'url', 'return', 'next', 'continue']
            test_urls = [f"https://{domain}/?{param}=http://evil.com" for param in redirect_params]
            
            for url in test_urls:
                response = requests.get(url, allow_redirects=False, timeout=5)
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        redirects.append(url)
        except:
            pass
        
        return redirects[:5]
    
    def _check_brand_protection(self, target: str) -> List[Dict[str, Any]]:
        """Check brand protection measures"""
        issues = []
        
        # Similar domain registration check
        similar_domains = self._check_similar_domains(target)
        if similar_domains:
            issues.append({
                'title': 'Unprotected Brand Domains',
                'description': f'Similar domains to {target} may be available for registration',
                'severity': 'medium',
                'proof_of_concept': f'Similar domains detected: {", ".join(similar_domains[:3])}',
                'remediation': f'Register and protect similar domain variations for {target}'
            })
        
        return issues
    
    def _check_similar_domains(self, domain: str) -> List[str]:
        """Check for similar domain registrations"""
        similar = []
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            base = domain_parts[0]
            tlds = ['.com', '.net', '.org', '.info', '.biz', '.co', '.io']
            
            variations = [
                base + 's',
                base + 'z',
                base.replace('o', '0'),
                base.replace('l', '1'),
                base.replace('a', '4'),
                base.replace('e', '3')
            ]
            
            for variation in variations:
                for tld in tlds:
                    similar_domain = f"{variation}{tld}"
                    if similar_domain != domain:
                        similar.append(similar_domain)
        
        return similar[:10]
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'social_engineering_specific': True
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate social engineering security recommendations"""
        recommendations = [
            'Implement comprehensive email security protocols (SPF, DKIM, DMARC)',
            'Enable DNSSEC for all domains',
            'Register and protect brand-related domain variations',
            'Implement subdomain takeover prevention measures',
            'Conduct regular phishing simulation exercises',
            'Provide security awareness training to employees',
            'Implement email filtering and anti-phishing solutions',
            'Use SSL/TLS certificates from reputable CAs',
            'Monitor for brand abuse and domain spoofing',
            'Implement DMARC policy enforcement (p=quarantine or p=reject)'
        ]
        
        return recommendations
    
    def _update_progress(self, progress: int, message: str):
        """Update scan progress"""
        logger.info(f"Social Engineering Scan: {progress}% - {message}")