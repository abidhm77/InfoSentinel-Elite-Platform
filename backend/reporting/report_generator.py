"""
Professional security report generator.
Generates detailed security reports with remediation guidance.
"""
import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """Generator for professional security reports."""
    
    def __init__(self):
        """Initialize the report generator."""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.env = Environment(loader=FileSystemLoader(template_dir))
    
    def generate_report(self, scan_data, report_type="standard"):
        """
        Generate a security report based on scan data.
        
        Args:
            scan_data: Data from the security scan
            report_type: Type of report to generate (standard, executive, compliance)
        
        Returns:
            Generated report as HTML
        """
        if report_type == "executive":
            return self._generate_executive_report(scan_data)
        elif report_type == "compliance":
            return self._generate_compliance_report(scan_data)
        else:
            return self._generate_standard_report(scan_data)
    
    def _generate_standard_report(self, scan_data):
        """
        Generate a standard security report.
        
        Args:
            scan_data: Data from the security scan
        
        Returns:
            Standard report as HTML
        """
        template = self.env.get_template('standard_report.html')
        
        # Process scan results
        vulnerabilities = scan_data.get('results', [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Generate report
        report = template.render(
            scan_id=scan_data.get('_id', 'Unknown'),
            target=scan_data.get('target', 'Unknown'),
            scan_type=scan_data.get('scan_type', 'Unknown'),
            start_time=scan_data.get('start_time', datetime.utcnow()),
            end_time=scan_data.get('end_time', datetime.utcnow()),
            duration=self._calculate_duration(scan_data),
            status=scan_data.get('status', 'Unknown'),
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts,
            vuln_by_type=vuln_by_type,
            risk_score=risk_score,
            report_date=datetime.utcnow()
        )
        
        return report
    
    def _generate_executive_report(self, scan_data):
        """
        Generate an executive summary report.
        
        Args:
            scan_data: Data from the security scan
        
        Returns:
            Executive report as HTML
        """
        template = self.env.get_template('executive_report.html')
        
        # Process scan results
        vulnerabilities = scan_data.get('results', [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Get top 5 critical findings
        critical_findings = []
        for vuln in sorted(vulnerabilities, key=lambda x: self._get_severity_value(x.get('severity', 'info')), reverse=True):
            if len(critical_findings) < 5:
                critical_findings.append(vuln)
        
        # Generate report
        report = template.render(
            scan_id=scan_data.get('_id', 'Unknown'),
            target=scan_data.get('target', 'Unknown'),
            scan_type=scan_data.get('scan_type', 'Unknown'),
            start_time=scan_data.get('start_time', datetime.utcnow()),
            end_time=scan_data.get('end_time', datetime.utcnow()),
            duration=self._calculate_duration(scan_data),
            status=scan_data.get('status', 'Unknown'),
            severity_counts=severity_counts,
            risk_score=risk_score,
            critical_findings=critical_findings,
            report_date=datetime.utcnow()
        )
        
        return report
    
    def _generate_compliance_report(self, scan_data):
        """
        Generate a compliance-focused security report.
        
        Args:
            scan_data: Data from the security scan
        
        Returns:
            Compliance report as HTML
        """
        template = self.env.get_template('compliance_report.html')
        
        # Process scan results
        vulnerabilities = scan_data.get('results', [])
        
        # Map vulnerabilities to compliance frameworks
        compliance_frameworks = {
            'owasp_top_10': {
                'name': 'OWASP Top 10',
                'categories': {
                    'A01': {'name': 'Broken Access Control', 'vulns': []},
                    'A02': {'name': 'Cryptographic Failures', 'vulns': []},
                    'A03': {'name': 'Injection', 'vulns': []},
                    'A04': {'name': 'Insecure Design', 'vulns': []},
                    'A05': {'name': 'Security Misconfiguration', 'vulns': []},
                    'A06': {'name': 'Vulnerable Components', 'vulns': []},
                    'A07': {'name': 'Auth Failures', 'vulns': []},
                    'A08': {'name': 'Software and Data Integrity Failures', 'vulns': []},
                    'A09': {'name': 'Logging Failures', 'vulns': []},
                    'A10': {'name': 'SSRF', 'vulns': []}
                }
            },
            'pci_dss': {
                'name': 'PCI DSS',
                'categories': {
                    '1': {'name': 'Install and maintain a firewall', 'vulns': []},
                    '2': {'name': 'Do not use vendor-supplied defaults', 'vulns': []},
                    '3': {'name': 'Protect stored cardholder data', 'vulns': []},
                    '4': {'name': 'Encrypt transmission of data', 'vulns': []},
                    '5': {'name': 'Use and update anti-virus', 'vulns': []},
                    '6': {'name': 'Develop and maintain secure systems', 'vulns': []},
                    '7': {'name': 'Restrict access to data', 'vulns': []},
                    '8': {'name': 'Assign unique ID to each person', 'vulns': []},
                    '9': {'name': 'Restrict physical access', 'vulns': []},
                    '10': {'name': 'Track and monitor access', 'vulns': []},
                    '11': {'name': 'Regularly test security systems', 'vulns': []},
                    '12': {'name': 'Maintain security policy', 'vulns': []}
                }
            },
            'nca': {
                'name': 'NCA',
                'categories': {
                    '1': {'name': 'Governance and Risk Management', 'vulns': []},
                    '2': {'name': 'Incident Response and Management', 'vulns': []},
                    '3': {'name': 'Access Control and Identity Management', 'vulns': []},
                    '4': {'name': 'Data Protection and Privacy', 'vulns': []},
                    '5': {'name': 'Business Continuity and Disaster Recovery', 'vulns': []}
                }
            },
            'sama': {
                'name': 'SAMA',
                'categories': {
                    '1': {'name': 'Cybersecurity Governance', 'vulns': []},
                    '2': {'name': 'Cybersecurity Risk Management', 'vulns': []},
                    '3': {'name': 'Cybersecurity Operations', 'vulns': []},
                    '4': {'name': 'Third-Party Risk Management', 'vulns': []}
                }
            }
        }
        
        # Map vulnerabilities to compliance frameworks
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            
            # Map to OWASP Top 10
            if vuln_type in ['xss', 'csrf', 'script_injection']:
                compliance_frameworks['owasp_top_10']['categories']['A03']['vulns'].append(vuln)
            elif vuln_type in ['sql_injection', 'command_injection']:
                compliance_frameworks['owasp_top_10']['categories']['A03']['vulns'].append(vuln)
            elif vuln_type in ['broken_auth', 'weak_password']:
                compliance_frameworks['owasp_top_10']['categories']['A07']['vulns'].append(vuln)
            elif vuln_type in ['security_header', 'misconfiguration']:
                compliance_frameworks['owasp_top_10']['categories']['A05']['vulns'].append(vuln)
            elif vuln_type in ['sensitive_data', 'data_exposure']:
                compliance_frameworks['owasp_top_10']['categories']['A02']['vulns'].append(vuln)
            
            # Map to PCI DSS
            if vuln_type in ['firewall', 'port_scan']:
                compliance_frameworks['pci_dss']['categories']['1']['vulns'].append(vuln)
            elif vuln_type in ['default_credential', 'weak_password']:
                compliance_frameworks['pci_dss']['categories']['2']['vulns'].append(vuln)
            elif vuln_type in ['sensitive_data', 'data_exposure']:
                compliance_frameworks['pci_dss']['categories']['3']['vulns'].append(vuln)
            elif vuln_type in ['ssl', 'tls', 'encryption']:
                compliance_frameworks['pci_dss']['categories']['4']['vulns'].append(vuln)
            elif vuln_type in ['security_header', 'misconfiguration']:
                compliance_frameworks['pci_dss']['categories']['6']['vulns'].append(vuln)
        
        # Generate report
        report = template.render(
            scan_id=scan_data.get('_id', 'Unknown'),
            target=scan_data.get('target', 'Unknown'),
            scan_type=scan_data.get('scan_type', 'Unknown'),
            start_time=scan_data.get('start_time', datetime.utcnow()),
            end_time=scan_data.get('end_time', datetime.utcnow()),
            duration=self._calculate_duration(scan_data),
            status=scan_data.get('status', 'Unknown'),
            compliance_frameworks=compliance_frameworks,
            report_date=datetime.utcnow()
        )
        
        return report
    
    def _calculate_duration(self, scan_data):
        """
        Calculate the duration of a scan.
        
        Args:
            scan_data: Data from the security scan
        
        Returns:
            Duration in seconds
        """
        start_time = scan_data.get('start_time')
        end_time = scan_data.get('end_time')
        
        if start_time and end_time:
            return (end_time - start_time).total_seconds()
        
        return 0
    
    def _calculate_risk_score(self, vulnerabilities):
        """
        Calculate a risk score based on vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Risk score (0-100)
        """
        if not vulnerabilities:
            return 0
        
        # Severity weights
        weights = {
            'critical': 10,
            'high': 5,
            'medium': 3,
            'low': 1,
            'info': 0
        }
        
        # Calculate weighted score
        total_weight = 0
        max_possible_weight = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            weight = weights.get(severity, 0)
            total_weight += weight
            max_possible_weight += weights['critical']
        
        # Normalize to 0-100 scale
        if max_possible_weight > 0:
            risk_score = (total_weight / max_possible_weight) * 100
        else:
            risk_score = 0
        
        return min(100, risk_score)
    
    def _get_severity_value(self, severity):
        """
        Get a numeric value for a severity level.
        
        Args:
            severity: Severity level (critical, high, medium, low, info)
        
        Returns:
            Numeric value
        """
        severity_values = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        
        return severity_values.get(severity.lower(), 0)