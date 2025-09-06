#!/usr/bin/env python3
"""
Automated remediation suggestion engine for InfoSentinel.
Provides intelligent, context-aware remediation recommendations.
"""
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RemediationType(Enum):
    """Types of remediation actions."""
    IMMEDIATE = "immediate"
    CONFIGURATION = "configuration"
    PATCH = "patch"
    UPGRADE = "upgrade"
    MITIGATION = "mitigation"
    MONITORING = "monitoring"
    PROCESS = "process"

class DifficultyLevel(Enum):
    """Difficulty levels for remediation."""
    TRIVIAL = 1
    EASY = 2
    MODERATE = 3
    DIFFICULT = 4
    EXPERT = 5

@dataclass
class RemediationAction:
    """Represents a single remediation action."""
    title: str
    description: str
    action_type: RemediationType
    difficulty: DifficultyLevel
    estimated_time: str
    impact: str
    prerequisites: List[str]
    commands: List[str]
    verification: List[str]
    references: List[str]
    priority: int  # 1-10, 10 being highest

class RemediationEngine:
    """
    Intelligent remediation suggestion engine.
    """
    
    def __init__(self):
        """
        Initialize the remediation engine.
        """
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.service_configs = self._load_service_configurations()
        self.security_frameworks = self._load_security_frameworks()
        
    def generate_remediation_plan(self, vulnerability: Dict, context: Optional[Dict] = None) -> Dict:
        """
        Generate comprehensive remediation plan for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data dictionary
            context: Optional context information (environment, constraints, etc.)
            
        Returns:
            Complete remediation plan
        """
        try:
            # Analyze vulnerability
            vuln_analysis = self._analyze_vulnerability(vulnerability)
            
            # Generate remediation actions
            actions = self._generate_remediation_actions(vulnerability, vuln_analysis, context)
            
            # Prioritize actions
            prioritized_actions = self._prioritize_actions(actions, vulnerability, context)
            
            # Generate implementation timeline
            timeline = self._generate_implementation_timeline(prioritized_actions)
            
            # Generate risk assessment
            risk_assessment = self._assess_remediation_risks(prioritized_actions, vulnerability)
            
            # Generate compliance mapping
            compliance_mapping = self._map_to_compliance_frameworks(vulnerability, prioritized_actions)
            
            return {
                'vulnerability_id': vulnerability.get('_id'),
                'vulnerability_title': vulnerability.get('title'),
                'analysis': vuln_analysis,
                'remediation_actions': [self._action_to_dict(action) for action in prioritized_actions],
                'implementation_timeline': timeline,
                'risk_assessment': risk_assessment,
                'compliance_mapping': compliance_mapping,
                'estimated_total_time': self._calculate_total_time(prioritized_actions),
                'success_criteria': self._define_success_criteria(vulnerability),
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating remediation plan: {str(e)}")
            return {
                'error': str(e),
                'vulnerability_id': vulnerability.get('_id'),
                'generated_at': datetime.utcnow().isoformat()
            }
    
    def _analyze_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Analyze vulnerability to understand its characteristics.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Analysis results
        """
        title = vulnerability.get('title', '').lower()
        description = vulnerability.get('description', '').lower()
        service = vulnerability.get('service', '').lower()
        port = vulnerability.get('port', 0)
        
        analysis = {
            'vulnerability_type': self._classify_vulnerability_type(title, description),
            'attack_vector': self._determine_attack_vector(service, port, title),
            'affected_component': self._identify_affected_component(service, port, title),
            'exploitation_complexity': self._assess_exploitation_complexity(title, description),
            'data_impact': self._assess_data_impact(title, description),
            'availability_impact': self._assess_availability_impact(title, description)
        }
        
        return analysis
    
    def _generate_remediation_actions(self, vulnerability: Dict, analysis: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """
        Generate specific remediation actions based on vulnerability analysis.
        
        Args:
            vulnerability: Vulnerability data
            analysis: Vulnerability analysis results
            context: Optional context information
            
        Returns:
            List of remediation actions
        """
        actions = []
        vuln_type = analysis.get('vulnerability_type', 'unknown')
        
        # Generate type-specific actions
        if vuln_type == 'sql_injection':
            actions.extend(self._generate_sql_injection_remediation(vulnerability, context))
        elif vuln_type == 'xss':
            actions.extend(self._generate_xss_remediation(vulnerability, context))
        elif vuln_type == 'authentication_bypass':
            actions.extend(self._generate_auth_bypass_remediation(vulnerability, context))
        elif vuln_type == 'buffer_overflow':
            actions.extend(self._generate_buffer_overflow_remediation(vulnerability, context))
        elif vuln_type == 'information_disclosure':
            actions.extend(self._generate_info_disclosure_remediation(vulnerability, context))
        elif vuln_type == 'privilege_escalation':
            actions.extend(self._generate_privilege_escalation_remediation(vulnerability, context))
        elif vuln_type == 'denial_of_service':
            actions.extend(self._generate_dos_remediation(vulnerability, context))
        else:
            actions.extend(self._generate_generic_remediation(vulnerability, context))
        
        # Add service-specific actions
        service = vulnerability.get('service', '').lower()
        if 'http' in service or 'web' in service:
            actions.extend(self._generate_web_service_remediation(vulnerability, context))
        elif 'ssh' in service:
            actions.extend(self._generate_ssh_remediation(vulnerability, context))
        elif 'ftp' in service:
            actions.extend(self._generate_ftp_remediation(vulnerability, context))
        elif 'smtp' in service:
            actions.extend(self._generate_smtp_remediation(vulnerability, context))
        
        # Add general security hardening actions
        actions.extend(self._generate_general_hardening_actions(vulnerability, context))
        
        return actions
    
    def _generate_sql_injection_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate SQL injection specific remediation actions."""
        actions = [
            RemediationAction(
                title="Implement Parameterized Queries",
                description="Replace dynamic SQL construction with parameterized queries or prepared statements",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-4 hours",
                impact="Eliminates SQL injection vulnerability",
                prerequisites=["Access to application source code", "Development environment"],
                commands=[
                    "# Example for Python/SQLAlchemy",
                    "# Replace: query = f'SELECT * FROM users WHERE id = {user_id}'",
                    "# With: query = session.query(User).filter(User.id == user_id)",
                    "# Or: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                ],
                verification=[
                    "Test all input fields with SQL injection payloads",
                    "Use automated SQL injection testing tools",
                    "Code review to ensure no dynamic SQL construction"
                ],
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
                priority=10
            ),
            RemediationAction(
                title="Input Validation and Sanitization",
                description="Implement comprehensive input validation and sanitization",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.EASY,
                estimated_time="1-2 hours",
                impact="Reduces attack surface",
                prerequisites=["Access to application code"],
                commands=[
                    "# Implement whitelist-based input validation",
                    "# Escape special characters",
                    "# Use input validation libraries"
                ],
                verification=[
                    "Test with malicious input patterns",
                    "Verify all user inputs are validated"
                ],
                references=["https://owasp.org/www-community/controls/Input_Validation"],
                priority=9
            ),
            RemediationAction(
                title="Database User Privilege Restriction",
                description="Limit database user privileges to minimum required",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.EASY,
                estimated_time="30 minutes",
                impact="Limits potential damage from successful injection",
                prerequisites=["Database administrator access"],
                commands=[
                    "REVOKE ALL PRIVILEGES ON *.* FROM 'app_user'@'%';",
                    "GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'%';",
                    "REVOKE DROP, CREATE, ALTER ON app_db.* FROM 'app_user'@'%';"
                ],
                verification=[
                    "Verify application still functions correctly",
                    "Test that administrative operations are blocked"
                ],
                references=["https://dev.mysql.com/doc/refman/8.0/en/privilege-system.html"],
                priority=8
            )
        ]
        return actions
    
    def _generate_xss_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate XSS specific remediation actions."""
        actions = [
            RemediationAction(
                title="Output Encoding",
                description="Implement proper output encoding for all user-controlled data",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-3 hours",
                impact="Prevents XSS attacks",
                prerequisites=["Access to application templates and code"],
                commands=[
                    "# HTML encode output: &lt;script&gt; instead of <script>",
                    "# Use framework-specific encoding functions",
                    "# Example: {{ user_input|escape }} in templates"
                ],
                verification=[
                    "Test with XSS payloads",
                    "Verify all user input is properly encoded"
                ],
                references=["https://owasp.org/www-community/attacks/xss/"],
                priority=10
            ),
            RemediationAction(
                title="Content Security Policy (CSP)",
                description="Implement strict Content Security Policy headers",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="1-2 hours",
                impact="Mitigates XSS impact",
                prerequisites=["Web server configuration access"],
                commands=[
                    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
                    "# Add to web server configuration or application headers"
                ],
                verification=[
                    "Test CSP with browser developer tools",
                    "Verify legitimate functionality still works"
                ],
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                priority=8
            )
        ]
        return actions
    
    def _generate_auth_bypass_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate authentication bypass remediation actions."""
        actions = [
            RemediationAction(
                title="Implement Multi-Factor Authentication",
                description="Add MFA to strengthen authentication mechanisms",
                action_type=RemediationType.UPGRADE,
                difficulty=DifficultyLevel.DIFFICULT,
                estimated_time="1-2 days",
                impact="Significantly improves authentication security",
                prerequisites=["MFA solution selection", "User communication plan"],
                commands=[
                    "# Integrate with MFA provider (TOTP, SMS, etc.)",
                    "# Update authentication flow",
                    "# Implement backup codes"
                ],
                verification=[
                    "Test MFA enrollment process",
                    "Verify bypass attempts fail",
                    "Test backup authentication methods"
                ],
                references=["https://owasp.org/www-community/controls/Multifactor_Authentication"],
                priority=9
            ),
            RemediationAction(
                title="Session Management Hardening",
                description="Implement secure session management practices",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-4 hours",
                impact="Prevents session-based attacks",
                prerequisites=["Access to session management code"],
                commands=[
                    "# Implement secure session tokens",
                    "# Set httpOnly and secure flags on cookies",
                    "# Implement session timeout",
                    "# Regenerate session ID after login"
                ],
                verification=[
                    "Test session fixation attacks",
                    "Verify session timeout works",
                    "Check cookie security flags"
                ],
                references=["https://owasp.org/www-community/controls/Session_Management"],
                priority=8
            )
        ]
        return actions
    
    def _generate_buffer_overflow_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate buffer overflow remediation actions."""
        actions = [
            RemediationAction(
                title="Input Length Validation",
                description="Implement strict input length validation",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.EASY,
                estimated_time="1-2 hours",
                impact="Prevents buffer overflow attacks",
                prerequisites=["Access to application source code"],
                commands=[
                    "# Validate input length before processing",
                    "if (strlen(input) > MAX_BUFFER_SIZE) { return ERROR; }",
                    "# Use safe string functions: strncpy, snprintf"
                ],
                verification=[
                    "Test with oversized inputs",
                    "Verify application handles large inputs gracefully"
                ],
                references=["https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"],
                priority=10
            ),
            RemediationAction(
                title="Enable Stack Protection",
                description="Enable compiler stack protection features",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.EASY,
                estimated_time="30 minutes",
                impact="Makes exploitation more difficult",
                prerequisites=["Access to build system"],
                commands=[
                    "# Add compiler flags: -fstack-protector-all",
                    "# Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space",
                    "# Enable NX bit protection"
                ],
                verification=[
                    "Verify stack canaries are present",
                    "Test that exploitation attempts fail"
                ],
                references=["https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html"],
                priority=7
            )
        ]
        return actions
    
    def _generate_info_disclosure_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate information disclosure remediation actions."""
        actions = [
            RemediationAction(
                title="Remove Sensitive Information",
                description="Remove or mask sensitive information from responses",
                action_type=RemediationType.IMMEDIATE,
                difficulty=DifficultyLevel.EASY,
                estimated_time="1 hour",
                impact="Prevents information leakage",
                prerequisites=["Access to application configuration"],
                commands=[
                    "# Remove debug information from production",
                    "# Mask sensitive data in logs",
                    "# Remove version information from headers"
                ],
                verification=[
                    "Verify sensitive information is not exposed",
                    "Check error messages don't reveal system details"
                ],
                references=["https://owasp.org/www-community/Improper_Error_Handling"],
                priority=8
            )
        ]
        return actions
    
    def _generate_privilege_escalation_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate privilege escalation remediation actions."""
        actions = [
            RemediationAction(
                title="Implement Principle of Least Privilege",
                description="Ensure users and processes have minimum required privileges",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-4 hours",
                impact="Limits potential for privilege escalation",
                prerequisites=["System administrator access"],
                commands=[
                    "# Review and reduce user privileges",
                    "# Implement role-based access control",
                    "# Remove unnecessary SUID/SGID bits"
                ],
                verification=[
                    "Verify users cannot access unauthorized resources",
                    "Test privilege escalation attempts fail"
                ],
                references=["https://owasp.org/www-community/Access_Control"],
                priority=9
            )
        ]
        return actions
    
    def _generate_dos_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate denial of service remediation actions."""
        actions = [
            RemediationAction(
                title="Implement Rate Limiting",
                description="Add rate limiting to prevent resource exhaustion",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-3 hours",
                impact="Prevents DoS attacks",
                prerequisites=["Web server or application configuration access"],
                commands=[
                    "# Configure rate limiting in web server",
                    "# Implement application-level throttling",
                    "# Set connection limits"
                ],
                verification=[
                    "Test rate limiting with automated tools",
                    "Verify legitimate traffic is not affected"
                ],
                references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                priority=8
            )
        ]
        return actions
    
    def _generate_generic_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate generic remediation actions."""
        actions = [
            RemediationAction(
                title="Apply Security Patches",
                description="Update affected software to latest secure version",
                action_type=RemediationType.PATCH,
                difficulty=DifficultyLevel.EASY,
                estimated_time="30 minutes - 2 hours",
                impact="Eliminates known vulnerabilities",
                prerequisites=["System maintenance window", "Backup procedures"],
                commands=[
                    "# Update package manager",
                    "sudo apt update && sudo apt upgrade",
                    "# Or specific package update",
                    "sudo apt install --only-upgrade <package-name>"
                ],
                verification=[
                    "Verify updated version is installed",
                    "Test application functionality",
                    "Re-run vulnerability scan"
                ],
                references=["https://ubuntu.com/security/notices"],
                priority=9
            )
        ]
        return actions
    
    def _generate_web_service_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate web service specific remediation actions."""
        actions = [
            RemediationAction(
                title="Configure Security Headers",
                description="Implement comprehensive security headers",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.EASY,
                estimated_time="1 hour",
                impact="Improves overall web security posture",
                prerequisites=["Web server configuration access"],
                commands=[
                    "# Add security headers to web server config",
                    "Header always set X-Frame-Options DENY",
                    "Header always set X-Content-Type-Options nosniff",
                    "Header always set X-XSS-Protection '1; mode=block'",
                    "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'"
                ],
                verification=[
                    "Check headers with browser developer tools",
                    "Use online security header checkers"
                ],
                references=["https://owasp.org/www-project-secure-headers/"],
                priority=7
            )
        ]
        return actions
    
    def _generate_ssh_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate SSH specific remediation actions."""
        actions = [
            RemediationAction(
                title="Harden SSH Configuration",
                description="Implement SSH security best practices",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.EASY,
                estimated_time="30 minutes",
                impact="Significantly improves SSH security",
                prerequisites=["Root access to SSH server"],
                commands=[
                    "# Edit /etc/ssh/sshd_config",
                    "PasswordAuthentication no",
                    "PermitRootLogin no",
                    "Protocol 2",
                    "MaxAuthTries 3",
                    "sudo systemctl restart sshd"
                ],
                verification=[
                    "Test SSH connection with keys",
                    "Verify password authentication is disabled",
                    "Test that root login is blocked"
                ],
                references=["https://www.ssh.com/academy/ssh/sshd_config"],
                priority=8
            )
        ]
        return actions
    
    def _generate_ftp_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate FTP specific remediation actions."""
        actions = [
            RemediationAction(
                title="Migrate to SFTP/FTPS",
                description="Replace insecure FTP with encrypted alternatives",
                action_type=RemediationType.UPGRADE,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-4 hours",
                impact="Eliminates FTP security vulnerabilities",
                prerequisites=["SFTP/FTPS server setup", "User migration plan"],
                commands=[
                    "# Install and configure SFTP server",
                    "sudo apt install openssh-server",
                    "# Configure SFTP chroot jail",
                    "# Migrate user accounts"
                ],
                verification=[
                    "Test SFTP connections",
                    "Verify FTP service is disabled",
                    "Confirm encrypted file transfers"
                ],
                references=["https://www.ssh.com/academy/ssh/sftp"],
                priority=9
            )
        ]
        return actions
    
    def _generate_smtp_remediation(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate SMTP specific remediation actions."""
        actions = [
            RemediationAction(
                title="Enable SMTP Authentication",
                description="Require authentication for SMTP access",
                action_type=RemediationType.CONFIGURATION,
                difficulty=DifficultyLevel.EASY,
                estimated_time="1 hour",
                impact="Prevents unauthorized email relay",
                prerequisites=["Mail server configuration access"],
                commands=[
                    "# Configure SMTP authentication",
                    "# Disable open relay",
                    "# Enable TLS encryption"
                ],
                verification=[
                    "Test that unauthenticated relay is blocked",
                    "Verify TLS encryption is working"
                ],
                references=["https://www.postfix.org/SASL_README.html"],
                priority=8
            )
        ]
        return actions
    
    def _generate_general_hardening_actions(self, vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Generate general security hardening actions."""
        actions = [
            RemediationAction(
                title="Enable Security Monitoring",
                description="Implement monitoring for the affected service",
                action_type=RemediationType.MONITORING,
                difficulty=DifficultyLevel.MODERATE,
                estimated_time="2-3 hours",
                impact="Enables detection of future attacks",
                prerequisites=["Monitoring system access"],
                commands=[
                    "# Configure log monitoring",
                    "# Set up alerting rules",
                    "# Implement intrusion detection"
                ],
                verification=[
                    "Test alert generation",
                    "Verify logs are being collected"
                ],
                references=["https://owasp.org/www-community/controls/Logging"],
                priority=6
            ),
            RemediationAction(
                title="Regular Security Assessments",
                description="Schedule regular vulnerability assessments",
                action_type=RemediationType.PROCESS,
                difficulty=DifficultyLevel.EASY,
                estimated_time="Ongoing",
                impact="Prevents future vulnerabilities",
                prerequisites=["Security assessment tools"],
                commands=[
                    "# Schedule automated scans",
                    "# Implement continuous monitoring",
                    "# Regular penetration testing"
                ],
                verification=[
                    "Verify scan schedules are active",
                    "Review assessment reports"
                ],
                references=["https://owasp.org/www-community/Vulnerability_Scanning_Tools"],
                priority=5
            )
        ]
        return actions
    
    def _prioritize_actions(self, actions: List[RemediationAction], vulnerability: Dict, context: Optional[Dict]) -> List[RemediationAction]:
        """Prioritize remediation actions based on various factors."""
        # Sort by priority (highest first), then by difficulty (easiest first)
        return sorted(actions, key=lambda x: (-x.priority, x.difficulty.value))
    
    def _generate_implementation_timeline(self, actions: List[RemediationAction]) -> Dict:
        """Generate implementation timeline for remediation actions."""
        timeline = {
            'phases': [],
            'total_estimated_time': self._calculate_total_time(actions),
            'critical_path': []
        }
        
        # Group actions by type and priority
        immediate_actions = [a for a in actions if a.action_type == RemediationType.IMMEDIATE]
        configuration_actions = [a for a in actions if a.action_type == RemediationType.CONFIGURATION]
        patch_actions = [a for a in actions if a.action_type == RemediationType.PATCH]
        upgrade_actions = [a for a in actions if a.action_type == RemediationType.UPGRADE]
        
        if immediate_actions:
            timeline['phases'].append({
                'phase': 'Immediate Response',
                'duration': 'Within 4 hours',
                'actions': [a.title for a in immediate_actions[:3]],
                'description': 'Critical security fixes that must be implemented immediately'
            })
        
        if patch_actions:
            timeline['phases'].append({
                'phase': 'Patch Management',
                'duration': 'Within 24 hours',
                'actions': [a.title for a in patch_actions],
                'description': 'Apply security patches and updates'
            })
        
        if configuration_actions:
            timeline['phases'].append({
                'phase': 'Configuration Hardening',
                'duration': 'Within 1 week',
                'actions': [a.title for a in configuration_actions],
                'description': 'Implement security configuration changes'
            })
        
        if upgrade_actions:
            timeline['phases'].append({
                'phase': 'System Upgrades',
                'duration': 'Within 1 month',
                'actions': [a.title for a in upgrade_actions],
                'description': 'Major system upgrades and improvements'
            })
        
        # Identify critical path
        timeline['critical_path'] = [a.title for a in actions[:5] if a.priority >= 8]
        
        return timeline
    
    def _assess_remediation_risks(self, actions: List[RemediationAction], vulnerability: Dict) -> Dict:
        """Assess risks associated with remediation actions."""
        risks = {
            'implementation_risks': [],
            'business_impact_risks': [],
            'technical_risks': [],
            'mitigation_strategies': []
        }
        
        # Analyze each action for potential risks
        for action in actions:
            if action.difficulty.value >= 4:
                risks['implementation_risks'].append(
                    f"High complexity for '{action.title}' may require expert assistance"
                )
            
            if action.action_type == RemediationType.UPGRADE:
                risks['business_impact_risks'].append(
                    f"'{action.title}' may require system downtime"
                )
            
            if 'restart' in ' '.join(action.commands).lower():
                risks['technical_risks'].append(
                    f"'{action.title}' requires service restart"
                )
        
        # General mitigation strategies
        risks['mitigation_strategies'] = [
            "Test all changes in development environment first",
            "Implement changes during maintenance windows",
            "Have rollback procedures ready",
            "Monitor systems closely after changes",
            "Communicate changes to stakeholders"
        ]
        
        return risks
    
    def _map_to_compliance_frameworks(self, vulnerability: Dict, actions: List[RemediationAction]) -> Dict:
        """Map remediation actions to compliance frameworks."""
        mapping = {
            'frameworks': {},
            'requirements_addressed': []
        }
        
        # OWASP Top 10 mapping
        vuln_type = vulnerability.get('title', '').lower()
        if 'injection' in vuln_type:
            mapping['frameworks']['OWASP_Top_10'] = ['A03:2021 – Injection']
        elif 'xss' in vuln_type or 'cross-site' in vuln_type:
            mapping['frameworks']['OWASP_Top_10'] = ['A03:2021 – Injection']
        elif 'auth' in vuln_type:
            mapping['frameworks']['OWASP_Top_10'] = ['A07:2021 – Identification and Authentication Failures']
        
        # PCI DSS mapping
        if any('encryption' in a.description.lower() for a in actions):
            mapping['frameworks']['PCI_DSS'] = ['Requirement 4: Encrypt transmission of cardholder data']
        
        if any('access control' in a.description.lower() for a in actions):
            mapping['frameworks']['PCI_DSS'] = mapping['frameworks'].get('PCI_DSS', []) + \
                ['Requirement 7: Restrict access to cardholder data']
        
        # ISO 27001 mapping
        mapping['frameworks']['ISO_27001'] = [
            'A.12.6.1 Management of technical vulnerabilities',
            'A.14.2.5 Secure system engineering principles'
        ]
        
        return mapping
    
    def _calculate_total_time(self, actions: List[RemediationAction]) -> str:
        """Calculate total estimated time for all actions."""
        total_hours = 0
        
        for action in actions:
            time_str = action.estimated_time.lower()
            if 'hour' in time_str:
                # Extract hours from strings like "2-4 hours" or "1 hour"
                hours = re.findall(r'(\d+)', time_str)
                if hours:
                    total_hours += int(hours[-1])  # Take the higher estimate
            elif 'day' in time_str:
                days = re.findall(r'(\d+)', time_str)
                if days:
                    total_hours += int(days[-1]) * 8  # Assume 8 hours per day
            elif 'minute' in time_str:
                minutes = re.findall(r'(\d+)', time_str)
                if minutes:
                    total_hours += int(minutes[-1]) / 60
        
        if total_hours < 1:
            return f"{int(total_hours * 60)} minutes"
        elif total_hours < 24:
            return f"{int(total_hours)} hours"
        else:
            days = total_hours / 8
            return f"{int(days)} day{'s' if days > 1 else ''}"
    
    def _define_success_criteria(self, vulnerability: Dict) -> List[str]:
        """Define success criteria for remediation."""
        criteria = [
            "Vulnerability no longer detected by security scanners",
            "Application/service functions normally after remediation",
            "No new vulnerabilities introduced during remediation",
            "Security controls are properly configured and active"
        ]
        
        # Add specific criteria based on vulnerability type
        title = vulnerability.get('title', '').lower()
        if 'injection' in title:
            criteria.append("Input validation successfully blocks injection attempts")
        elif 'xss' in title:
            criteria.append("Output encoding prevents script execution")
        elif 'auth' in title:
            criteria.append("Authentication bypass attempts fail")
        
        return criteria
    
    def _action_to_dict(self, action: RemediationAction) -> Dict:
        """Convert RemediationAction to dictionary."""
        return {
            'title': action.title,
            'description': action.description,
            'action_type': action.action_type.value,
            'difficulty': action.difficulty.name.lower(),
            'difficulty_level': action.difficulty.value,
            'estimated_time': action.estimated_time,
            'impact': action.impact,
            'prerequisites': action.prerequisites,
            'commands': action.commands,
            'verification': action.verification,
            'references': action.references,
            'priority': action.priority
        }
    
    # Classification helper methods
    def _classify_vulnerability_type(self, title: str, description: str) -> str:
        """Classify vulnerability type based on title and description."""
        text = f"{title} {description}".lower()
        
        if any(keyword in text for keyword in ['sql injection', 'sqli']):
            return 'sql_injection'
        elif any(keyword in text for keyword in ['xss', 'cross-site scripting']):
            return 'xss'
        elif any(keyword in text for keyword in ['buffer overflow', 'stack overflow']):
            return 'buffer_overflow'
        elif any(keyword in text for keyword in ['authentication', 'auth', 'bypass']):
            return 'authentication_bypass'
        elif any(keyword in text for keyword in ['information disclosure', 'info leak']):
            return 'information_disclosure'
        elif any(keyword in text for keyword in ['privilege escalation', 'privesc']):
            return 'privilege_escalation'
        elif any(keyword in text for keyword in ['denial of service', 'dos']):
            return 'denial_of_service'
        else:
            return 'unknown'
    
    def _determine_attack_vector(self, service: str, port: int, title: str) -> str:
        """Determine attack vector."""
        if port in [80, 443, 8080, 8443] or 'http' in service:
            return 'network_web'
        elif port == 22 or 'ssh' in service:
            return 'network_ssh'
        elif port in [21, 990] or 'ftp' in service:
            return 'network_ftp'
        elif port > 0:
            return 'network_other'
        else:
            return 'local'
    
    def _identify_affected_component(self, service: str, port: int, title: str) -> str:
        """Identify affected component."""
        if 'web' in service or 'http' in service:
            return 'web_application'
        elif 'database' in service or 'sql' in service:
            return 'database'
        elif 'ssh' in service:
            return 'ssh_service'
        elif 'ftp' in service:
            return 'ftp_service'
        else:
            return 'system_service'
    
    def _assess_exploitation_complexity(self, title: str, description: str) -> str:
        """Assess exploitation complexity."""
        text = f"{title} {description}".lower()
        
        if any(keyword in text for keyword in ['remote code execution', 'rce', 'unauthenticated']):
            return 'low'
        elif any(keyword in text for keyword in ['authentication required', 'authenticated']):
            return 'medium'
        elif any(keyword in text for keyword in ['local access', 'physical access']):
            return 'high'
        else:
            return 'medium'
    
    def _assess_data_impact(self, title: str, description: str) -> str:
        """Assess potential data impact."""
        text = f"{title} {description}".lower()
        
        if any(keyword in text for keyword in ['data breach', 'data access', 'information disclosure']):
            return 'high'
        elif any(keyword in text for keyword in ['data modification', 'data corruption']):
            return 'medium'
        else:
            return 'low'
    
    def _assess_availability_impact(self, title: str, description: str) -> str:
        """Assess potential availability impact."""
        text = f"{title} {description}".lower()
        
        if any(keyword in text for keyword in ['denial of service', 'dos', 'crash', 'hang']):
            return 'high'
        elif any(keyword in text for keyword in ['performance', 'slow', 'resource']):
            return 'medium'
        else:
            return 'low'
    
    def _load_vulnerability_patterns(self) -> Dict:
        """Load vulnerability patterns for analysis."""
        # This would typically load from a database or configuration file
        return {}
    
    def _load_service_configurations(self) -> Dict:
        """Load service-specific configuration templates."""
        # This would typically load from a database or configuration file
        return {}
    
    def _load_security_frameworks(self) -> Dict:
        """Load security framework mappings."""
        # This would typically load from a database or configuration file
        return {}