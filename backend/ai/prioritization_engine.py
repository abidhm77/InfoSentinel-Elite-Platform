#!/usr/bin/env python3
"""
Intelligent vulnerability prioritization engine for InfoSentinel.
Implements advanced algorithms for risk-based vulnerability prioritization.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging
import json
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class ExploitabilityLevel(Enum):
    """Exploitability level enumeration."""
    FUNCTIONAL = 5
    PROOF_OF_CONCEPT = 4
    THEORETICAL = 3
    UNPROVEN = 2
    NOT_DEFINED = 1

@dataclass
class VulnerabilityContext:
    """Context information for vulnerability prioritization."""
    asset_criticality: float  # 0.0 - 1.0
    network_exposure: float   # 0.0 - 1.0
    data_sensitivity: float   # 0.0 - 1.0
    business_impact: float    # 0.0 - 1.0
    compliance_requirement: bool
    active_exploitation: bool
    patch_availability: bool
    remediation_complexity: float  # 0.0 - 1.0

class VulnerabilityPrioritizer:
    """
    Intelligent vulnerability prioritization engine.
    """
    
    def __init__(self):
        """
        Initialize the prioritization engine.
        """
        self.cvss_weights = {
            'base_score': 0.4,
            'temporal_score': 0.3,
            'environmental_score': 0.3
        }
        
        self.context_weights = {
            'asset_criticality': 0.25,
            'network_exposure': 0.20,
            'data_sensitivity': 0.20,
            'business_impact': 0.15,
            'compliance_requirement': 0.10,
            'active_exploitation': 0.10
        }
        
        # Threat intelligence data (simulated)
        self.threat_intelligence = {
            'active_campaigns': [],
            'exploit_kits': [],
            'trending_vulnerabilities': [],
            'apt_indicators': []
        }
    
    def calculate_priority_score(self, vulnerability: Dict, context: Optional[VulnerabilityContext] = None) -> Dict:
        """
        Calculate comprehensive priority score for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data dictionary
            context: Optional context information
            
        Returns:
            Priority score and breakdown
        """
        try:
            # Base CVSS score
            cvss_score = self._calculate_cvss_score(vulnerability)
            
            # Exploitability assessment
            exploitability_score = self._assess_exploitability(vulnerability)
            
            # Threat intelligence score
            threat_intel_score = self._assess_threat_intelligence(vulnerability)
            
            # Context score
            context_score = self._calculate_context_score(context) if context else 0.5
            
            # Temporal factors
            temporal_score = self._calculate_temporal_factors(vulnerability)
            
            # Calculate weighted priority score
            priority_score = (
                cvss_score * 0.30 +
                exploitability_score * 0.25 +
                threat_intel_score * 0.20 +
                context_score * 0.15 +
                temporal_score * 0.10
            )
            
            # Normalize to 0-100 scale
            priority_score = min(100, max(0, priority_score * 100))
            
            # Determine priority level
            priority_level = self._determine_priority_level(priority_score)
            
            # Calculate time to remediation recommendation
            remediation_timeline = self._calculate_remediation_timeline(priority_score, context)
            
            return {
                'priority_score': round(priority_score, 2),
                'priority_level': priority_level,
                'remediation_timeline': remediation_timeline,
                'score_breakdown': {
                    'cvss_score': round(cvss_score, 3),
                    'exploitability_score': round(exploitability_score, 3),
                    'threat_intelligence_score': round(threat_intel_score, 3),
                    'context_score': round(context_score, 3),
                    'temporal_score': round(temporal_score, 3)
                },
                'risk_factors': self._identify_risk_factors(vulnerability, context),
                'calculated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error calculating priority score: {str(e)}")
            return {
                'priority_score': 50.0,
                'priority_level': 'medium',
                'error': str(e)
            }
    
    def _calculate_cvss_score(self, vulnerability: Dict) -> float:
        """
        Calculate CVSS-based score component.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            CVSS score component (0.0 - 1.0)
        """
        # Extract CVSS score if available
        cvss_score = vulnerability.get('cvss_score', 0)
        if cvss_score > 0:
            return min(1.0, cvss_score / 10.0)
        
        # Fallback to severity mapping
        severity_map = {
            'critical': 0.95,
            'high': 0.75,
            'medium': 0.50,
            'low': 0.25,
            'info': 0.10
        }
        
        severity = vulnerability.get('severity', 'medium').lower()
        return severity_map.get(severity, 0.50)
    
    def _assess_exploitability(self, vulnerability: Dict) -> float:
        """
        Assess exploitability of the vulnerability.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Exploitability score (0.0 - 1.0)
        """
        score = 0.0
        
        # Check for known exploits
        title = vulnerability.get('title', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # High exploitability indicators
        high_exploit_keywords = [
            'remote code execution', 'rce', 'buffer overflow',
            'sql injection', 'command injection', 'authentication bypass'
        ]
        
        for keyword in high_exploit_keywords:
            if keyword in title or keyword in description:
                score += 0.3
                break
        
        # Medium exploitability indicators
        medium_exploit_keywords = [
            'cross-site scripting', 'xss', 'csrf', 'directory traversal',
            'information disclosure', 'privilege escalation'
        ]
        
        for keyword in medium_exploit_keywords:
            if keyword in title or keyword in description:
                score += 0.2
                break
        
        # Service-based exploitability
        service = vulnerability.get('service', '').lower()
        port = vulnerability.get('port', 0)
        
        # Network-accessible services
        if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
            score += 0.2
        
        # Web services (higher attack surface)
        if 'http' in service or port in [80, 443, 8080, 8443]:
            score += 0.15
        
        # SSH services
        if 'ssh' in service or port == 22:
            score += 0.1
        
        # Check for script-based detection
        script = vulnerability.get('script', '').lower()
        if 'exploit' in script or 'vuln' in script:
            score += 0.15
        
        return min(1.0, score)
    
    def _assess_threat_intelligence(self, vulnerability: Dict) -> float:
        """
        Assess threat intelligence relevance.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Threat intelligence score (0.0 - 1.0)
        """
        score = 0.0
        
        # Check CVE in threat intelligence
        cve = vulnerability.get('cve', '')
        if cve:
            # Simulate threat intelligence lookup
            if self._is_cve_in_active_campaigns(cve):
                score += 0.4
            
            if self._is_cve_in_exploit_kits(cve):
                score += 0.3
            
            if self._is_trending_vulnerability(cve):
                score += 0.2
        
        # Check for APT indicators
        if self._has_apt_indicators(vulnerability):
            score += 0.3
        
        # Recent vulnerability (higher threat)
        created_at = vulnerability.get('created_at')
        if created_at:
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            
            days_old = (datetime.utcnow() - created_at).days
            if days_old <= 7:
                score += 0.2
            elif days_old <= 30:
                score += 0.1
        
        return min(1.0, score)
    
    def _calculate_context_score(self, context: VulnerabilityContext) -> float:
        """
        Calculate context-based score.
        
        Args:
            context: Vulnerability context information
            
        Returns:
            Context score (0.0 - 1.0)
        """
        if not context:
            return 0.5  # Default neutral score
        
        score = (
            context.asset_criticality * self.context_weights['asset_criticality'] +
            context.network_exposure * self.context_weights['network_exposure'] +
            context.data_sensitivity * self.context_weights['data_sensitivity'] +
            context.business_impact * self.context_weights['business_impact'] +
            (1.0 if context.compliance_requirement else 0.0) * self.context_weights['compliance_requirement'] +
            (1.0 if context.active_exploitation else 0.0) * self.context_weights['active_exploitation']
        )
        
        return min(1.0, score)
    
    def _calculate_temporal_factors(self, vulnerability: Dict) -> float:
        """
        Calculate temporal factors affecting priority.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Temporal score (0.0 - 1.0)
        """
        score = 0.0
        
        # Age of vulnerability
        created_at = vulnerability.get('created_at')
        if created_at:
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            
            days_old = (datetime.utcnow() - created_at).days
            
            # Newer vulnerabilities get higher priority
            if days_old <= 1:
                score += 0.4
            elif days_old <= 7:
                score += 0.3
            elif days_old <= 30:
                score += 0.2
            elif days_old <= 90:
                score += 0.1
        
        # Check for patch availability
        if vulnerability.get('patch_available', False):
            score += 0.2
        
        # Check for active exploitation
        if vulnerability.get('actively_exploited', False):
            score += 0.4
        
        return min(1.0, score)
    
    def _determine_priority_level(self, priority_score: float) -> str:
        """
        Determine priority level based on score.
        
        Args:
            priority_score: Calculated priority score (0-100)
            
        Returns:
            Priority level string
        """
        if priority_score >= 90:
            return 'critical'
        elif priority_score >= 75:
            return 'high'
        elif priority_score >= 50:
            return 'medium'
        elif priority_score >= 25:
            return 'low'
        else:
            return 'info'
    
    def _calculate_remediation_timeline(self, priority_score: float, context: Optional[VulnerabilityContext]) -> Dict:
        """
        Calculate recommended remediation timeline.
        
        Args:
            priority_score: Priority score
            context: Optional context information
            
        Returns:
            Remediation timeline recommendations
        """
        # Base timeline based on priority score
        if priority_score >= 90:
            base_hours = 4  # Critical: 4 hours
        elif priority_score >= 75:
            base_hours = 24  # High: 1 day
        elif priority_score >= 50:
            base_hours = 168  # Medium: 1 week
        elif priority_score >= 25:
            base_hours = 720  # Low: 1 month
        else:
            base_hours = 2160  # Info: 3 months
        
        # Adjust based on context
        if context:
            # Increase urgency for compliance requirements
            if context.compliance_requirement:
                base_hours = int(base_hours * 0.5)
            
            # Adjust for remediation complexity
            complexity_multiplier = 1 + context.remediation_complexity
            base_hours = int(base_hours * complexity_multiplier)
            
            # Adjust for active exploitation
            if context.active_exploitation:
                base_hours = min(base_hours, 2)  # Maximum 2 hours if actively exploited
        
        # Convert to human-readable format
        if base_hours <= 24:
            timeline = f"{base_hours} hours"
            urgency = "immediate"
        elif base_hours <= 168:
            days = base_hours // 24
            timeline = f"{days} day{'s' if days > 1 else ''}"
            urgency = "urgent"
        elif base_hours <= 720:
            weeks = base_hours // 168
            timeline = f"{weeks} week{'s' if weeks > 1 else ''}"
            urgency = "normal"
        else:
            months = base_hours // 720
            timeline = f"{months} month{'s' if months > 1 else ''}"
            urgency = "low"
        
        return {
            'recommended_timeline': timeline,
            'urgency_level': urgency,
            'hours': base_hours,
            'target_date': (datetime.utcnow() + timedelta(hours=base_hours)).isoformat()
        }
    
    def _identify_risk_factors(self, vulnerability: Dict, context: Optional[VulnerabilityContext]) -> List[str]:
        """
        Identify key risk factors for the vulnerability.
        
        Args:
            vulnerability: Vulnerability data
            context: Optional context information
            
        Returns:
            List of risk factors
        """
        risk_factors = []
        
        # Severity-based factors
        severity = vulnerability.get('severity', '').lower()
        if severity in ['critical', 'high']:
            risk_factors.append(f"High severity ({severity})")
        
        # Exploitability factors
        title = vulnerability.get('title', '').lower()
        if any(keyword in title for keyword in ['remote code execution', 'rce']):
            risk_factors.append("Remote code execution possible")
        
        if any(keyword in title for keyword in ['sql injection', 'sqli']):
            risk_factors.append("SQL injection vulnerability")
        
        if any(keyword in title for keyword in ['authentication', 'auth', 'bypass']):
            risk_factors.append("Authentication bypass possible")
        
        # Network exposure
        port = vulnerability.get('port', 0)
        if port in [80, 443, 22, 21, 23]:
            risk_factors.append(f"Exposed on common port {port}")
        
        # Context-based factors
        if context:
            if context.asset_criticality > 0.8:
                risk_factors.append("Critical asset affected")
            
            if context.network_exposure > 0.8:
                risk_factors.append("High network exposure")
            
            if context.data_sensitivity > 0.8:
                risk_factors.append("Sensitive data at risk")
            
            if context.compliance_requirement:
                risk_factors.append("Compliance requirement")
            
            if context.active_exploitation:
                risk_factors.append("Active exploitation detected")
        
        # CVE-based factors
        cve = vulnerability.get('cve', '')
        if cve and self._is_cve_in_active_campaigns(cve):
            risk_factors.append("Part of active attack campaigns")
        
        return risk_factors
    
    def prioritize_vulnerability_list(self, vulnerabilities: List[Dict], contexts: Optional[Dict] = None) -> List[Dict]:
        """
        Prioritize a list of vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            contexts: Optional dictionary mapping vulnerability IDs to contexts
            
        Returns:
            Sorted list of vulnerabilities with priority scores
        """
        prioritized_vulns = []
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('_id') or vuln.get('id')
            context = contexts.get(vuln_id) if contexts else None
            
            priority_result = self.calculate_priority_score(vuln, context)
            
            # Add priority information to vulnerability
            vuln_with_priority = vuln.copy()
            vuln_with_priority['priority_analysis'] = priority_result
            
            prioritized_vulns.append(vuln_with_priority)
        
        # Sort by priority score (highest first)
        prioritized_vulns.sort(
            key=lambda x: x['priority_analysis'].get('priority_score', 0),
            reverse=True
        )
        
        return prioritized_vulns
    
    def generate_priority_report(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Generate a comprehensive priority report.
        
        Args:
            vulnerabilities: List of prioritized vulnerabilities
            
        Returns:
            Priority report dictionary
        """
        if not vulnerabilities:
            return {'error': 'No vulnerabilities provided'}
        
        # Calculate statistics
        priority_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        total_score = 0
        
        for vuln in vulnerabilities:
            priority_info = vuln.get('priority_analysis', {})
            level = priority_info.get('priority_level', 'medium')
            score = priority_info.get('priority_score', 0)
            
            if level in priority_levels:
                priority_levels[level] += 1
            total_score += score
        
        avg_score = total_score / len(vulnerabilities) if vulnerabilities else 0
        
        # Identify top risks
        top_risks = sorted(
            vulnerabilities,
            key=lambda x: x.get('priority_analysis', {}).get('priority_score', 0),
            reverse=True
        )[:10]
        
        # Calculate remediation timeline
        immediate_action = len([v for v in vulnerabilities 
                              if v.get('priority_analysis', {}).get('priority_level') == 'critical'])
        
        urgent_action = len([v for v in vulnerabilities 
                           if v.get('priority_analysis', {}).get('priority_level') == 'high'])
        
        return {
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'average_priority_score': round(avg_score, 2),
                'priority_distribution': priority_levels,
                'immediate_action_required': immediate_action,
                'urgent_action_required': urgent_action
            },
            'top_risks': [
                {
                    'id': vuln.get('_id'),
                    'title': vuln.get('title'),
                    'priority_score': vuln.get('priority_analysis', {}).get('priority_score'),
                    'priority_level': vuln.get('priority_analysis', {}).get('priority_level'),
                    'remediation_timeline': vuln.get('priority_analysis', {}).get('remediation_timeline')
                }
                for vuln in top_risks
            ],
            'recommendations': self._generate_priority_recommendations(vulnerabilities),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _generate_priority_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Generate priority-based recommendations.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        critical_count = len([v for v in vulnerabilities 
                            if v.get('priority_analysis', {}).get('priority_level') == 'critical'])
        
        high_count = len([v for v in vulnerabilities 
                        if v.get('priority_analysis', {}).get('priority_level') == 'high'])
        
        if critical_count > 0:
            recommendations.append(
                f"Immediate action required: {critical_count} critical vulnerabilities need attention within 4 hours"
            )
        
        if high_count > 0:
            recommendations.append(
                f"Urgent action required: {high_count} high-priority vulnerabilities need attention within 24 hours"
            )
        
        if critical_count > 5:
            recommendations.append(
                "Consider implementing emergency response procedures due to high number of critical vulnerabilities"
            )
        
        if high_count > 10:
            recommendations.append(
                "Consider additional security resources to address the high volume of urgent vulnerabilities"
            )
        
        recommendations.extend([
            "Prioritize vulnerabilities affecting critical assets and public-facing services",
            "Implement temporary mitigations for vulnerabilities that cannot be immediately patched",
            "Monitor for active exploitation of identified vulnerabilities",
            "Review and update incident response procedures based on current threat landscape"
        ])
        
        return recommendations
    
    # Simulated threat intelligence methods
    def _is_cve_in_active_campaigns(self, cve: str) -> bool:
        """Check if CVE is part of active attack campaigns."""
        # Simulate threat intelligence lookup
        active_cves = ['CVE-2024-1234', 'CVE-2023-5678']  # Example active CVEs
        return cve in active_cves
    
    def _is_cve_in_exploit_kits(self, cve: str) -> bool:
        """Check if CVE is used in exploit kits."""
        # Simulate exploit kit intelligence
        exploit_kit_cves = ['CVE-2024-1235', 'CVE-2023-9999']  # Example exploit kit CVEs
        return cve in exploit_kit_cves
    
    def _is_trending_vulnerability(self, cve: str) -> bool:
        """Check if CVE is trending in security community."""
        # Simulate trending vulnerability detection
        trending_cves = ['CVE-2024-1236', 'CVE-2023-8888']  # Example trending CVEs
        return cve in trending_cves
    
    def _has_apt_indicators(self, vulnerability: Dict) -> bool:
        """Check for APT (Advanced Persistent Threat) indicators."""
        # Simulate APT indicator detection
        apt_keywords = ['apt', 'advanced persistent', 'nation state', 'targeted attack']
        description = vulnerability.get('description', '').lower()
        return any(keyword in description for keyword in apt_keywords)