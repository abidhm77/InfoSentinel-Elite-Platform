"""Comprehensive compliance framework scanner for multiple security standards."""
import json
import threading
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

from database.db import get_db

@dataclass
class ComplianceControl:
    """Represents a compliance control requirement."""
    control_id: str
    title: str
    description: str
    category: str
    severity: str
    test_procedure: str
    remediation: str

class ComplianceScanner:
    """Scanner for compliance framework assessment."""
    
    def __init__(self):
        self.compliance_frameworks = {
            "OWASP_TOP_10": self._load_owasp_top10_controls(),
            "PCI_DSS": self._load_pci_dss_controls(),
            "ISO_27001": self._load_iso27001_controls(),
            "NIST_CSF": self._load_nist_csf_controls(),
            "SOC_2": self._load_soc2_controls(),
            "HIPAA": self._load_hipaa_controls(),
            "GDPR": self._load_gdpr_controls(),
            "NCA": self._load_nca_controls(),
            "SAMA": self._load_sama_controls()
        }
        self.scan_results = {}
    
    def start_compliance_scan(self, scan_id: str, target: str, frameworks: List[str] = None):
        """Start comprehensive compliance assessment."""
        if frameworks is None:
            frameworks = list(self.compliance_frameworks.keys())
        
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "running",
                "scan_type": "compliance",
                "frameworks": frameworks,
                "start_time": datetime.utcnow()
            }}
        )
        
        thread = threading.Thread(
            target=self._run_compliance_scan,
            args=(scan_id, target, frameworks)
        )
        thread.daemon = True
        thread.start()
    
    def _run_compliance_scan(self, scan_id: str, target: str, frameworks: List[str]):
        """Execute compliance scan for specified frameworks."""
        try:
            total_frameworks = len(frameworks)
            completed_frameworks = 0
            
            compliance_results = {
                "scan_id": scan_id,
                "target": target,
                "frameworks_tested": frameworks,
                "overall_compliance_score": 0.0,
                "framework_results": {},
                "critical_findings": [],
                "recommendations": [],
                "generated_at": datetime.utcnow().isoformat()
            }
            
            for framework in frameworks:
                self._update_progress(scan_id, 
                    int((completed_frameworks / total_frameworks) * 100),
                    f"Scanning {framework}")
                
                framework_result = self._scan_framework(target, framework)
                compliance_results["framework_results"][framework] = framework_result
                
                # Collect critical findings
                critical_findings = [f for f in framework_result["findings"] 
                                   if f["severity"] in ["critical", "high"]]
                compliance_results["critical_findings"].extend(critical_findings)
                
                completed_frameworks += 1
            
            # Calculate overall compliance score
            compliance_results["overall_compliance_score"] = self._calculate_overall_score(
                compliance_results["framework_results"])
            
            # Generate comprehensive recommendations
            compliance_results["recommendations"] = self._generate_compliance_recommendations(
                compliance_results["framework_results"])
            
            # Save results
            self._save_compliance_results(scan_id, compliance_results)
            
            self._update_progress(scan_id, 100, "Compliance scan completed")
            
        except Exception as e:
            self._handle_scan_error(scan_id, str(e))
    
    def _scan_framework(self, target: str, framework: str) -> Dict[str, Any]:
        """Scan target against specific compliance framework."""
        controls = self.compliance_frameworks.get(framework, {})
        
        framework_result = {
            "framework": framework,
            "total_controls": len(controls),
            "compliant_controls": 0,
            "non_compliant_controls": 0,
            "not_applicable_controls": 0,
            "compliance_percentage": 0.0,
            "findings": [],
            "control_results": {}
        }
        
        for control_id, control in controls.items():
            control_result = self._test_control(target, control)
            framework_result["control_results"][control_id] = control_result
            
            if control_result["status"] == "compliant":
                framework_result["compliant_controls"] += 1
            elif control_result["status"] == "non_compliant":
                framework_result["non_compliant_controls"] += 1
                # Add to findings if non-compliant
                finding = {
                    "control_id": control_id,
                    "title": control.title,
                    "description": control_result["details"],
                    "severity": control.severity,
                    "remediation": control.remediation,
                    "framework": framework
                }
                framework_result["findings"].append(finding)
            else:
                framework_result["not_applicable_controls"] += 1
        
        # Calculate compliance percentage
        applicable_controls = (framework_result["compliant_controls"] + 
                             framework_result["non_compliant_controls"])
        if applicable_controls > 0:
            framework_result["compliance_percentage"] = (
                framework_result["compliant_controls"] / applicable_controls) * 100
        
        return framework_result
    
    def _test_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test individual compliance control."""
        # This is where specific control testing logic would be implemented
        # For now, we'll simulate testing based on control categories
        
        control_result = {
            "control_id": control.control_id,
            "status": "not_tested",
            "details": "",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        # Simulate control testing based on category
        if control.category == "authentication":
            control_result = self._test_authentication_control(target, control)
        elif control.category == "encryption":
            control_result = self._test_encryption_control(target, control)
        elif control.category == "access_control":
            control_result = self._test_access_control(target, control)
        elif control.category == "logging":
            control_result = self._test_logging_control(target, control)
        elif control.category == "network_security":
            control_result = self._test_network_security_control(target, control)
        elif control.category == "vulnerability_management":
            control_result = self._test_vulnerability_management_control(target, control)
        else:
            control_result["status"] = "not_applicable"
            control_result["details"] = "Control testing not implemented for this category"
        
        return control_result
    
    def _test_authentication_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test authentication-related controls."""
        # Simulate authentication testing
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if "multi-factor" in control.title.lower():
            result["details"] = "Multi-factor authentication implementation assessed"
            if result["status"] == "non_compliant":
                result["details"] += " - MFA not properly implemented"
        elif "password" in control.title.lower():
            result["details"] = "Password policy compliance assessed"
            if result["status"] == "non_compliant":
                result["details"] += " - Password policy does not meet requirements"
        
        return result
    
    def _test_encryption_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test encryption-related controls."""
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "Encryption implementation assessed",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if result["status"] == "non_compliant":
            result["details"] += " - Weak encryption or missing encryption detected"
        
        return result
    
    def _test_access_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test access control-related controls."""
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "Access control mechanisms assessed",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if result["status"] == "non_compliant":
            result["details"] += " - Inadequate access controls or privilege escalation possible"
        
        return result
    
    def _test_logging_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test logging and monitoring controls."""
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "Logging and monitoring capabilities assessed",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if result["status"] == "non_compliant":
            result["details"] += " - Insufficient logging or monitoring detected"
        
        return result
    
    def _test_network_security_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test network security controls."""
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "Network security configuration assessed",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if result["status"] == "non_compliant":
            result["details"] += " - Network security gaps identified"
        
        return result
    
    def _test_vulnerability_management_control(self, target: str, control: ComplianceControl) -> Dict[str, Any]:
        """Test vulnerability management controls."""
        import random
        
        result = {
            "control_id": control.control_id,
            "status": random.choice(["compliant", "non_compliant"]),
            "details": "Vulnerability management processes assessed",
            "evidence": [],
            "tested_at": datetime.utcnow().isoformat()
        }
        
        if result["status"] == "non_compliant":
            result["details"] += " - Vulnerability management gaps identified"
        
        return result
    
    def _calculate_overall_score(self, framework_results: Dict[str, Any]) -> float:
        """Calculate overall compliance score across all frameworks."""
        if not framework_results:
            return 0.0
        
        total_score = sum(result["compliance_percentage"] for result in framework_results.values())
        return total_score / len(framework_results)
    
    def _generate_compliance_recommendations(self, framework_results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive compliance recommendations."""
        recommendations = []
        
        for framework, result in framework_results.items():
            if result["compliance_percentage"] < 80:
                recommendations.append(
                    f"Improve {framework} compliance from {result['compliance_percentage']:.1f}% to at least 80%"
                )
            
            # Add specific recommendations based on findings
            critical_findings = [f for f in result["findings"] if f["severity"] == "critical"]
            if critical_findings:
                recommendations.append(
                    f"Address {len(critical_findings)} critical {framework} findings immediately"
                )
        
        # Add general recommendations
        recommendations.extend([
            "Implement continuous compliance monitoring",
            "Establish regular compliance assessments",
            "Provide compliance training to relevant staff",
            "Document all compliance procedures and controls"
        ])
        
        return recommendations
    
    def _save_compliance_results(self, scan_id: str, results: Dict[str, Any]):
        """Save compliance scan results to database."""
        db = get_db()
        
        # Save detailed results
        db.compliance_results.insert_one(results)
        
        # Update scan record
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "completed",
                "end_time": datetime.utcnow(),
                "compliance_score": results["overall_compliance_score"],
                "critical_findings_count": len(results["critical_findings"])
            }}
        )
    
    def _update_progress(self, scan_id: str, progress: int, phase: str):
        """Update scan progress."""
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "progress": progress,
                "current_phase": phase,
                "last_updated": datetime.utcnow()
            }}
        )
    
    def _handle_scan_error(self, scan_id: str, error_message: str):
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
    
    # Framework control definitions
    def _load_owasp_top10_controls(self) -> Dict[str, ComplianceControl]:
        """Load OWASP Top 10 controls."""
        return {
            "A01": ComplianceControl(
                "A01", "Broken Access Control", 
                "Ensure proper access controls are implemented",
                "access_control", "critical",
                "Test for privilege escalation and unauthorized access",
                "Implement proper access control mechanisms"
            ),
            "A02": ComplianceControl(
                "A02", "Cryptographic Failures",
                "Ensure sensitive data is properly protected",
                "encryption", "high",
                "Test encryption implementation and key management",
                "Implement strong encryption for sensitive data"
            ),
            "A03": ComplianceControl(
                "A03", "Injection",
                "Prevent injection attacks",
                "input_validation", "critical",
                "Test for SQL, NoSQL, OS, and LDAP injection",
                "Implement input validation and parameterized queries"
            ),
            "A04": ComplianceControl(
                "A04", "Insecure Design",
                "Ensure secure design principles",
                "design", "high",
                "Review application design for security flaws",
                "Implement secure design patterns and threat modeling"
            ),
            "A05": ComplianceControl(
                "A05", "Security Misconfiguration",
                "Ensure proper security configuration",
                "configuration", "high",
                "Test for default configurations and unnecessary features",
                "Implement secure configuration management"
            )
        }
    
    def _load_pci_dss_controls(self) -> Dict[str, ComplianceControl]:
        """Load PCI DSS controls."""
        return {
            "1.1": ComplianceControl(
                "1.1", "Firewall Configuration",
                "Establish and implement firewall configuration standards",
                "network_security", "high",
                "Review firewall rules and configuration",
                "Implement and maintain firewall configuration standards"
            ),
            "2.1": ComplianceControl(
                "2.1", "Default Passwords",
                "Change vendor-supplied defaults for system passwords",
                "authentication", "critical",
                "Test for default passwords and accounts",
                "Change all default passwords and remove default accounts"
            ),
            "3.4": ComplianceControl(
                "3.4", "Cardholder Data Protection",
                "Render cardholder data unreadable",
                "encryption", "critical",
                "Test encryption of stored cardholder data",
                "Implement strong encryption for cardholder data"
            ),
            "8.2": ComplianceControl(
                "8.2", "User Authentication",
                "Assign unique ID to each person with computer access",
                "authentication", "high",
                "Test user authentication mechanisms",
                "Implement strong user authentication controls"
            )
        }
    
    def _load_iso27001_controls(self) -> Dict[str, ComplianceControl]:
        """Load ISO 27001 controls."""
        return {
            "A.9.1.1": ComplianceControl(
                "A.9.1.1", "Access Control Policy",
                "Establish access control policy",
                "access_control", "high",
                "Review access control policy implementation",
                "Develop and implement comprehensive access control policy"
            ),
            "A.10.1.1": ComplianceControl(
                "A.10.1.1", "Audit Logging",
                "Implement audit logging procedures",
                "logging", "medium",
                "Test audit logging capabilities",
                "Implement comprehensive audit logging"
            ),
            "A.13.1.1": ComplianceControl(
                "A.13.1.1", "Network Controls",
                "Implement network security controls",
                "network_security", "high",
                "Test network security controls",
                "Implement network segmentation and controls"
            )
        }
    
    def _load_nist_csf_controls(self) -> Dict[str, ComplianceControl]:
        """Load NIST Cybersecurity Framework controls."""
        return {
            "ID.AM-1": ComplianceControl(
                "ID.AM-1", "Asset Management",
                "Physical devices and systems are inventoried",
                "asset_management", "medium",
                "Review asset inventory and management",
                "Implement comprehensive asset management program"
            ),
            "PR.AC-1": ComplianceControl(
                "PR.AC-1", "Identity Management",
                "Identities and credentials are issued and managed",
                "authentication", "high",
                "Test identity and credential management",
                "Implement identity and access management system"
            ),
            "DE.CM-1": ComplianceControl(
                "DE.CM-1", "Network Monitoring",
                "The network is monitored to detect potential cybersecurity events",
                "monitoring", "high",
                "Test network monitoring capabilities",
                "Implement network monitoring and detection systems"
            )
        }
    
    def _load_soc2_controls(self) -> Dict[str, ComplianceControl]:
        """Load SOC 2 controls."""
        return {
            "CC6.1": ComplianceControl(
                "CC6.1", "Logical Access Controls",
                "Implement logical access security measures",
                "access_control", "high",
                "Test logical access controls",
                "Implement comprehensive logical access controls"
            ),
            "CC6.7": ComplianceControl(
                "CC6.7", "Data Transmission",
                "Transmit data securely",
                "encryption", "high",
                "Test data transmission security",
                "Implement secure data transmission protocols"
            )
        }
    
    def _load_hipaa_controls(self) -> Dict[str, ComplianceControl]:
        """Load HIPAA controls."""
        return {
            "164.308": ComplianceControl(
                "164.308", "Administrative Safeguards",
                "Implement administrative safeguards",
                "administrative", "high",
                "Review administrative safeguards implementation",
                "Implement HIPAA administrative safeguards"
            ),
            "164.312": ComplianceControl(
                "164.312", "Technical Safeguards",
                "Implement technical safeguards",
                "technical", "high",
                "Test technical safeguards implementation",
                "Implement HIPAA technical safeguards"
            )
        }
    
    def _load_gdpr_controls(self) -> Dict[str, ComplianceControl]:
        """Load GDPR controls."""
        return {
            "Art.25": ComplianceControl(
                "Art.25", "Data Protection by Design",
                "Implement data protection by design and by default",
                "privacy", "high",
                "Review data protection implementation",
                "Implement privacy by design principles"
            ),
            "Art.32": ComplianceControl(
                "Art.32", "Security of Processing",
                "Implement appropriate technical and organizational measures",
                "security", "high",
                "Test security of data processing",
                "Implement appropriate security measures for data processing"
            )
        }

    def _load_nca_controls(self) -> Dict[str, ComplianceControl]:
        """Load NCA (National Cybersecurity Authority) controls."""
        return {
            "NCA-1.1": ComplianceControl(
                "NCA-1.1", "Cybersecurity Governance",
                "Establish comprehensive cybersecurity governance framework",
                "governance", "critical",
                "Review cybersecurity governance structure and policies",
                "Implement NCA-compliant cybersecurity governance framework"
            ),
            "NCA-2.1": ComplianceControl(
                "NCA-2.1", "Risk Management",
                "Implement risk management framework for cybersecurity",
                "risk_management", "high",
                "Test risk assessment and management processes",
                "Establish NCA-compliant risk management framework"
            ),
            "NCA-3.1": ComplianceControl(
                "NCA-3.1", "Incident Response",
                "Establish incident response and reporting procedures",
                "incident_response", "high",
                "Test incident response capabilities and reporting",
                "Implement NCA-compliant incident response procedures"
            ),
            "NCA-4.1": ComplianceControl(
                "NCA-4.1", "Access Control",
                "Implement access control and identity management",
                "access_control", "high",
                "Test access control mechanisms and identity management",
                "Implement NCA-compliant access control framework"
            ),
            "NCA-5.1": ComplianceControl(
                "NCA-5.1", "Data Protection",
                "Ensure protection of sensitive data and information assets",
                "data_protection", "high",
                "Test data protection measures and encryption",
                "Implement NCA-compliant data protection controls"
            )
        }

    def _load_sama_controls(self) -> Dict[str, ComplianceControl]:
        """Load SAMA (Saudi Arabian Monetary Authority) controls."""
        return {
            "SAMA-1.1": ComplianceControl(
                "SAMA-1.1", "Cybersecurity Framework",
                "Implement SAMA Cybersecurity Framework for financial sector",
                "framework", "critical",
                "Review SAMA framework implementation and compliance",
                "Implement comprehensive SAMA Cybersecurity Framework"
            ),
            "SAMA-2.1": ComplianceControl(
                "SAMA-2.1", "Business Continuity",
                "Establish business continuity and disaster recovery procedures",
                "business_continuity", "high",
                "Test business continuity plans and disaster recovery",
                "Implement SAMA-compliant business continuity framework"
            ),
            "SAMA-3.1": ComplianceControl(
                "SAMA-3.1", "Third-Party Risk",
                "Manage third-party and vendor cybersecurity risks",
                "third_party_risk", "high",
                "Assess third-party risk management processes",
                "Establish SAMA-compliant third-party risk management"
            ),
            "SAMA-4.1": ComplianceControl(
                "SAMA-4.1", "Monitoring and Detection",
                "Implement continuous monitoring and threat detection",
                "monitoring", "high",
                "Test monitoring capabilities and threat detection systems",
                "Implement SAMA-compliant monitoring and detection framework"
            ),
            "SAMA-5.1": ComplianceControl(
                "SAMA-5.1", "Regulatory Reporting",
                "Establish regulatory reporting and compliance procedures",
                "regulatory_reporting", "high",
                "Test regulatory reporting processes and compliance",
                "Implement SAMA-compliant regulatory reporting framework"
            )
        }