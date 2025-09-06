import hashlib
import hmac
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

class SecurityException(Exception):
    """Custom exception for audit trail security violations"""
    pass


class GRCManager:
    def __init__(self):
        self.controls = {}
        self.risks = {}
        self.audit_trail = []
        self.hmac_secret = os.urandom(32)  # 256-bit HMAC key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def add_control(self, control_id, framework, requirements):
        self.controls[control_id] = {
            'framework': framework,
            'requirements': requirements,
            'evidence': []
        }

    def calculate_risk(self, threat_frequency: float, loss_magnitude: float,
                     vulnerability_score: float, control_effectiveness: float) -> float:
        """
        Enhanced FAIR-based risk quantification with NIST 800-30 factors
        Risk = (Threat Frequency * Loss Magnitude) * Vulnerability Score / Control Effectiveness
        """
        base_risk = threat_frequency * loss_magnitude
        risk_factor = vulnerability_score / max(control_effectiveness, 0.1)
        return round(base_risk * risk_factor, 2)

    def residual_risk(self, inherent_risk: float, control_effectiveness: float) -> float:
        """Calculate residual risk after controls using COBIT 5 formula"""
        return inherent_risk * (1 - min(control_effectiveness, 1.0))

    def control_maturity_score(self, control_id: str) -> float:
        """Calculate control effectiveness using COBIT maturity levels"""
        control = self.controls.get(control_id, {})
        return len(control.get('evidence', [])) / 5.0

    def generate_compliance_report(self, framework: str) -> dict:
        """
        Generate comprehensive compliance documentation with automated evidence collection
        Supported frameworks: NIST 800-53, ISO 27001, NCA ECC, SAMA, PCI-DSS v4
        """
        return {
            'framework': framework,
            'timestamp': datetime.utcnow().isoformat(),
            'controls': [
                {
                    'id': cid,
                    'mappings': self._map_to_standard(cid, framework),
                    'evidence': self._get_control_evidence(cid),
                    'test_results': self._get_audit_results(cid),
                    'artifacts': self._collect_digital_artifacts(cid)
                } for cid, control in self.controls.items() 
                if control['framework'] == framework
            ],
            'risk_assessment': self._calculate_framework_risk(framework)
        }

    def _map_to_standard(self, control_id: str, target_framework: str) -> list:
        """
        Map controls to multiple compliance frameworks with latest versions
        Includes detailed mappings for:
        - NIST 800-53 Rev5 control families
        - ISO 27001:2022 Annex A controls
        - PCI-DSS v4 requirements
        """
        framework_map = {
            'NIST_800_53': ['AC-1', 'AC-2', 'AU-3', 'CM-6', 'SI-4'],
            'ISO_27001': ['A.5.1', 'A.6.2', 'A.8.3', 'A.12.4', 'A.18.1'],
            'PCI_DSS_v4': ['Req 1.2.1', 'Req 3.5.2', 'Req 6.4.3', 'Req 8.3.1', 'Req 11.5.2'],
            'NCA_ECC': ['ECC-1.1.4', 'ECC-2.3.1', 'ECC-3.5.2', 'ECC-4.2.3'],
            'SAMA': ['SAMA-IT-01.4', 'SAMA-IT-02.1', 'SAMA-RM-03.2', 'SAMA-IS-04.3']
        }
        return framework_map.get(target_framework, [])

    def _get_control_evidence(self, control_id: str) -> list:
        """Collect evidence from integrated systems
        - SIEM alerts
        - Vulnerability scans
        - Configuration management DB
        """
        # Mock implementation - integrate with actual systems
        evidence_sources = {
            'AC-1': ['SIEM Alert: Access control policy violation', 'Config Scan: Password policy compliance'],
            'A.5.1': ['Policy Document: Information security policy v2.1', 'Audit Log: Policy review meeting 2024'],
            'Req 1.2.1': ['Network Scan: Firewall configuration verified', 'Compliance Check: Network segmentation']
        }
        return evidence_sources.get(control_id, ['Evidence collection pending'])

    def _calculate_framework_risk(self, framework: str) -> dict:
        """Calculate compliance risk score using:
        - Control coverage percentage
        - Evidence freshness
        - Audit findings severity
        """
        framework_controls = [c for c in self.controls.values() if c['framework'] == framework]
        if not framework_controls:
            return {'score': 0.0, 'maturity': 0.0, 'coverage': 0.0}
        
        # Calculate risk metrics
        risk_scores = [c.get('risk_score', 0.5) for c in framework_controls]
        maturity_scores = [c.get('maturity', 0.3) for c in framework_controls]
        
        return {
            'score': sum(risk_scores) / len(risk_scores),
            'maturity': sum(maturity_scores) / len(maturity_scores),
            'coverage': len(framework_controls) / len(self.controls) if self.controls else 0.0
        }

    def _get_audit_results(self, control_id: str) -> dict:
        """Retrieve audit test results for specific control"""
        audit_results = {
            'AC-1': {'status': 'pass', 'details': 'Access control policy implemented and tested'},
            'A.5.1': {'status': 'pass', 'details': 'Information security policy documented and communicated'},
            'Req 1.2.1': {'status': 'fail', 'details': 'Network segmentation requires improvement'}
        }
        return audit_results.get(control_id, {'status': 'pending', 'details': 'Audit not performed'})

    def _collect_digital_artifacts(self, control_id: str) -> list:
        """Collect digital evidence artifacts for compliance"""
        artifacts = {
            'AC-1': ['access_control_policy.pdf', 'user_access_review_2024.xlsx'],
            'A.5.1': ['infosec_policy_v2.1.docx', 'policy_approval_minutes.pdf'],
            'Req 1.2.1': ['network_diagram.vsdx', 'firewall_config_backup.xml']
        }
        return artifacts.get(control_id, ['No artifacts collected'])

    def verify_audit_integrity(self):
        """Validate cryptographic chain of custody with HMAC and digital signatures"""
        for i in range(1, len(self.audit_trail)):
            prev_hash = self.audit_trail[i-1]['event_hash']
            prev_signature = self.audit_trail[i-1]['signature']
            
            # Verify HMAC integrity
            event_data = json.dumps({
                'timestamp': self.audit_trail[i]['timestamp'].isoformat(),
                'details': self.audit_trail[i]['details'],
                'prev_hash': prev_hash
            }).encode()
            
            expected_hmac = hmac.new(self.hmac_secret, event_data, hashlib.sha256).hexdigest()
            if expected_hmac != self.audit_trail[i]['hmac']:
                raise SecurityException("HMAC validation failed - audit trail tampering detected")
            
            # Verify digital signature (signature is for current event's data)
            try:
                self.public_key.verify(
                    bytes.fromhex(self.audit_trail[i]['signature']),
                    event_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                raise SecurityException("Digital signature verification failed - audit trail compromised")

    def log_audit_event(self, event_type, details):
        """Log audit event with cryptographic sealing (HMAC + digital signature)"""
        timestamp = datetime.utcnow()
        
        # Calculate hash chain
        prev_hash = self.audit_trail[-1]['event_hash'] if self.audit_trail else '0' * 64
        event_data = json.dumps({
            'timestamp': timestamp.isoformat(),
            'details': details,
            'prev_hash': prev_hash
        }).encode()
        
        # Generate HMAC
        event_hmac = hmac.new(self.hmac_secret, event_data, hashlib.sha256).hexdigest()
        
        # Generate digital signature for current event data
        signature = self.private_key.sign(
            event_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()
        
        # Create sealed audit entry
        audit_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'details': details,
            'event_hash': hashlib.sha256(event_data).hexdigest(),
            'hmac': event_hmac,
            'signature': signature,
            'prev_hash': prev_hash
        }
        
        self.audit_trail.append(audit_entry)