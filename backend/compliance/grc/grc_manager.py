from services.database_service import db_service
from analytics.trend_analyzer import VulnerabilityTrendAnalyzer
from reporting.report_generator import ReportGenerator
from services.enterprise_logger import enterprise_logger
from typing import Dict, Any

class GRCManager:
    def __init__(self):
        self.db_service = db_service
        self.analyzer = VulnerabilityTrendAnalyzer()
        self.report_generator = ReportGenerator()

    def assess_risk(self, vulnerabilities):
        return self.analyzer.generate_risk_score_algorithm(vulnerabilities)

    def generate_compliance_report(self, user_id):
        try:
            # Get user scans and generate compliance report
            user_scans = self.db_service.get_user_scans(user_id, limit=100)
            if not user_scans:
                return {
                    'compliance_status': 'No Data',
                    'total_scans': 0,
                    'vulnerabilities_found': 0,
                    'risk_score': 0,
                    'frameworks': []
                }
            
            # Calculate compliance metrics
            total_vulnerabilities = 0
            high_severity_count = 0
            
            for scan in user_scans:
                scan_details = self.db_service.get_scan_by_id(scan['id'])
                if scan_details and scan_details.get('vulnerabilities'):
                    vulns = scan_details['vulnerabilities']
                    total_vulnerabilities += len(vulns)
                    high_severity_count += len([v for v in vulns if v.get('severity', '').lower() == 'high'])
            
            # Calculate risk score
            risk_score = min(100, (high_severity_count * 10) + (total_vulnerabilities * 2))
            
            # Determine compliance status
            if risk_score < 20:
                compliance_status = 'Compliant'
            elif risk_score < 50:
                compliance_status = 'Partially Compliant'
            else:
                compliance_status = 'Non-Compliant'
            
            return {
                'compliance_status': compliance_status,
                'total_scans': len(user_scans),
                'vulnerabilities_found': total_vulnerabilities,
                'high_severity_vulnerabilities': high_severity_count,
                'risk_score': risk_score,
                'frameworks': ['OWASP Top 10', 'ISO 27001', 'NIST'],
                'last_assessment': user_scans[0]['created_at'] if user_scans else None
            }
        except Exception as e:
            return {
                'compliance_status': 'Error',
                'error': str(e),
                'total_scans': 0,
                'vulnerabilities_found': 0,
                'risk_score': 0,
                'frameworks': []
            }

    def log_audit_event(self, event: Dict[str, Any]):
        action = event.get('action', 'grc_event')
        resource = event.get('resource', 'grc')
        resource_id = event.get('resource_id')
        user_id = event.get('user_id')
        details = event.get('details', {})
        compliance_standard = event.get('compliance_standard', 'GRC')
        evidence_type = event.get('evidence_type', 'audit')
        enterprise_logger.log_audit_event(
            action=action,
            resource=resource,
            resource_id=resource_id,
            user_id=user_id,
            details=details,
            compliance_standard=compliance_standard,
            evidence_type=evidence_type
        )