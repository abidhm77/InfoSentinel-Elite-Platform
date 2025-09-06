import unittest
from unittest.mock import patch, MagicMock
from compliance.grc.grc_manager import GRCManager

class TestGRCManager(unittest.TestCase):
    def test_assess_risk(self):
        with patch('compliance.grc.grc_manager.VulnerabilityTrendAnalyzer') as mock_analyzer_class:
            mock_analyzer = mock_analyzer_class.return_value
            mock_analyzer.generate_risk_score_algorithm.return_value = 75.0
            grc = GRCManager()
            vulnerabilities = [{'severity': 'high'}]
            risk_score = grc.assess_risk(vulnerabilities)
            self.assertEqual(risk_score, 75.0)

    def test_generate_compliance_report(self):
        with patch('compliance.grc.grc_manager.db') as mock_db, \
             patch('compliance.grc.grc_manager.ReportGenerator') as mock_report_gen_class:
            mock_db.get_scan_data_for_tenant.return_value = [{'vulnerabilities': [{'type': 'SQL Injection'}]}]
            mock_report_gen = mock_report_gen_class.return_value
            mock_report_gen.generate_report.return_value = {'compliance_status': 'partial'}
            grc = GRCManager()
            report = grc.generate_compliance_report('test_tenant_id')
            self.assertIn('compliance_status', report)

    def test_log_audit_event(self):
        with patch('compliance.grc.grc_manager.enterprise_logger') as mock_logger:
            grc = GRCManager()
            event = {
                'action': 'test_event',
                'resource': 'test_resource',
                'resource_id': 'test_id',
                'user_id': 'test_user',
                'details': {'detail': 'test'},
                'compliance_standard': 'ISO 27001',
                'evidence_type': 'evidence'
            }
            grc.log_audit_event(event)
            mock_logger.log_audit_event.assert_called_once()

    def test_calculate_risk_with_controls(self):
        """Should calculate mitigated risk using vulnerability and control factors"""
        risk = self.grc.calculate_risk(
            threat_frequency=0.5,
            loss_magnitude=100000,
            vulnerability_score=0.8,
            control_effectiveness=0.7
        )
        assert risk == round((0.5 * 100000) * (0.8 / 0.7), 2), "Risk calculation mismatch"

    def test_residual_risk_calculation(self):
        """Should demonstrate COBIT residual risk reduction"""
        residual = self.grc.residual_risk(
            inherent_risk=50000,
            control_effectiveness=0.65
        )
        assert residual == 50000 * 0.35, "Residual risk formula error"

    def test_control_maturity_scoring(self):
        """Should calculate maturity based on evidence completeness"""
        self.grc.add_control('PCI-1', 'PCI_DSS', 'Req 1.2')
        self.grc.controls['PCI-1']['evidence'] = ['config1', 'scan2']
        assert self.grc.control_maturity_score('PCI-1') == 0.4, "Maturity score incorrect"

if __name__ == '__main__':
    unittest.main()