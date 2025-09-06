#!/usr/bin/env python3
"""
Compliance Documentation Generator Test Suite
Tests automated compliance report generation for ISO/NIST/SOC2 frameworks
"""

import unittest
from compliance.grc.grc_engine import GRCManager

class TestComplianceDocumentation(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment with sample controls"""
        self.grc = GRCManager()
        
        # Add NIST 800-53 controls
        self.grc.add_control('AC-1', 'NIST_800_53', 'Access Control Policy')
        self.grc.add_control('AU-3', 'NIST_800_53', 'Audit Log Content')
        self.grc.add_control('SI-4', 'NIST_800_53', 'System Monitoring')
        
        # Add ISO 27001 controls
        self.grc.add_control('A.5.1', 'ISO_27001', 'Information Security Policy')
        self.grc.add_control('A.8.3', 'ISO_27001', 'Acceptable Use of Assets')
        self.grc.add_control('A.12.4', 'ISO_27001', 'Logging and Monitoring')
        
        # Add PCI-DSS controls
        self.grc.add_control('Req 1.2.1', 'PCI_DSS_v4', 'Network Segmentation')
        self.grc.add_control('Req 3.5.2', 'PCI_DSS_v4', 'Cryptographic Key Management')
        self.grc.add_control('Req 8.3.1', 'PCI_DSS_v4', 'Multi-factor Authentication')
    
    def test_nist_compliance_report(self):
        """Test NIST 800-53 compliance report generation"""
        report = self.grc.generate_compliance_report('NIST_800_53')
        
        self.assertEqual(report['framework'], 'NIST_800_53')
        self.assertIn('timestamp', report)
        self.assertEqual(len(report['controls']), 3)
        
        # Verify control mappings
        ac1_control = next(c for c in report['controls'] if c['id'] == 'AC-1')
        self.assertIn('AC-1', ac1_control['mappings'])
        self.assertGreater(len(ac1_control['evidence']), 0)
        self.assertIn('status', ac1_control['test_results'])
    
    def test_iso_compliance_report(self):
        """Test ISO 27001 compliance report generation"""
        report = self.grc.generate_compliance_report('ISO_27001')
        
        self.assertEqual(report['framework'], 'ISO_27001')
        self.assertEqual(len(report['controls']), 3)
        
        # Verify evidence collection
        a51_control = next(c for c in report['controls'] if c['id'] == 'A.5.1')
        self.assertIn('A.5.1', a51_control['mappings'])
        self.assertGreater(len(a51_control['evidence']), 0)
        self.assertIn('artifacts', a51_control)
    
    def test_pci_compliance_report(self):
        """Test PCI-DSS v4 compliance report generation"""
        report = self.grc.generate_compliance_report('PCI_DSS_v4')
        
        self.assertEqual(report['framework'], 'PCI_DSS_v4')
        self.assertEqual(len(report['controls']), 3)
        
        # Verify risk assessment
        self.assertIn('risk_assessment', report)
        risk_assessment = report['risk_assessment']
        self.assertIn('score', risk_assessment)
        self.assertIn('maturity', risk_assessment)
        self.assertIn('coverage', risk_assessment)
    
    def test_framework_risk_calculation(self):
        """Test framework-level risk calculation"""
        risk_assessment = self.grc._calculate_framework_risk('NIST_800_53')
        
        self.assertIsInstance(risk_assessment, dict)
        self.assertIn('score', risk_assessment)
        self.assertIn('maturity', risk_assessment)
        self.assertIn('coverage', risk_assessment)
        
        # Risk score should be between 0 and 1
        self.assertGreaterEqual(risk_assessment['score'], 0.0)
        self.assertLessEqual(risk_assessment['score'], 1.0)
    
    def test_evidence_collection(self):
        """Test automated evidence collection"""
        evidence = self.grc._get_control_evidence('AC-1')
        
        self.assertIsInstance(evidence, list)
        self.assertGreater(len(evidence), 0)
        self.assertTrue(any('SIEM' in item for item in evidence))
    
    def test_audit_results(self):
        """Test audit test results retrieval"""
        audit_results = self.grc._get_audit_results('AC-1')
        
        self.assertIsInstance(audit_results, dict)
        self.assertIn('status', audit_results)
        self.assertIn('details', audit_results)
        self.assertIn(audit_results['status'], ['pass', 'fail', 'pending'])
    
    def test_digital_artifacts(self):
        """Test digital artifact collection"""
        artifacts = self.grc._collect_digital_artifacts('AC-1')
        
        self.assertIsInstance(artifacts, list)
        self.assertGreater(len(artifacts), 0)
        self.assertTrue(any('.pdf' in item or '.docx' in item for item in artifacts))

if __name__ == '__main__':
    unittest.main()