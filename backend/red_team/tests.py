#!/usr/bin/env python3

"""
Red Team Automation Test Module

This module provides test cases for the continuous red team automation platform,
including unit tests and integration tests for various components.
"""

import unittest
import os
import json
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Import modules to test
from backend.red_team.automation_engine import AdvancedAutomationEngine, ScheduledScenario
from backend.red_team.scenarios import NetworkPenetrationScenario, WebApplicationScenario
from backend.red_team.feedback_loop import FeedbackLoop, FeedbackAnalyzer
from backend.red_team.scenario_library import ScenarioLibrary, ScenarioTemplate
from backend.red_team.config import ConfigManager
from backend.red_team.utils import SecurityManager, MitreAttackManager, ReportGenerator
from backend.red_team.integration import IntegrationManager


class TestConfigManager(unittest.TestCase):
    """Test cases for the ConfigManager class"""
    
    def setUp(self):
        # Create a temporary config file for testing
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_config_path = self.temp_config.name
        
        # Sample config data
        self.config_data = {
            "engine": {
                "max_concurrent_scenarios": 3,
                "default_interval_hours": 12
            },
            "library": {
                "storage_path": "test_library.json"
            }
        }
        
        # Write to temp file
        with open(self.temp_config_path, 'w') as f:
            json.dump(self.config_data, f)
    
    def tearDown(self):
        # Clean up temp file
        os.unlink(self.temp_config_path)
    
    def test_load_from_file(self):
        """Test loading configuration from a file"""
        config = ConfigManager(self.temp_config_path)
        
        # Check if config was loaded correctly
        self.assertEqual(config.get('engine', 'max_concurrent_scenarios'), 3)
        self.assertEqual(config.get('library', 'storage_path'), "test_library.json")
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ConfigManager()
        
        # Check default values
        self.assertIsNotNone(config.get('engine'))
        self.assertIsNotNone(config.get('library'))
        self.assertIsNotNone(config.get('feedback'))
    
    def test_set_and_get(self):
        """Test setting and getting configuration values"""
        config = ConfigManager()
        
        # Set a value
        config.set('test_section', 'test_key', 'test_value')
        
        # Get the value
        self.assertEqual(config.get('test_section', 'test_key'), 'test_value')
        
        # Get with default
        self.assertEqual(config.get('test_section', 'nonexistent', 'default'), 'default')
    
    def test_save_to_file(self):
        """Test saving configuration to a file"""
        config = ConfigManager()
        
        # Set some values
        config.set('test_section', 'test_key', 'test_value')
        
        # Save to a new temp file
        new_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json').name
        config.save_to_file(new_temp_file)
        
        # Load the saved file
        new_config = ConfigManager(new_temp_file)
        
        # Check if values were saved correctly
        self.assertEqual(new_config.get('test_section', 'test_key'), 'test_value')
        
        # Clean up
        os.unlink(new_temp_file)


class TestScenarios(unittest.TestCase):
    """Test cases for scenario classes"""
    
    def setUp(self):
        # Create mock config
        self.config = MagicMock()
        self.config.get.return_value = {
            "network_penetration": {
                "enabled": True,
                "default_scan_type": "stealth"
            },
            "web_application": {
                "enabled": True,
                "default_scan_depth": "medium"
            }
        }
    
    def test_network_penetration_scenario(self):
        """Test NetworkPenetrationScenario class"""
        scenario = NetworkPenetrationScenario(
            name="Test Network Scan",
            target="192.168.1.0/24",
            config=self.config
        )
        
        # Check initialization
        self.assertEqual(scenario.name, "Test Network Scan")
        self.assertEqual(scenario.target, "192.168.1.0/24")
        
        # Test execution (mock)
        with patch.object(scenario, '_run_scan', return_value=True):
            with patch.object(scenario, '_analyze_results'):
                result = scenario.execute()
                self.assertTrue(result.get('success'))
    
    def test_web_application_scenario(self):
        """Test WebApplicationScenario class"""
        scenario = WebApplicationScenario(
            name="Test Web App Scan",
            target="https://example.com",
            config=self.config
        )
        
        # Check initialization
        self.assertEqual(scenario.name, "Test Web App Scan")
        self.assertEqual(scenario.target, "https://example.com")
        
        # Test execution (mock)
        with patch.object(scenario, '_scan_web_application', return_value=True):
            with patch.object(scenario, '_analyze_vulnerabilities'):
                result = scenario.execute()
                self.assertTrue(result.get('success'))


class TestAutomationEngine(unittest.TestCase):
    """Test cases for the AdvancedAutomationEngine class"""
    
    def setUp(self):
        # Create mock config
        self.config = MagicMock()
        self.config.get_all.return_value = {
            "engine": {
                "max_concurrent_scenarios": 3,
                "default_interval_hours": 24
            }
        }
        
        # Create mock scenario library
        self.library = MagicMock()
        self.library.get_all_templates.return_value = [
            {"id": "template1", "name": "Test Template 1", "type": "network_penetration"},
            {"id": "template2", "name": "Test Template 2", "type": "web_application"}
        ]
        
        # Create mock feedback loop
        self.feedback = MagicMock()
        
        # Create engine
        self.engine = AdvancedAutomationEngine(
            config=self.config,
            scenario_library=self.library,
            feedback_loop=self.feedback
        )
    
    def test_schedule_scenario(self):
        """Test scheduling a scenario"""
        # Create a mock scenario
        scenario = MagicMock()
        scenario.id = "test-scenario"
        scenario.name = "Test Scenario"
        
        # Schedule the scenario
        scheduled = self.engine.schedule_scenario(
            scenario=scenario,
            start_time=datetime.now() + timedelta(hours=1),
            interval_hours=12
        )
        
        # Check if scheduled correctly
        self.assertTrue(scheduled)
        self.assertEqual(len(self.engine.scheduled_scenarios), 1)
        
        # Check scheduled scenario properties
        scheduled_scenario = self.engine.scheduled_scenarios[0]
        self.assertEqual(scheduled_scenario.scenario.id, "test-scenario")
        self.assertEqual(scheduled_scenario.interval_hours, 12)
    
    def test_cancel_scenario(self):
        """Test canceling a scheduled scenario"""
        # Create and schedule a mock scenario
        scenario = MagicMock()
        scenario.id = "test-scenario"
        scenario.name = "Test Scenario"
        
        self.engine.schedule_scenario(
            scenario=scenario,
            start_time=datetime.now() + timedelta(hours=1),
            interval_hours=12
        )
        
        # Cancel the scenario
        canceled = self.engine.cancel_scheduled_scenario("test-scenario")
        
        # Check if canceled correctly
        self.assertTrue(canceled)
        self.assertEqual(len(self.engine.scheduled_scenarios), 0)
    
    def test_execute_scenario(self):
        """Test executing a scenario"""
        # Create a mock scenario
        scenario = MagicMock()
        scenario.id = "test-scenario"
        scenario.name = "Test Scenario"
        scenario.execute.return_value = {"success": True, "findings": []}
        
        # Execute the scenario
        with patch.object(self.engine, '_publish_results'):
            result = self.engine.execute_scenario(scenario)
            
            # Check execution result
            self.assertTrue(result.get('success'))
            scenario.execute.assert_called_once()
            self.feedback.process_results.assert_called_once()


class TestFeedbackLoop(unittest.TestCase):
    """Test cases for the FeedbackLoop class"""
    
    def setUp(self):
        # Create mock config
        self.config = MagicMock()
        self.config.get.return_value = {
            "analysis_threshold": 0.7,
            "improvement_metrics": ["detection_rate", "time_to_detect"],
            "learning_rate": 0.1
        }
        
        # Create mock analyzer and optimizer
        self.analyzer = MagicMock()
        self.optimizer = MagicMock()
        
        # Create feedback loop
        self.feedback_loop = FeedbackLoop(
            config=self.config,
            analyzer=self.analyzer,
            optimizer=self.optimizer
        )
    
    def test_process_results(self):
        """Test processing scenario results"""
        # Create mock scenario results
        results = {
            "scenario_id": "test-scenario",
            "success": True,
            "findings": [
                {"id": "finding1", "severity": "high"},
                {"id": "finding2", "severity": "medium"}
            ],
            "metrics": {
                "detection_rate": 0.8,
                "time_to_detect": 120
            }
        }
        
        # Process the results
        self.analyzer.analyze.return_value = {"insights": ["Test insight"]}
        self.optimizer.optimize.return_value = {"improvements": ["Test improvement"]}
        
        feedback = self.feedback_loop.process_results(results)
        
        # Check if processed correctly
        self.assertIn("insights", feedback)
        self.assertIn("improvements", feedback)
        self.analyzer.analyze.assert_called_once()
        self.optimizer.optimize.assert_called_once()
    
    def test_get_improvement_metrics(self):
        """Test getting improvement metrics"""
        # Add some historical data
        self.feedback_loop.historical_data = [
            {
                "scenario_id": "test-scenario",
                "timestamp": datetime.now() - timedelta(days=2),
                "metrics": {"detection_rate": 0.7, "time_to_detect": 150}
            },
            {
                "scenario_id": "test-scenario",
                "timestamp": datetime.now() - timedelta(days=1),
                "metrics": {"detection_rate": 0.8, "time_to_detect": 120}
            }
        ]
        
        # Get metrics
        metrics = self.feedback_loop.get_improvement_metrics("test-scenario")
        
        # Check metrics
        self.assertIn("detection_rate", metrics)
        self.assertIn("time_to_detect", metrics)
        self.assertEqual(metrics["detection_rate"]["trend"], "improving")


class TestScenarioLibrary(unittest.TestCase):
    """Test cases for the ScenarioLibrary class"""
    
    def setUp(self):
        # Create mock config
        self.config = MagicMock()
        self.config.get.return_value = {
            "storage_path": "test_library.json",
            "auto_save": True
        }
        
        # Create library
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', create=True):
                with patch('json.dump'):
                    self.library = ScenarioLibrary(config=self.config)
    
    def test_add_template(self):
        """Test adding a template to the library"""
        # Create a template
        template = ScenarioTemplate(
            name="Test Template",
            type="network_penetration",
            description="Test description",
            parameters={
                "target": "192.168.1.0/24",
                "scan_type": "stealth"
            }
        )
        
        # Add to library
        with patch.object(self.library, '_save_library'):
            added = self.library.add_template(template)
            
            # Check if added correctly
            self.assertTrue(added)
            self.assertEqual(len(self.library.templates), 1)
            self.assertEqual(self.library.templates[0].name, "Test Template")
    
    def test_get_template(self):
        """Test getting a template from the library"""
        # Add a template
        template = ScenarioTemplate(
            name="Test Template",
            type="network_penetration",
            description="Test description",
            parameters={
                "target": "192.168.1.0/24",
                "scan_type": "stealth"
            }
        )
        
        with patch.object(self.library, '_save_library'):
            self.library.add_template(template)
            
            # Get the template
            retrieved = self.library.get_template(template.id)
            
            # Check if retrieved correctly
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.id, template.id)
            self.assertEqual(retrieved.name, "Test Template")
    
    def test_remove_template(self):
        """Test removing a template from the library"""
        # Add a template
        template = ScenarioTemplate(
            name="Test Template",
            type="network_penetration",
            description="Test description",
            parameters={
                "target": "192.168.1.0/24",
                "scan_type": "stealth"
            }
        )
        
        with patch.object(self.library, '_save_library'):
            self.library.add_template(template)
            
            # Remove the template
            removed = self.library.remove_template(template.id)
            
            # Check if removed correctly
            self.assertTrue(removed)
            self.assertEqual(len(self.library.templates), 0)


class TestSecurityManager(unittest.TestCase):
    """Test cases for the SecurityManager class"""
    
    def setUp(self):
        # Create mock config
        self.config = {
            "security": {
                "encryption_enabled": True,
                "encryption_key": "test_key",
                "api_authentication": True,
                "api_token": "test_token"
            }
        }
        
        # Create security manager
        self.security = SecurityManager(self.config)
    
    def test_encryption(self):
        """Test encryption and decryption"""
        # Test data
        test_data = "sensitive information"
        
        # Encrypt
        encrypted = self.security.encrypt(test_data)
        
        # Check if encrypted
        self.assertNotEqual(encrypted, test_data)
        
        # Decrypt
        decrypted = self.security.decrypt(encrypted)
        
        # Check if decrypted correctly
        self.assertEqual(decrypted, test_data)
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        # Test password
        password = "secure_password"
        
        # Hash password
        hashed = self.security.hash_password(password)
        
        # Check if hashed
        self.assertNotEqual(hashed, password)
        
        # Verify password
        verified = self.security.verify_password(hashed, password)
        
        # Check if verified correctly
        self.assertTrue(verified)
        
        # Verify with wrong password
        wrong_verified = self.security.verify_password(hashed, "wrong_password")
        
        # Check if verification fails
        self.assertFalse(wrong_verified)
    
    def test_api_token_validation(self):
        """Test API token validation"""
        # Valid token
        valid = self.security.validate_api_token("test_token")
        
        # Check if validated correctly
        self.assertTrue(valid)
        
        # Invalid token
        invalid = self.security.validate_api_token("wrong_token")
        
        # Check if validation fails
        self.assertFalse(invalid)


class TestIntegrationManager(unittest.TestCase):
    """Test cases for the IntegrationManager class"""
    
    def setUp(self):
        # Create mock config
        self.config = MagicMock()
        self.config.get.return_value = {
            "enabled": True,
            "ueba": {
                "api_endpoint": "http://localhost:8000/api/ueba",
                "api_key": "ueba_key"
            },
            "deception": {
                "api_endpoint": "http://localhost:8000/api/deception",
                "api_key": "deception_key"
            }
        }
        
        # Create integration manager
        self.integration = IntegrationManager(config=self.config)
    
    def test_initialize_integrations(self):
        """Test initializing integrations"""
        # Check if integrations were initialized
        self.assertTrue(self.integration.enabled)
        self.assertIsNotNone(self.integration.integrations)
        self.assertEqual(len(self.integration.integrations), 2)  # UEBA and Deception
    
    def test_publish_event(self):
        """Test publishing an event"""
        # Create mock integrations
        ueba_integration = MagicMock()
        deception_integration = MagicMock()
        
        # Replace real integrations with mocks
        self.integration.integrations = {
            "ueba": ueba_integration,
            "deception": deception_integration
        }
        
        # Test event
        event = {
            "type": "scenario_executed",
            "scenario_id": "test-scenario",
            "timestamp": datetime.now().isoformat(),
            "data": {"success": True}
        }
        
        # Publish event
        self.integration.publish_event(event)
        
        # Check if event was published to all integrations
        ueba_integration.handle_event.assert_called_once()
        deception_integration.handle_event.assert_called_once()
    
    def test_publish_to_specific_integration(self):
        """Test publishing an event to a specific integration"""
        # Create mock integrations
        ueba_integration = MagicMock()
        deception_integration = MagicMock()
        
        # Replace real integrations with mocks
        self.integration.integrations = {
            "ueba": ueba_integration,
            "deception": deception_integration
        }
        
        # Test event
        event = {
            "type": "scenario_executed",
            "scenario_id": "test-scenario",
            "timestamp": datetime.now().isoformat(),
            "data": {"success": True}
        }
        
        # Publish event to specific integration
        self.integration.publish_event(event, target="ueba")
        
        # Check if event was published only to UEBA
        ueba_integration.handle_event.assert_called_once()
        deception_integration.handle_event.assert_not_called()


class TestReportGenerator(unittest.TestCase):
    """Test cases for the ReportGenerator class"""
    
    def setUp(self):
        # Create mock config
        self.config = {
            "reporting": {
                "output_dir": "test_reports",
                "formats": ["json"],
                "include_mitre_mapping": True,
                "include_remediation": True
            }
        }
        
        # Create temp directory for reports
        os.makedirs("test_reports", exist_ok=True)
        
        # Create mock MITRE manager
        self.mitre_manager = MagicMock()
        self.mitre_manager.get_technique.return_value = {
            "name": "Test Technique",
            "description": "Test description",
            "tactics": ["initial-access"],
            "url": "https://attack.mitre.org/techniques/T1234"
        }
        
        # Create report generator
        self.report_generator = ReportGenerator(
            config=self.config,
            mitre_manager=self.mitre_manager
        )
    
    def tearDown(self):
        # Clean up temp directory
        import shutil
        if os.path.exists("test_reports"):
            shutil.rmtree("test_reports")
    
    def test_generate_scenario_report(self):
        """Test generating a scenario report"""
        # Test scenario data
        scenario_data = {
            "id": "test-scenario",
            "name": "Test Scenario",
            "type": "network_penetration",
            "execution_time": "10.5 seconds",
            "success_rate": 80,
            "detection_time": "2.3 seconds",
            "evasion_rate": 70,
            "techniques": ["T1234"],
            "findings": [
                {
                    "id": "finding1",
                    "title": "Test Finding 1",
                    "severity": "high",
                    "description": "Test description 1",
                    "remediation": "Test remediation 1",
                    "remediation_effort": "medium"
                },
                {
                    "id": "finding2",
                    "title": "Test Finding 2",
                    "severity": "medium",
                    "description": "Test description 2",
                    "remediation": "Test remediation 2",
                    "remediation_effort": "low"
                }
            ]
        }
        
        # Generate report
        report_files = self.report_generator.generate_scenario_report(
            scenario_data=scenario_data,
            report_id="test_report"
        )
        
        # Check if report was generated
        self.assertIn("json", report_files)
        self.assertTrue(os.path.exists(report_files["json"]))
        
        # Check report content
        with open(report_files["json"], 'r') as f:
            report = json.load(f)
            
            # Check report structure
            self.assertIn("id", report)
            self.assertIn("timestamp", report)
            self.assertIn("scenario", report)
            self.assertIn("summary", report)
            self.assertIn("mitre_mapping", report)
            self.assertIn("remediation", report)
            
            # Check summary
            self.assertEqual(report["summary"]["name"], "Test Scenario")
            self.assertEqual(report["summary"]["total_findings"], 2)
            
            # Check MITRE mapping
            self.assertEqual(len(report["mitre_mapping"]), 1)
            self.assertEqual(report["mitre_mapping"][0]["technique_id"], "T1234")
            
            # Check remediation
            self.assertEqual(len(report["remediation"]), 2)


if __name__ == "__main__":
    unittest.main()