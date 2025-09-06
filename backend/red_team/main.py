#!/usr/bin/env python3

"""
Red Team Automation Main Module

This module serves as the main entry point for the continuous red team automation
platform, orchestrating all components and providing a unified interface for
managing automated security testing operations.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta

from . import ContinuousAutomationEngine, AttackScenario, AutomationStatus
from .automation_engine import AdvancedAutomationEngine, ScenarioBuilder, ScheduledScenario
from .feedback_loop import FeedbackLoop
from .scenario_library import ScenarioLibrary, ScenarioTemplate
from .integration import get_platform_integration

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('red_team_automation.log')
    ]
)
logger = logging.getLogger(__name__)


class RedTeamAutomation:
    """Main class for the Red Team Automation Platform"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.engine = None
        self.library = None
        self.feedback_loop = None
        self.platform_integration = None
        self.initialized = False
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "engine": {
                "max_concurrent_scenarios": 5,
                "default_interval_hours": 24,
                "execution_timeout_minutes": 60
            },
            "library": {
                "storage_path": "scenario_library.json"
            },
            "feedback": {
                "analysis_threshold": 0.7,
                "improvement_metrics": ["detection_rate", "time_to_detect", "false_positive_rate"]
            },
            "integration": {
                "enabled": True,
                "ueba": {
                    "api_endpoint": "http://localhost:8000/api/ueba"
                },
                "deception": {
                    "api_endpoint": "http://localhost:8000/api/deception"
                },
                "zero_day_hunting": {
                    "api_endpoint": "http://localhost:8000/api/zero_day_hunting"
                }
            },
            "reporting": {
                "output_dir": "reports",
                "formats": ["json", "pdf", "html"],
                "include_mitre_mapping": True
            },
            "logging": {
                "level": "INFO",
                "file": "red_team_automation.log"
            }
        }
        
        if not config_path:
            logger.info("Using default configuration")
            return default_config
            
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Merge user config with defaults
            merged_config = default_config.copy()
            for section, values in user_config.items():
                if section in merged_config and isinstance(merged_config[section], dict):
                    merged_config[section].update(values)
                else:
                    merged_config[section] = values
                    
            logger.info(f"Loaded configuration from {config_path}")
            return merged_config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
            return default_config
    
    def initialize(self) -> bool:
        """Initialize the Red Team Automation Platform"""
        if self.initialized:
            return True
            
        try:
            # Initialize scenario library
            library_config = self.config.get("library", {})
            storage_path = library_config.get("storage_path")
            self.library = ScenarioLibrary(storage_path)
            
            # Initialize feedback loop
            feedback_config = self.config.get("feedback", {})
            self.feedback_loop = FeedbackLoop(
                analysis_threshold=feedback_config.get("analysis_threshold", 0.7),
                improvement_metrics=feedback_config.get("improvement_metrics", [])
            )
            
            # Initialize platform integration
            if self.config.get("integration", {}).get("enabled", True):
                integration_config = self.config.get("integration", {})
                self.platform_integration = get_platform_integration(integration_config)
            
            # Initialize automation engine
            engine_config = self.config.get("engine", {})
            self.engine = AdvancedAutomationEngine(
                max_concurrent_scenarios=engine_config.get("max_concurrent_scenarios", 5),
                feedback_loop=self.feedback_loop,
                scenario_library=self.library
            )
            
            self.initialized = True
            logger.info("Red Team Automation Platform initialized")
            return True
        except Exception as e:
            logger.error(f"Error initializing Red Team Automation Platform: {e}")
            return False
    
    def shutdown(self) -> None:
        """Shutdown the Red Team Automation Platform"""
        if not self.initialized:
            return
            
        try:
            # Stop the automation engine
            if self.engine:
                self.engine.stop()
                
            # Shutdown platform integration
            if self.platform_integration:
                self.platform_integration.shutdown()
                
            # Save scenario library
            if self.library:
                self.library.save()
                
            self.initialized = False
            logger.info("Red Team Automation Platform shutdown")
        except Exception as e:
            logger.error(f"Error shutting down Red Team Automation Platform: {e}")
    
    def start_automation(self) -> bool:
        """Start the continuous automation engine"""
        if not self.initialized and not self.initialize():
            return False
            
        try:
            self.engine.start()
            logger.info("Continuous Red Team Automation started")
            return True
        except Exception as e:
            logger.error(f"Error starting automation: {e}")
            return False
    
    def stop_automation(self) -> bool:
        """Stop the continuous automation engine"""
        if not self.initialized:
            return False
            
        try:
            self.engine.stop()
            logger.info("Continuous Red Team Automation stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping automation: {e}")
            return False
    
    def get_automation_status(self) -> Dict[str, Any]:
        """Get the current status of the automation engine"""
        if not self.initialized:
            return {"status": "not_initialized"}
            
        try:
            engine_status = self.engine.get_status()
            active_scenarios = self.engine.get_active_scenarios()
            scheduled_scenarios = self.engine.get_scheduled_scenarios()
            
            return {
                "status": engine_status,
                "active_scenarios": len(active_scenarios),
                "scheduled_scenarios": len(scheduled_scenarios),
                "uptime": self.engine.get_uptime_seconds(),
                "last_scenario_completed": self.engine.last_scenario_completed.isoformat() if self.engine.last_scenario_completed else None
            }
        except Exception as e:
            logger.error(f"Error getting automation status: {e}")
            return {"status": "error", "message": str(e)}
    
    def schedule_scenario(self, template_id: str, parameters: Dict[str, Any], 
                         schedule_time: Optional[datetime] = None,
                         interval_hours: Optional[int] = None) -> Optional[str]:
        """Schedule a scenario for execution"""
        if not self.initialized and not self.initialize():
            return None
            
        try:
            # Get default interval if not specified
            if interval_hours is None:
                interval_hours = self.config.get("engine", {}).get("default_interval_hours", 24)
                
            # Set schedule time to now if not specified
            if schedule_time is None:
                schedule_time = datetime.now()
                
            # Get the template
            template = self.library.get_template(template_id)
            if not template:
                logger.error(f"Template not found: {template_id}")
                return None
                
            # Create the scenario
            scenario = template.create_scenario(parameters)
            if not scenario:
                logger.error(f"Failed to create scenario from template: {template_id}")
                return None
                
            # Schedule the scenario
            scheduled_scenario = ScheduledScenario(
                scenario=scenario,
                schedule_time=schedule_time,
                interval_hours=interval_hours
            )
            
            scenario_id = self.engine.schedule_scenario(scheduled_scenario)
            logger.info(f"Scheduled scenario {scenario.name} with ID {scenario_id}")
            return scenario_id
        except Exception as e:
            logger.error(f"Error scheduling scenario: {e}")
            return None
    
    def cancel_scheduled_scenario(self, scenario_id: str) -> bool:
        """Cancel a scheduled scenario"""
        if not self.initialized:
            return False
            
        try:
            result = self.engine.cancel_scheduled_scenario(scenario_id)
            if result:
                logger.info(f"Cancelled scheduled scenario: {scenario_id}")
            else:
                logger.warning(f"Failed to cancel scheduled scenario: {scenario_id}")
            return result
        except Exception as e:
            logger.error(f"Error cancelling scheduled scenario: {e}")
            return False
    
    def get_scenario_results(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        """Get the results of a completed scenario"""
        if not self.initialized:
            return None
            
        try:
            results = self.engine.get_scenario_results(scenario_id)
            if not results:
                logger.warning(f"No results found for scenario: {scenario_id}")
            return results
        except Exception as e:
            logger.error(f"Error getting scenario results: {e}")
            return None
    
    def get_feedback_insights(self, scenario_type: Optional[str] = None, 
                             days: int = 30) -> List[Dict[str, Any]]:
        """Get insights from the feedback loop"""
        if not self.initialized or not self.feedback_loop:
            return []
            
        try:
            since_date = datetime.now() - timedelta(days=days)
            insights = self.feedback_loop.get_insights(since_date, scenario_type)
            return insights
        except Exception as e:
            logger.error(f"Error getting feedback insights: {e}")
            return []
    
    def create_custom_scenario(self, name: str, scenario_type: str, 
                              parameters: Dict[str, Any], 
                              mitre_techniques: List[str]) -> Optional[str]:
        """Create a custom scenario template"""
        if not self.initialized and not self.initialize():
            return None
            
        try:
            # Get the appropriate category
            category = self.library.get_category_by_name(scenario_type.capitalize())
            if not category:
                logger.error(f"Category not found for scenario type: {scenario_type}")
                return None
                
            # Create the template
            template = ScenarioTemplate(
                name=name,
                description=f"Custom scenario: {name}",
                scenario_type=scenario_type,
                parameters=parameters,
                mitre_techniques=mitre_techniques
            )
            
            # Add to category
            category.add_template(template)
            
            # Save the library
            self.library.save()
            
            logger.info(f"Created custom scenario template: {name}")
            return template.id
        except Exception as e:
            logger.error(f"Error creating custom scenario: {e}")
            return None
    
    def get_library_statistics(self) -> Dict[str, Any]:
        """Get statistics about the scenario library"""
        if not self.initialized or not self.library:
            return {}
            
        try:
            return self.library.get_statistics()
        except Exception as e:
            logger.error(f"Error getting library statistics: {e}")
            return {}
    
    def generate_report(self, scenario_id: Optional[str] = None, 
                       report_type: str = "json") -> Optional[str]:
        """Generate a report for a scenario or overall automation"""
        if not self.initialized:
            return None
            
        try:
            # Create reports directory if it doesn't exist
            reports_dir = self.config.get("reporting", {}).get("output_dir", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if scenario_id:
                filename = f"{reports_dir}/scenario_{scenario_id}_{timestamp}.{report_type}"
                # Get scenario results
                results = self.engine.get_scenario_results(scenario_id)
                if not results:
                    logger.warning(f"No results found for scenario: {scenario_id}")
                    return None
                    
                # Generate report content
                if report_type == "json":
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2)
            else:
                filename = f"{reports_dir}/automation_report_{timestamp}.{report_type}"
                # Generate overall report
                report_data = {
                    "status": self.get_automation_status(),
                    "statistics": self.get_library_statistics(),
                    "insights": self.get_feedback_insights()
                }
                
                # Generate report content
                if report_type == "json":
                    with open(filename, 'w') as f:
                        json.dump(report_data, f, indent=2)
            
            logger.info(f"Generated report: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None


def main():
    """Main entry point for the command-line interface"""
    parser = argparse.ArgumentParser(description="Red Team Automation Platform")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--action", choices=["start", "stop", "status", "schedule", "report"], 
                        default="status", help="Action to perform")
    parser.add_argument("--template", help="Template ID for scheduling a scenario")
    parser.add_argument("--parameters", help="JSON parameters for the scenario")
    parser.add_argument("--scenario", help="Scenario ID for reports or cancellation")
    parser.add_argument("--report-type", choices=["json", "pdf", "html"], 
                        default="json", help="Report format")
    
    args = parser.parse_args()
    
    # Create and initialize the platform
    platform = RedTeamAutomation(args.config)
    if not platform.initialize():
        logger.error("Failed to initialize Red Team Automation Platform")
        return 1
    
    # Perform the requested action
    if args.action == "start":
        if platform.start_automation():
            print("Continuous Red Team Automation started successfully")
        else:
            print("Failed to start Continuous Red Team Automation")
            return 1
    elif args.action == "stop":
        if platform.stop_automation():
            print("Continuous Red Team Automation stopped successfully")
        else:
            print("Failed to stop Continuous Red Team Automation")
            return 1
    elif args.action == "status":
        status = platform.get_automation_status()
        print(json.dumps(status, indent=2))
    elif args.action == "schedule":
        if not args.template:
            print("Error: --template is required for scheduling a scenario")
            return 1
            
        parameters = {}
        if args.parameters:
            try:
                parameters = json.loads(args.parameters)
            except json.JSONDecodeError:
                print("Error: --parameters must be valid JSON")
                return 1
                
        scenario_id = platform.schedule_scenario(args.template, parameters)
        if scenario_id:
            print(f"Scheduled scenario with ID: {scenario_id}")
        else:
            print("Failed to schedule scenario")
            return 1
    elif args.action == "report":
        report_path = platform.generate_report(args.scenario, args.report_type)
        if report_path:
            print(f"Generated report: {report_path}")
        else:
            print("Failed to generate report")
            return 1
    
    # Shutdown the platform
    platform.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())