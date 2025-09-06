#!/usr/bin/env python3

"""
Red Team Automation CLI Tool

This module provides a command-line interface for interacting with the
continuous red team automation platform, allowing users to manage scenarios,
view results, and control the automation engine from the terminal.
"""

import argparse
import json
import logging
import os
import sys
import textwrap
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union

from .main import RedTeamAutomation
from . import AutomationStatus

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RedTeamCLI:
    """Command-line interface for the Red Team Automation Platform"""
    
    def __init__(self):
        self.platform = None
        self.parser = self._create_parser()
        
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser"""
        parser = argparse.ArgumentParser(
            description="InfoSentinel Red Team Automation Platform CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent("""
                Examples:
                  # Start the automation engine
                  python -m backend.red_team.cli start --config config.json
                  
                  # Check the current status
                  python -m backend.red_team.cli status
                  
                  # Schedule a scenario
                  python -m backend.red_team.cli schedule --template-id 12345 --params '{"target":"192.168.1.0/24"}'
                  
                  # View scenario results
                  python -m backend.red_team.cli results --scenario-id 67890
                  
                  # Generate a report
                  python -m backend.red_team.cli report --scenario-id 67890 --format pdf
            """)
        )
        
        # Add global arguments
        parser.add_argument("--config", help="Path to configuration file")
        parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
        
        # Create subparsers for commands
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Start command
        start_parser = subparsers.add_parser("start", help="Start the automation engine")
        
        # Stop command
        stop_parser = subparsers.add_parser("stop", help="Stop the automation engine")
        
        # Status command
        status_parser = subparsers.add_parser("status", help="Get the current status of the automation engine")
        status_parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        # Schedule command
        schedule_parser = subparsers.add_parser("schedule", help="Schedule a scenario for execution")
        schedule_parser.add_argument("--template-id", required=True, help="ID of the scenario template")
        schedule_parser.add_argument("--params", help="JSON parameters for the scenario")
        schedule_parser.add_argument("--time", help="Schedule time (ISO format, default: now)")
        schedule_parser.add_argument("--interval", type=int, help="Repeat interval in hours")
        
        # Cancel command
        cancel_parser = subparsers.add_parser("cancel", help="Cancel a scheduled scenario")
        cancel_parser.add_argument("--scenario-id", required=True, help="ID of the scheduled scenario")
        
        # Results command
        results_parser = subparsers.add_parser("results", help="Get the results of a completed scenario")
        results_parser.add_argument("--scenario-id", required=True, help="ID of the completed scenario")
        results_parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        # Library command
        library_parser = subparsers.add_parser("library", help="Manage the scenario library")
        library_subparsers = library_parser.add_subparsers(dest="library_command", help="Library command")
        
        # Library list command
        library_list_parser = library_subparsers.add_parser("list", help="List available scenario templates")
        library_list_parser.add_argument("--category", help="Filter by category")
        library_list_parser.add_argument("--type", help="Filter by scenario type")
        library_list_parser.add_argument("--technique", help="Filter by MITRE ATT&CK technique")
        
        # Library create command
        library_create_parser = library_subparsers.add_parser("create", help="Create a custom scenario template")
        library_create_parser.add_argument("--name", required=True, help="Name of the scenario")
        library_create_parser.add_argument("--type", required=True, help="Type of the scenario")
        library_create_parser.add_argument("--params", required=True, help="JSON parameters for the scenario")
        library_create_parser.add_argument("--techniques", help="Comma-separated list of MITRE ATT&CK techniques")
        
        # Library stats command
        library_stats_parser = library_subparsers.add_parser("stats", help="Get statistics about the scenario library")
        
        # Feedback command
        feedback_parser = subparsers.add_parser("feedback", help="Get insights from the feedback loop")
        feedback_parser.add_argument("--type", help="Filter by scenario type")
        feedback_parser.add_argument("--days", type=int, default=30, help="Number of days to include")
        feedback_parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        # Report command
        report_parser = subparsers.add_parser("report", help="Generate a report")
        report_parser.add_argument("--scenario-id", help="ID of the scenario (omit for overall report)")
        report_parser.add_argument("--format", choices=["json", "pdf", "html"], default="json", help="Report format")
        
        return parser
    
    def _initialize_platform(self, args) -> bool:
        """Initialize the Red Team Automation Platform"""
        if self.platform is None:
            self.platform = RedTeamAutomation(args.config)
            
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            
        return self.platform.initialize()
    
    def _format_status(self, status: Dict[str, Any], json_output: bool = False) -> str:
        """Format the status output"""
        if json_output:
            return json.dumps(status, indent=2)
            
        lines = [
            "Red Team Automation Status:",
            f"  Status: {status.get('status', 'Unknown')}",
            f"  Active Scenarios: {status.get('active_scenarios', 0)}",
            f"  Scheduled Scenarios: {status.get('scheduled_scenarios', 0)}"
        ]
        
        if 'uptime' in status:
            uptime_seconds = status['uptime']
            hours, remainder = divmod(uptime_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            lines.append(f"  Uptime: {int(hours)}h {int(minutes)}m {int(seconds)}s")
            
        if 'last_scenario_completed' in status and status['last_scenario_completed']:
            lines.append(f"  Last Scenario Completed: {status['last_scenario_completed']}")
            
        return "\n".join(lines)
    
    def _format_results(self, results: Dict[str, Any], json_output: bool = False) -> str:
        """Format the results output"""
        if json_output or not results:
            return json.dumps(results, indent=2)
            
        scenario_name = results.get('scenario_name', 'Unknown')
        scenario_type = results.get('scenario_type', 'Unknown')
        status = results.get('status', 'Unknown')
        start_time = results.get('start_time', 'Unknown')
        end_time = results.get('end_time', 'Unknown')
        
        lines = [
            f"Results for Scenario: {scenario_name} ({scenario_type})",
            f"  Status: {status}",
            f"  Start Time: {start_time}",
            f"  End Time: {end_time}"
        ]
        
        # Add findings
        findings = results.get('findings', [])
        if findings:
            lines.append("\nFindings:")
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'Unknown')
                title = finding.get('title', 'Unknown')
                lines.append(f"  {i}. [{severity.upper()}] {title}")
                
        # Add MITRE ATT&CK techniques
        techniques = results.get('mitre_techniques', [])
        if techniques:
            lines.append("\nMITRE ATT&CK Techniques:")
            for technique in techniques:
                technique_id = technique.get('id', 'Unknown')
                technique_name = technique.get('name', 'Unknown')
                lines.append(f"  - {technique_id}: {technique_name}")
                
        return "\n".join(lines)
    
    def _format_insights(self, insights: List[Dict[str, Any]], json_output: bool = False) -> str:
        """Format the insights output"""
        if json_output or not insights:
            return json.dumps(insights, indent=2)
            
        lines = ["Feedback Loop Insights:"]
        
        for insight in insights:
            scenario_type = insight.get('scenario_type', 'Unknown')
            metric = insight.get('metric', 'Unknown')
            trend = insight.get('trend', 'Unknown')
            value = insight.get('value', 'Unknown')
            recommendation = insight.get('recommendation', 'Unknown')
            
            lines.append(f"\n[{scenario_type}] {metric}:")
            lines.append(f"  Trend: {trend}")
            lines.append(f"  Value: {value}")
            lines.append(f"  Recommendation: {recommendation}")
            
        return "\n".join(lines)
    
    def _format_library_list(self, library, category: Optional[str] = None, 
                            scenario_type: Optional[str] = None,
                            technique: Optional[str] = None) -> str:
        """Format the library list output"""
        lines = ["Available Scenario Templates:"]
        
        for cat in library.categories:
            if category and category.lower() != cat.name.lower():
                continue
                
            lines.append(f"\n{cat.name}: {cat.description}")
            
            for template in cat.templates:
                if scenario_type and scenario_type.lower() != template.scenario_type.lower():
                    continue
                    
                if technique and technique not in template.mitre_techniques:
                    continue
                    
                lines.append(f"  - {template.name} (ID: {template.id})")
                lines.append(f"    Type: {template.scenario_type}")
                lines.append(f"    Description: {template.description}")
                if template.mitre_techniques:
                    lines.append(f"    MITRE Techniques: {', '.join(template.mitre_techniques)}")
                lines.append("")
                
        return "\n".join(lines)
    
    def _format_library_stats(self, stats: Dict[str, Any]) -> str:
        """Format the library stats output"""
        if not stats:
            return "No statistics available"
            
        lines = [
            "Scenario Library Statistics:",
            f"  Total Categories: {stats.get('total_categories', 0)}",
            f"  Total Templates: {stats.get('total_templates', 0)}"
        ]
        
        # Add templates by type
        templates_by_type = stats.get('templates_by_type', {})
        if templates_by_type:
            lines.append("\nTemplates by Type:")
            for type_name, count in templates_by_type.items():
                lines.append(f"  - {type_name}: {count}")
                
        # Add MITRE techniques coverage
        techniques_coverage = stats.get('mitre_techniques_coverage', 0)
        techniques = stats.get('mitre_techniques', [])
        if techniques_coverage:
            lines.append(f"\nMITRE ATT&CK Coverage: {techniques_coverage} techniques")
            if techniques and len(techniques) <= 10:
                lines.append(f"  Techniques: {', '.join(techniques)}")
            elif techniques:
                lines.append(f"  Techniques: {', '.join(techniques[:10])} and {len(techniques) - 10} more")
                
        return "\n".join(lines)
    
    def run(self, args=None) -> int:
        """Run the CLI with the given arguments"""
        args = self.parser.parse_args(args)
        
        # Initialize the platform
        if not self._initialize_platform(args):
            print("Error: Failed to initialize Red Team Automation Platform")
            return 1
        
        try:
            # Handle commands
            if args.command == "start":
                if self.platform.start_automation():
                    print("Continuous Red Team Automation started successfully")
                else:
                    print("Error: Failed to start Continuous Red Team Automation")
                    return 1
            elif args.command == "stop":
                if self.platform.stop_automation():
                    print("Continuous Red Team Automation stopped successfully")
                else:
                    print("Error: Failed to stop Continuous Red Team Automation")
                    return 1
            elif args.command == "status":
                status = self.platform.get_automation_status()
                print(self._format_status(status, args.json))
            elif args.command == "schedule":
                # Parse parameters
                parameters = {}
                if args.params:
                    try:
                        parameters = json.loads(args.params)
                    except json.JSONDecodeError:
                        print("Error: --params must be valid JSON")
                        return 1
                
                # Parse schedule time
                schedule_time = None
                if args.time:
                    try:
                        schedule_time = datetime.fromisoformat(args.time)
                    except ValueError:
                        print("Error: --time must be in ISO format (YYYY-MM-DDTHH:MM:SS)")
                        return 1
                
                # Schedule the scenario
                scenario_id = self.platform.schedule_scenario(
                    args.template_id, parameters, schedule_time, args.interval
                )
                
                if scenario_id:
                    print(f"Scheduled scenario with ID: {scenario_id}")
                else:
                    print("Error: Failed to schedule scenario")
                    return 1
            elif args.command == "cancel":
                if self.platform.cancel_scheduled_scenario(args.scenario_id):
                    print(f"Cancelled scheduled scenario: {args.scenario_id}")
                else:
                    print(f"Error: Failed to cancel scheduled scenario: {args.scenario_id}")
                    return 1
            elif args.command == "results":
                results = self.platform.get_scenario_results(args.scenario_id)
                if results:
                    print(self._format_results(results, args.json))
                else:
                    print(f"Error: No results found for scenario: {args.scenario_id}")
                    return 1
            elif args.command == "library":
                if args.library_command == "list":
                    print(self._format_library_list(
                        self.platform.library, args.category, args.type, args.technique
                    ))
                elif args.library_command == "create":
                    # Parse parameters
                    try:
                        parameters = json.loads(args.params)
                    except json.JSONDecodeError:
                        print("Error: --params must be valid JSON")
                        return 1
                    
                    # Parse techniques
                    techniques = []
                    if args.techniques:
                        techniques = [t.strip() for t in args.techniques.split(',')]
                    
                    # Create the template
                    template_id = self.platform.create_custom_scenario(
                        args.name, args.type, parameters, techniques
                    )
                    
                    if template_id:
                        print(f"Created custom scenario template with ID: {template_id}")
                    else:
                        print("Error: Failed to create custom scenario template")
                        return 1
                elif args.library_command == "stats":
                    stats = self.platform.get_library_statistics()
                    print(self._format_library_stats(stats))
                else:
                    print("Error: Unknown library command")
                    return 1
            elif args.command == "feedback":
                insights = self.platform.get_feedback_insights(args.type, args.days)
                print(self._format_insights(insights, args.json))
            elif args.command == "report":
                report_path = self.platform.generate_report(args.scenario_id, args.format)
                if report_path:
                    print(f"Generated report: {report_path}")
                else:
                    print("Error: Failed to generate report")
                    return 1
            else:
                self.parser.print_help()
        finally:
            # Shutdown the platform
            self.platform.shutdown()
        
        return 0


def main():
    """Main entry point for the CLI"""
    cli = RedTeamCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())