#!/usr/bin/env python3

"""
Continuous Red Team Automation Engine

This module implements a 24/7 autonomous red team simulation engine that can
execute attack scenarios, collect results, and provide feedback for security improvements.
"""

import logging
import threading
import time
import json
import os
from typing import Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta

from . import ContinuousAutomationEngine, AttackScenario, AutomationStatus, FeedbackLoop, ScenarioLibrary


class ScheduledScenario:
    """A scheduled attack scenario with timing parameters"""
    
    def __init__(self, scenario: AttackScenario, schedule_type: str, 
                 interval: Optional[int] = None, specific_time: Optional[datetime] = None,
                 max_runs: Optional[int] = None):
        self.scenario = scenario
        self.schedule_type = schedule_type  # 'interval', 'specific_time', 'random'
        self.interval = interval  # in seconds
        self.specific_time = specific_time
        self.max_runs = max_runs
        self.run_count = 0
        self.last_run = None
        self.next_run = self._calculate_next_run()
        
    def _calculate_next_run(self) -> datetime:
        """Calculate the next run time based on schedule type"""
        now = datetime.now()
        
        if self.schedule_type == 'interval' and self.interval:
            if self.last_run:
                return self.last_run + timedelta(seconds=self.interval)
            return now
            
        elif self.schedule_type == 'specific_time' and self.specific_time:
            if self.specific_time > now:
                return self.specific_time
            # If specific time is in the past, schedule for tomorrow
            tomorrow = now + timedelta(days=1)
            return datetime(tomorrow.year, tomorrow.month, tomorrow.day, 
                           self.specific_time.hour, self.specific_time.minute)
                           
        # Default to now for immediate or random scheduling
        return now
        
    def should_run(self) -> bool:
        """Check if this scenario should run now"""
        if self.max_runs and self.run_count >= self.max_runs:
            return False
            
        now = datetime.now()
        return now >= self.next_run
        
    def mark_executed(self):
        """Mark this scenario as executed"""
        self.run_count += 1
        self.last_run = datetime.now()
        self.next_run = self._calculate_next_run()


class AdvancedAutomationEngine(ContinuousAutomationEngine):
    """Enhanced automation engine with scheduling and continuous operation"""
    
    def __init__(self, feedback_loop: Optional[FeedbackLoop] = None):
        super().__init__()
        self.scheduled_scenarios = []
        self.running = False
        self.thread = None
        self.feedback_loop = feedback_loop or FeedbackLoop()
        self.logger = logging.getLogger("RedTeamAutomation")
        self.notification_callbacks = []
        
    def schedule_scenario(self, scenario: AttackScenario, schedule_type: str, 
                         interval: Optional[int] = None, 
                         specific_time: Optional[datetime] = None,
                         max_runs: Optional[int] = None) -> str:
        """Schedule a scenario for execution"""
        scheduled = ScheduledScenario(
            scenario=scenario,
            schedule_type=schedule_type,
            interval=interval,
            specific_time=specific_time,
            max_runs=max_runs
        )
        self.scheduled_scenarios.append(scheduled)
        return scheduled.scenario.id
        
    def _automation_loop(self):
        """Main automation loop that runs continuously"""
        self.logger.info("Starting continuous automation loop")
        
        while self.running:
            if self.status == AutomationStatus.RUNNING:
                # Check for scenarios that should run
                for scheduled in self.scheduled_scenarios:
                    if scheduled.should_run():
                        self.logger.info(f"Executing scenario: {scheduled.scenario.name}")
                        
                        try:
                            # Prepare and execute the scenario
                            scheduled.scenario.prepare()
                            result = scheduled.scenario.execute()
                            scheduled.scenario.cleanup()
                            
                            # Record the result
                            result['timestamp'] = datetime.now().isoformat()
                            result['scenario_id'] = scheduled.scenario.id
                            result['scenario_name'] = scheduled.scenario.name
                            self.results_history.append(result)
                            
                            # Update scenario metadata
                            scheduled.mark_executed()
                            
                            # Process feedback
                            if self.feedback_loop:
                                feedback = self.feedback_loop.analyze_results([result])
                                self._send_notifications({
                                    'type': 'scenario_complete',
                                    'scenario': scheduled.scenario.name,
                                    'result': result,
                                    'feedback': feedback
                                })
                                
                        except Exception as e:
                            self.logger.error(f"Error executing scenario {scheduled.scenario.name}: {str(e)}")
                            self._send_notifications({
                                'type': 'scenario_error',
                                'scenario': scheduled.scenario.name,
                                'error': str(e)
                            })
            
            # Sleep to prevent CPU overuse
            time.sleep(1)
    
    def register_notification_callback(self, callback: Callable[[Dict], None]):
        """Register a callback for notifications"""
        self.notification_callbacks.append(callback)
        
    def _send_notifications(self, data: Dict):
        """Send notifications to all registered callbacks"""
        for callback in self.notification_callbacks:
            try:
                callback(data)
            except Exception as e:
                self.logger.error(f"Error in notification callback: {str(e)}")
    
    def start_automation(self, scenario_id: Optional[str] = None) -> bool:
        """Start the continuous automation engine"""
        result = super().start_automation(scenario_id)
        
        if result and not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._automation_loop)
            self.thread.daemon = True
            self.thread.start()
            self.logger.info("Continuous automation engine started")
            
        return result
        
    def stop_automation(self) -> bool:
        """Stop the continuous automation engine"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
            self.thread = None
            
        return super().stop_automation()
        
    def get_status_report(self) -> Dict:
        """Get a detailed status report of the automation engine"""
        return {
            'status': self.status.value,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'scenarios_count': len(self.scenarios),
            'scheduled_scenarios_count': len(self.scheduled_scenarios),
            'results_count': len(self.results_history),
            'next_scenarios': [
                {
                    'name': s.scenario.name,
                    'next_run': s.next_run.isoformat(),
                    'run_count': s.run_count
                } for s in sorted(self.scheduled_scenarios, key=lambda x: x.next_run)[:5]
            ]
        }


class ScenarioBuilder:
    """Helper class to build attack scenarios"""
    
    @staticmethod
    def from_template(template_name: str, params: Dict) -> Optional[AttackScenario]:
        """Create a scenario from a template with custom parameters"""
        # Implementation would load templates and create scenarios
        pass
        
    @staticmethod
    def from_mitre_technique(technique_id: str) -> Optional[AttackScenario]:
        """Create a scenario based on a MITRE ATT&CK technique"""
        # Implementation would generate scenarios based on MITRE techniques
        pass