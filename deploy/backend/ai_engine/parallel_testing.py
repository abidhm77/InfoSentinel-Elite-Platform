"""
Parallel Universe Testing Framework

This module implements a system for simultaneously testing thousands of attack
scenarios across virtualized target replicas, allowing for comprehensive security
assessment with minimal resource overhead.
"""

import uuid
import random
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
import numpy as np
from collections import defaultdict, Counter

try:
    from .apt_simulation import APTSimulationEngine
except ImportError:
    print("Warning: Unable to import APTSimulationEngine. Some functionality may be limited.")


class ParallelUniverseTesting:
    """
    A framework for running thousands of attack simulations in parallel
    across virtualized target replicas to identify optimal attack paths
    and security weaknesses.
    """

    def __init__(self, max_parallel_universes=1000):
        """
        Initialize the Parallel Universe Testing framework.
        
        Args:
            max_parallel_universes (int): Maximum number of parallel simulations
        """
        self.max_parallel_universes = max_parallel_universes
        self.universes = {}
        self.universe_results = {}
        self.universe_stats = {}
        self.simulation_engine = self._initialize_simulation_engine()
        self.lock = threading.Lock()
        self.test_status = {
            "running": False,
            "total_universes": 0,
            "completed_universes": 0,
            "start_time": None,
            "end_time": None
        }
    
    def _initialize_simulation_engine(self):
        """Initialize the APT simulation engine."""
        try:
            return APTSimulationEngine()
        except Exception as e:
            print(f"Error initializing APT simulation engine: {e}")
            return None
    
    def create_target_environment_variants(self, base_environment, variation_count=10):
        """
        Create multiple variants of a target environment with different security controls,
        configurations, and vulnerabilities.
        
        Args:
            base_environment (dict): Base target environment configuration
            variation_count (int): Number of variations to create
            
        Returns:
            list: List of environment variants
        """
        environment_variants = []
        
        # Define possible security controls
        all_security_controls = [
            "firewall", "antivirus", "edr", "email_filtering", "web_filtering",
            "dlp", "network_segmentation", "mfa", "privileged_access_management",
            "vulnerability_management", "patch_management", "siem", "ids", "ips",
            "waf", "api_gateway", "zero_trust", "encryption", "sandboxing"
        ]
        
        # Define possible vulnerabilities
        all_vulnerabilities = [
            "unpatched_systems", "weak_credentials", "misconfigured_services",
            "default_credentials", "insecure_apis", "sql_injection", "xss",
            "csrf", "file_inclusion", "path_traversal", "open_s3_buckets",
            "exposed_admin_interfaces", "insecure_deserialization", "xxe",
            "business_logic_flaws", "race_conditions", "insufficient_logging"
        ]
        
        # Define possible environment types
        environment_types = ["on_premise", "cloud", "hybrid", "container"]
        
        # Define possible security maturity levels
        maturity_levels = ["low", "medium", "high"]
        
        # Create base variant from the provided environment
        base_variant = base_environment.copy()
        if "security_controls" not in base_variant:
            base_variant["security_controls"] = []
        if "vulnerabilities" not in base_variant:
            base_variant["vulnerabilities"] = []
        
        environment_variants.append(base_variant)
        
        # Create variations
        for i in range(variation_count - 1):
            variant = base_variant.copy()
            variant["id"] = f"env_variant_{i+1}"
            
            # Vary environment type (20% chance)
            if random.random() < 0.2:
                variant["environment_type"] = random.choice(environment_types)
            
            # Vary security maturity (30% chance)
            if random.random() < 0.3:
                variant["security_maturity"] = random.choice(maturity_levels)
            
            # Vary security controls
            security_controls = base_variant.get("security_controls", []).copy()
            
            # Remove some controls (30% chance for each)
            security_controls = [c for c in security_controls if random.random() > 0.3]
            
            # Add some new controls
            available_controls = [c for c in all_security_controls if c not in security_controls]
            new_controls_count = random.randint(0, min(5, len(available_controls)))
            security_controls.extend(random.sample(available_controls, new_controls_count))
            
            variant["security_controls"] = security_controls
            
            # Vary vulnerabilities
            vulnerabilities = base_variant.get("vulnerabilities", []).copy()
            
            # Remove some vulnerabilities (30% chance for each)
            vulnerabilities = [v for v in vulnerabilities if random.random() > 0.3]
            
            # Add some new vulnerabilities
            available_vulns = [v for v in all_vulnerabilities if v not in vulnerabilities]
            new_vulns_count = random.randint(0, min(5, len(available_vulns)))
            vulnerabilities.extend(random.sample(available_vulns, new_vulns_count))
            
            variant["vulnerabilities"] = vulnerabilities
            
            # Add to variants list
            environment_variants.append(variant)
        
        return environment_variants
    
    def create_attack_scenario_variants(self, base_scenario, variation_count=10):
        """
        Create multiple variants of attack scenarios with different threat actors,
        objectives, and durations.
        
        Args:
            base_scenario (dict): Base attack scenario configuration
            variation_count (int): Number of variations to create
            
        Returns:
            list: List of scenario variants
        """
        scenario_variants = []
        
        # Define possible objectives
        all_objectives = [
            "data_exfiltration", "persistence", "lateral_movement",
            "ransomware_deployment", "cryptomining", "service_disruption",
            "data_destruction", "credential_theft", "command_and_control",
            "reconnaissance", "privilege_escalation"
        ]
        
        # Define possible durations (in days)
        durations = [1, 7, 14, 30, 60, 90, 180]
        
        # Get available threat actors
        available_actors = []
        if self.simulation_engine:
            available_actors = [actor["id"] for actor in self.simulation_engine.list_available_actors()]
        
        # Create base variant from the provided scenario
        base_variant = base_scenario.copy()
        if "objectives" not in base_variant:
            base_variant["objectives"] = ["data_exfiltration"]
        
        scenario_variants.append(base_variant)
        
        # Create variations
        for i in range(variation_count - 1):
            variant = base_variant.copy()
            variant["id"] = f"scenario_variant_{i+1}"
            
            # Vary threat actor (40% chance)
            if random.random() < 0.4 and available_actors:
                variant["actor_id"] = random.choice(available_actors)
            
            # Vary duration (50% chance)
            if random.random() < 0.5:
                variant["campaign_duration_days"] = random.choice(durations)
            
            # Vary objectives
            objectives = base_variant.get("objectives", []).copy()
            
            # Remove some objectives (30% chance for each)
            objectives = [o for o in objectives if random.random() > 0.3]
            
            # Add some new objectives
            available_objectives = [o for o in all_objectives if o not in objectives]
            new_objectives_count = random.randint(0, min(3, len(available_objectives)))
            objectives.extend(random.sample(available_objectives, new_objectives_count))
            
            # Ensure at least one objective
            if not objectives:
                objectives = [random.choice(all_objectives)]
            
            variant["objectives"] = objectives
            
            # Add to variants list
            scenario_variants.append(variant)
        
        return scenario_variants
    
    def generate_universe_matrix(self, environment_variants, scenario_variants, max_universes=None):
        """
        Generate a matrix of parallel universes by combining environment and scenario variants.
        
        Args:
            environment_variants (list): List of environment variants
            scenario_variants (list): List of scenario variants
            max_universes (int): Maximum number of universes to generate
            
        Returns:
            list: List of universe configurations
        """
        if max_universes is None:
            max_universes = self.max_parallel_universes
        
        # Calculate all possible combinations
        total_combinations = len(environment_variants) * len(scenario_variants)
        
        # If total combinations exceed max_universes, sample randomly
        if total_combinations > max_universes:
            universe_configs = []
            for _ in range(max_universes):
                env = random.choice(environment_variants)
                scenario = random.choice(scenario_variants)
                
                universe_config = {
                    "id": str(uuid.uuid4()),
                    "environment": env,
                    "scenario": scenario
                }
                universe_configs.append(universe_config)
        else:
            # Generate all combinations
            universe_configs = []
            for env in environment_variants:
                for scenario in scenario_variants:
                    universe_config = {
                        "id": str(uuid.uuid4()),
                        "environment": env,
                        "scenario": scenario
                    }
                    universe_configs.append(universe_config)
        
        return universe_configs
    
    def _simulate_universe(self, universe_config):
        """
        Simulate a single universe (attack scenario against an environment).
        
        Args:
            universe_config (dict): Universe configuration
            
        Returns:
            dict: Simulation results
        """
        if not self.simulation_engine:
            return {
                "universe_id": universe_config["id"],
                "error": "Simulation engine not available",
                "status": "failed"
            }
        
        try:
            # Extract configuration
            environment = universe_config["environment"]
            scenario = universe_config["scenario"]
            
            # Create simulation
            simulation = self.simulation_engine.create_simulation(
                actor_id=scenario.get("actor_id", "APT29"),  # Default to APT29 if not specified
                target_environment=environment,
                campaign_duration_days=scenario.get("campaign_duration_days", 30),
                objectives=scenario.get("objectives", ["data_exfiltration"])
            )
            
            # Plan attack campaign
            self.simulation_engine.plan_attack_campaign()
            
            # Execute simulation
            executed_simulation = self.simulation_engine.execute_simulation()
            
            # Generate report
            report = self.simulation_engine.generate_report()
            
            # Extract key results
            results = {
                "universe_id": universe_config["id"],
                "simulation_id": simulation["id"],
                "environment": environment,
                "scenario": scenario,
                "attack_path": executed_simulation["attack_path"],
                "overall_success": executed_simulation["results"]["overall_success"],
                "objectives_achieved": executed_simulation["results"]["objectives_achieved"],
                "objectives_failed": executed_simulation["results"]["objectives_failed"],
                "detection_points": executed_simulation["results"]["detection_points"],
                "dwell_time": executed_simulation["results"]["dwell_time"],
                "status": "completed"
            }
            
            return results
        
        except Exception as e:
            return {
                "universe_id": universe_config["id"],
                "error": str(e),
                "status": "failed"
            }
    
    def run_parallel_simulations(self, universe_configs, max_workers=10):
        """
        Run simulations for multiple universes in parallel.
        
        Args:
            universe_configs (list): List of universe configurations
            max_workers (int): Maximum number of parallel workers
            
        Returns:
            dict: Aggregated results
        """
        # Reset test status
        self.test_status = {
            "running": True,
            "total_universes": len(universe_configs),
            "completed_universes": 0,
            "start_time": datetime.now(),
            "end_time": None
        }
        
        # Store universe configurations
        self.universes = {config["id"]: config for config in universe_configs}
        
        # Clear previous results
        self.universe_results = {}
        
        # Define callback function for completed simulations
        def simulation_callback(future):
            result = future.result()
            universe_id = result["universe_id"]
            
            with self.lock:
                self.universe_results[universe_id] = result
                self.test_status["completed_universes"] += 1
        
        # Run simulations in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for config in universe_configs:
                future = executor.submit(self._simulate_universe, config)
                future.add_done_callback(simulation_callback)
                futures.append(future)
            
            # Wait for all simulations to complete
            for future in futures:
                future.result()
        
        # Update test status
        self.test_status["running"] = False
        self.test_status["end_time"] = datetime.now()
        
        # Analyze results
        self._analyze_results()
        
        return {
            "status": self.test_status,
            "stats": self.universe_stats,
            "results": self.universe_results
        }
    
    def _analyze_results(self):
        """Analyze simulation results and generate statistics."""
        if not self.universe_results:
            self.universe_stats = {"error": "No simulation results available"}
            return
        
        # Initialize statistics
        stats = {
            "total_universes": len(self.universe_results),
            "successful_universes": 0,
            "failed_universes": 0,
            "error_universes": 0,
            "success_rate": 0,
            "average_dwell_time": 0,
            "detection_rate": 0,
            "most_successful_techniques": [],
            "most_successful_actor": "",
            "most_vulnerable_environments": [],
            "most_achieved_objectives": [],
            "security_control_effectiveness": {},
            "optimal_attack_paths": []
        }
        
        # Counters for analysis
        successful_techniques = Counter()
        actor_success_count = defaultdict(int)
        actor_total_count = defaultdict(int)
        environment_vulnerability = defaultdict(list)
        achieved_objectives = Counter()
        security_control_presence = defaultdict(lambda: {"present": 0, "not_present": 0})
        security_control_success = defaultdict(lambda: {"present": 0, "not_present": 0})
        
        # Analyze each universe result
        total_dwell_time = 0
        detected_count = 0
        
        for universe_id, result in self.universe_results.items():
            # Count successes and failures
            if result.get("status") == "failed":
                stats["error_universes"] += 1
                continue
            
            if result.get("overall_success", False):
                stats["successful_universes"] += 1
                
                # Count successful techniques
                for phase in result.get("attack_path", []):
                    successful_techniques[phase.get("technique", "")] += 1
                
                # Count actor successes
                actor_id = result.get("scenario", {}).get("actor_id", "")
                if actor_id:
                    actor_success_count[actor_id] += 1
                
                # Track environment vulnerabilities
                env_type = result.get("environment", {}).get("environment_type", "")
                if env_type:
                    environment_vulnerability[env_type].append(1)
                else:
                    environment_vulnerability["unknown"].append(1)
                
                # Count achieved objectives
                for objective in result.get("objectives_achieved", []):
                    achieved_objectives[objective] += 1
            else:
                stats["failed_universes"] += 1
                
                # Track environment resistance
                env_type = result.get("environment", {}).get("environment_type", "")
                if env_type:
                    environment_vulnerability[env_type].append(0)
                else:
                    environment_vulnerability["unknown"].append(0)
            
            # Track actor total counts
            actor_id = result.get("scenario", {}).get("actor_id", "")
            if actor_id:
                actor_total_count[actor_id] += 1
            
            # Track dwell time
            dwell_time = result.get("dwell_time", 0)
            if dwell_time > 0:
                total_dwell_time += dwell_time
            
            # Track detection rate
            if result.get("detection_points", []):
                detected_count += 1
            
            # Track security control effectiveness
            env_controls = result.get("environment", {}).get("security_controls", [])
            success = result.get("overall_success", False)
            
            for control in ["firewall", "antivirus", "edr", "email_filtering", "dlp", "network_segmentation", "mfa"]:
                if control in env_controls:
                    security_control_presence[control]["present"] += 1
                    if success:
                        security_control_success[control]["present"] += 1
                else:
                    security_control_presence[control]["not_present"] += 1
                    if success:
                        security_control_success[control]["not_present"] += 1
        
        # Calculate statistics
        valid_universes = stats["successful_universes"] + stats["failed_universes"]
        if valid_universes > 0:
            stats["success_rate"] = stats["successful_universes"] / valid_universes
            
            if detected_count > 0:
                stats["detection_rate"] = detected_count / valid_universes
            
            if total_dwell_time > 0:
                stats["average_dwell_time"] = total_dwell_time / valid_universes
        
        # Most successful techniques
        stats["most_successful_techniques"] = successful_techniques.most_common(5)
        
        # Most successful actor
        if actor_success_count and actor_total_count:
            actor_success_rates = {}
            for actor, success_count in actor_success_count.items():
                total = actor_total_count[actor]
                if total > 0:
                    actor_success_rates[actor] = success_count / total
            
            if actor_success_rates:
                stats["most_successful_actor"] = max(actor_success_rates.items(), key=lambda x: x[1])[0]
        
        # Most vulnerable environments
        for env_type, results in environment_vulnerability.items():
            if results:
                vulnerability_rate = sum(results) / len(results)
                stats["most_vulnerable_environments"].append((env_type, vulnerability_rate))
        
        stats["most_vulnerable_environments"].sort(key=lambda x: x[1], reverse=True)
        stats["most_vulnerable_environments"] = stats["most_vulnerable_environments"][:3]
        
        # Most achieved objectives
        stats["most_achieved_objectives"] = achieved_objectives.most_common(3)
        
        # Security control effectiveness
        for control, presence in security_control_presence.items():
            if presence["present"] > 0:
                success_with_control = security_control_success[control]["present"] / presence["present"]
            else:
                success_with_control = 0
            
            if presence["not_present"] > 0:
                success_without_control = security_control_success[control]["not_present"] / presence["not_present"]
            else:
                success_without_control = 0
            
            effectiveness = 1 - (success_with_control / success_without_control if success_without_control > 0 else 0)
            stats["security_control_effectiveness"][control] = effectiveness
        
        # Find optimal attack paths
        successful_results = [r for r in self.universe_results.values() if r.get("overall_success", False)]
        if successful_results:
            # Sort by number of objectives achieved and dwell time (lower is better)
            sorted_results = sorted(
                successful_results,
                key=lambda r: (len(r.get("objectives_achieved", [])), -r.get("dwell_time", 0)),
                reverse=True
            )
            
            # Take top 3 optimal paths
            for result in sorted_results[:3]:
                optimal_path = {
                    "universe_id": result.get("universe_id", ""),
                    "actor_id": result.get("scenario", {}).get("actor_id", ""),
                    "environment_type": result.get("environment", {}).get("environment_type", ""),
                    "objectives_achieved": result.get("objectives_achieved", []),
                    "dwell_time": result.get("dwell_time", 0),
                    "attack_path": [(phase.get("phase", ""), phase.get("technique", "")) for phase in result.get("attack_path", [])]
                }
                stats["optimal_attack_paths"].append(optimal_path)
        
        self.universe_stats = stats
    
    def get_test_status(self):
        """
        Get the current status of parallel universe testing.
        
        Returns:
            dict: Test status information
        """
        return self.test_status
    
    def get_universe_results(self, universe_id=None):
        """
        Get results for a specific universe or all universes.
        
        Args:
            universe_id (str): ID of the universe to get results for
            
        Returns:
            dict: Universe results
        """
        if universe_id:
            return self.universe_results.get(universe_id, {"error": "Universe not found"})
        else:
            return self.universe_results
    
    def get_statistics(self):
        """
        Get statistics from the parallel universe testing.
        
        Returns:
            dict: Testing statistics
        """
        return self.universe_stats
    
    def find_critical_attack_paths(self):
        """
        Identify critical attack paths that consistently lead to successful breaches.
        
        Returns:
            list: Critical attack paths
        """
        if not self.universe_results:
            return []
        
        # Extract attack paths from successful simulations
        successful_paths = []
        for result in self.universe_results.values():
            if result.get("overall_success", False):
                path = [(phase.get("phase", ""), phase.get("technique", "")) for phase in result.get("attack_path", [])]
                successful_paths.append(path)
        
        if not successful_paths:
            return []
        
        # Find common subsequences in attack paths
        critical_paths = []
        
        # Convert paths to strings for easier comparison
        path_strings = ['->'.join([f"{p[0]}:{p[1]}" for p in path]) for path in successful_paths]
        
        # Count occurrences of each path
        path_counts = Counter(path_strings)
        
        # Find paths that appear in at least 20% of successful simulations
        threshold = max(1, len(successful_paths) * 0.2)
        common_paths = [path for path, count in path_counts.items() if count >= threshold]
        
        # Convert back to structured format
        for path_str in common_paths:
            steps = path_str.split('->')
            path = []
            for step in steps:
                phase, technique = step.split(':')
                path.append({"phase": phase, "technique": technique})
            
            critical_paths.append({
                "path": path,
                "frequency": path_counts[path_str] / len(successful_paths)
            })
        
        # Sort by frequency
        critical_paths.sort(key=lambda x: x["frequency"], reverse=True)
        
        return critical_paths
    
    def identify_security_control_gaps(self):
        """
        Identify gaps in security controls based on simulation results.
        
        Returns:
            list: Security control gaps
        """
        if not self.universe_results or not self.universe_stats:
            return []
        
        # Extract security control effectiveness
        control_effectiveness = self.universe_stats.get("security_control_effectiveness", {})
        
        # Identify controls with low effectiveness
        gaps = []
        for control, effectiveness in control_effectiveness.items():
            if effectiveness < 0.3:  # Less than 30% effective
                gaps.append({
                    "control": control,
                    "effectiveness": effectiveness,
                    "recommendation": f"Improve {control} implementation or consider alternative controls"
                })
        
        # Identify missing controls in vulnerable environments
        environment_types = set()
        missing_controls = defaultdict(set)
        
        for result in self.universe_results.values():
            if result.get("overall_success", False):
                env = result.get("environment", {})
                env_type = env.get("environment_type", "unknown")
                environment_types.add(env_type)
                
                controls = set(env.get("security_controls", []))
                all_controls = {"firewall", "antivirus", "edr", "email_filtering", "dlp", "network_segmentation", "mfa"}
                
                missing = all_controls - controls
                missing_controls[env_type].update(missing)
        
        # Add missing control recommendations
        for env_type in environment_types:
            if env_type in missing_controls and missing_controls[env_type]:
                gaps.append({
                    "environment_type": env_type,
                    "missing_controls": list(missing_controls[env_type]),
                    "recommendation": f"Implement missing controls for {env_type} environments"
                })
        
        return gaps
    
    def generate_comprehensive_report(self):
        """
        Generate a comprehensive report of parallel universe testing results.
        
        Returns:
            dict: Comprehensive report
        """
        if not self.universe_results or not self.universe_stats:
            return {"error": "No simulation results available"}
        
        # Calculate test duration
        if self.test_status["start_time"] and self.test_status["end_time"]:
            duration = (self.test_status["end_time"] - self.test_status["start_time"]).total_seconds()
        else:
            duration = 0
        
        # Generate report
        report = {
            "title": "Parallel Universe Testing Comprehensive Report",
            "generation_date": datetime.now(),
            "test_summary": {
                "total_universes": self.test_status["total_universes"],
                "completed_universes": self.test_status["completed_universes"],
                "duration_seconds": duration,
                "success_rate": self.universe_stats.get("success_rate", 0),
                "detection_rate": self.universe_stats.get("detection_rate", 0),
                "average_dwell_time": self.universe_stats.get("average_dwell_time", 0)
            },
            "key_findings": {
                "most_successful_techniques": self.universe_stats.get("most_successful_techniques", []),
                "most_successful_actor": self.universe_stats.get("most_successful_actor", ""),
                "most_vulnerable_environments": self.universe_stats.get("most_vulnerable_environments", []),
                "most_achieved_objectives": self.universe_stats.get("most_achieved_objectives", [])
            },
            "optimal_attack_paths": self.universe_stats.get("optimal_attack_paths", []),
            "critical_attack_paths": self.find_critical_attack_paths(),
            "security_control_effectiveness": self.universe_stats.get("security_control_effectiveness", {}),
            "security_control_gaps": self.identify_security_control_gaps(),
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self):
        """
        Generate security recommendations based on simulation results.
        
        Returns:
            list: Security recommendations
        """
        if not self.universe_stats:
            return []
        
        recommendations = []
        
        # Recommendations based on most successful techniques
        most_successful_techniques = self.universe_stats.get("most_successful_techniques", [])
        if most_successful_techniques:
            technique_recommendations = {
                "spear_phishing": "Implement advanced email filtering and user awareness training",
                "strategic_web_compromise": "Deploy web application firewalls and browser isolation",
                "valid_accounts": "Implement multi-factor authentication and privileged access management",
                "powershell": "Enable PowerShell logging and constrained language mode",
                "wmi_event_subscription": "Monitor for suspicious WMI activity and implement application whitelisting",
                "access_token_manipulation": "Deploy endpoint detection and response solutions",
                "credential_dumping": "Implement credential guard and privileged access workstations",
                "network_service_scanning": "Deploy network monitoring and segmentation",
                "remote_desktop_protocol": "Restrict RDP access and implement just-in-time access",
                "data_encrypted": "Deploy data loss prevention solutions"
            }
            
            for technique, _ in most_successful_techniques:
                if technique in technique_recommendations:
                    recommendations.append({
                        "title": f"Mitigate {technique.replace('_', ' ')} attacks",
                        "description": f"This technique was highly successful in simulations",
                        "actions": [technique_recommendations[technique]]
                    })
        
        # Recommendations based on security control gaps
        gaps = self.identify_security_control_gaps()
        if gaps:
            for gap in gaps:
                if "control" in gap:
                    recommendations.append({
                        "title": f"Improve {gap['control']} effectiveness",
                        "description": f"Current implementation shows low effectiveness ({gap['effectiveness']:.2f})",
                        "actions": [gap["recommendation"]]
                    })
                elif "environment_type" in gap:
                    recommendations.append({
                        "title": f"Address security gaps in {gap['environment_type']} environments",
                        "description": f"Missing critical security controls",
                        "actions": [f"Implement {control}" for control in gap["missing_controls"]]
                    })
        
        # Recommendations based on most vulnerable environments
        vulnerable_environments = self.universe_stats.get("most_vulnerable_environments", [])
        if vulnerable_environments:
            env_recommendations = {
                "on_premise": [
                    "Implement network segmentation",
                    "Deploy endpoint detection and response",
                    "Implement privileged access management"
                ],
                "cloud": [
                    "Enable cloud security posture management",
                    "Implement identity and access management",
                    "Enable cloud workload protection"
                ],
                "hybrid": [
                    "Establish consistent security controls across environments",
                    "Implement zero trust architecture",
                    "Deploy unified security monitoring"
                ],
                "container": [
                    "Implement container security scanning",
                    "Deploy runtime container security",
                    "Establish secure CI/CD pipelines"
                ]
            }
            
            for env_type, vulnerability_rate in vulnerable_environments:
                if env_type in env_recommendations and vulnerability_rate > 0.5:
                    recommendations.append({
                        "title": f"Strengthen {env_type} environment security",
                        "description": f"High vulnerability rate ({vulnerability_rate:.2f})",
                        "actions": env_recommendations[env_type]
                    })
        
        return recommendations
    
    def visualize_attack_paths(self):
        """
        Generate data for visualizing attack paths across universes.
        
        Returns:
            dict: Visualization data
        """
        if not self.universe_results:
            return {"error": "No simulation results available"}
        
        # Extract attack paths
        attack_paths = []
        for result in self.universe_results.values():
            if "attack_path" in result:
                path = []
                for phase in result["attack_path"]:
                    path.append({
                        "phase": phase.get("phase", ""),
                        "technique": phase.get("technique", ""),
                        "success": result.get("overall_success", False)
                    })
                
                attack_paths.append({
                    "universe_id": result.get("universe_id", ""),
                    "path": path,
                    "success": result.get("overall_success", False)
                })
        
        # Generate nodes and links for visualization
        nodes = set()
        links = []
        
        for path_data in attack_paths:
            path = path_data["path"]
            success = path_data["success"]
            
            for i, step in enumerate(path):
                phase = step["phase"]
                technique = step["technique"]
                
                # Add nodes
                nodes.add(phase)
                nodes.add(technique)
                
                # Add link from phase to technique
                links.append({
                    "source": phase,
                    "target": technique,
                    "value": 2 if success else 1
                })
                
                # Add link to next phase if available
                if i < len(path) - 1:
                    next_phase = path[i+1]["phase"]
                    links.append({
                        "source": technique,
                        "target": next_phase,
                        "value": 2 if success else 1
                    })
        
        # Convert nodes to list of dictionaries
        node_list = [{"id": node, "group": 1 if node in ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration"] else 2} for node in nodes]
        
        # Aggregate link values
        link_dict = {}
        for link in links:
            key = f"{link['source']}->{link['target']}"
            if key in link_dict:
                link_dict[key]["value"] += link["value"]
            else:
                link_dict[key] = link
        
        # Convert back to list
        link_list = list(link_dict.values())
        
        return {
            "nodes": node_list,
            "links": link_list
        }
    
    def export_results(self, format="json"):
        """
        Export simulation results in the specified format.
        
        Args:
            format (str): Export format (json, csv)
            
        Returns:
            str: Exported results
        """
        if format == "json":
            export_data = {
                "test_status": self.test_status,
                "universe_stats": self.universe_stats,
                "universe_results": self.universe_results
            }
            return json.dumps(export_data, default=str, indent=2)
        else:
            # Could implement other formats like CSV, HTML, etc.
            return "Unsupported format"


# Example usage
if __name__ == "__main__":
    # Create the Parallel Universe Testing framework
    put = ParallelUniverseTesting(max_parallel_universes=100)
    
    # Create a base target environment
    base_environment = {
        "name": "Example Corporation",
        "environment_type": "hybrid",
        "security_maturity": "medium",
        "security_controls": [
            "firewall",
            "antivirus",
            "email_filtering"
        ]
    }
    
    # Create environment variants
    environment_variants = put.create_target_environment_variants(base_environment, variation_count=5)
    
    # Create a base attack scenario
    base_scenario = {
        "actor_id": "APT29",
        "campaign_duration_days": 30,
        "objectives": ["data_exfiltration", "persistence"]
    }
    
    # Create scenario variants
    scenario_variants = put.create_attack_scenario_variants(base_scenario, variation_count=5)
    
    # Generate universe matrix
    universe_configs = put.generate_universe_matrix(environment_variants, scenario_variants, max_universes=10)
    
    # Run parallel simulations
    results = put.run_parallel_simulations(universe_configs, max_workers=5)
    
    # Generate comprehensive report
    report = put.generate_comprehensive_report()
    
    print(json.dumps(report["test_summary"], indent=2))