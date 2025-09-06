"""
Advanced Persistent Threat (APT) Simulation Engine

This module implements a system for simulating sophisticated nation-state level
threat actors with their complete tactics, techniques, and procedures (TTPs).
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from collections import defaultdict
import networkx as nx

try:
    from .knowledge_graph import AttackKnowledgeGraph
except ImportError:
    print("Warning: Unable to import AttackKnowledgeGraph. Some functionality may be limited.")


class APTSimulationEngine:
    """
    A system that simulates Advanced Persistent Threat (APT) actors,
    their tactics, techniques, and procedures for realistic security testing.
    """

    def __init__(self):
        self.threat_actors = self._load_threat_actors()
        self.attack_graph = nx.DiGraph()
        self.simulation_results = []
        self.current_simulation = None
        self._build_attack_graph()
    
    def _load_threat_actors(self):
        """Load known APT groups and their TTPs."""
        # In a production system, this would be loaded from a database
        # that's regularly updated with new threat intelligence
        return {
            "APT1": {
                "name": "APT1 (Comment Crew)",
                "attribution": "China (PLA Unit 61398)",
                "motivation": ["espionage", "intellectual_property_theft"],
                "target_sectors": ["aerospace", "defense", "energy", "telecommunications"],
                "sophistication_level": 8,
                "first_observed": "2006",
                "tactics": {
                    "initial_access": ["spear_phishing", "strategic_web_compromise"],
                    "execution": ["command_line_interface", "scripting"],
                    "persistence": ["registry_run_keys", "web_shells", "backdoor"],
                    "privilege_escalation": ["valid_accounts", "accessibility_features"],
                    "defense_evasion": ["file_deletion", "timestomp", "obfuscated_files"],
                    "credential_access": ["credential_dumping", "brute_force"],
                    "discovery": ["network_service_scanning", "system_information_discovery"],
                    "lateral_movement": ["remote_desktop_protocol", "windows_admin_shares"],
                    "collection": ["data_from_local_system", "email_collection"],
                    "exfiltration": ["data_compressed", "scheduled_transfer"]
                },
                "tools": ["BACKDOOR.BARKIOFORK", "BACKDOOR.WAKEMINAP", "TROJAN.ECLTYS", "BACKDOOR.DALBOT"],
                "malware_characteristics": {
                    "c2_protocol": "HTTP",
                    "encryption": "custom_obfuscation",
                    "persistence_mechanism": "registry_keys",
                    "anti_analysis": ["anti_vm", "anti_debugging"]
                }
            },
            "APT28": {
                "name": "APT28 (Fancy Bear)",
                "attribution": "Russia (GRU)",
                "motivation": ["espionage", "political_influence"],
                "target_sectors": ["government", "defense", "political_organizations", "media"],
                "sophistication_level": 9,
                "first_observed": "2008",
                "tactics": {
                    "initial_access": ["spear_phishing", "zero_day_vulnerabilities"],
                    "execution": ["powershell", "command_line_interface", "scheduled_task"],
                    "persistence": ["bootkit", "wmi_event_subscription", "accessibility_features"],
                    "privilege_escalation": ["exploitation_for_privilege_escalation", "access_token_manipulation"],
                    "defense_evasion": ["process_injection", "masquerading", "rootkit"],
                    "credential_access": ["credential_dumping", "keylogger", "input_capture"],
                    "discovery": ["account_discovery", "network_share_discovery", "system_network_configuration_discovery"],
                    "lateral_movement": ["exploitation_of_remote_services", "pass_the_hash", "remote_file_copy"],
                    "collection": ["screen_capture", "clipboard_data", "data_staged"],
                    "exfiltration": ["exfiltration_over_c2_channel", "automated_exfiltration", "data_encrypted"]
                },
                "tools": ["X-Tunnel", "X-Agent", "CHOPSTICK", "ADVSTORESHELL", "HAMMERTOSS"],
                "malware_characteristics": {
                    "c2_protocol": "HTTPS",
                    "encryption": "AES",
                    "persistence_mechanism": "bootkit",
                    "anti_analysis": ["anti_vm", "anti_debugging", "code_signing"]
                }
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "attribution": "North Korea",
                "motivation": ["financial_gain", "sabotage", "espionage"],
                "target_sectors": ["financial", "media", "entertainment", "critical_infrastructure"],
                "sophistication_level": 9,
                "first_observed": "2009",
                "tactics": {
                    "initial_access": ["supply_chain_compromise", "spear_phishing", "watering_hole"],
                    "execution": ["user_execution", "command_line_interface", "scripting"],
                    "persistence": ["registry_run_keys", "create_account", "scheduled_task"],
                    "privilege_escalation": ["bypass_user_account_control", "exploitation_for_privilege_escalation"],
                    "defense_evasion": ["obfuscated_files", "file_deletion", "indicator_removal_on_host"],
                    "credential_access": ["credential_dumping", "input_capture", "brute_force"],
                    "discovery": ["system_information_discovery", "security_software_discovery"],
                    "lateral_movement": ["exploitation_of_remote_services", "remote_file_copy", "windows_admin_shares"],
                    "collection": ["data_from_local_system", "data_staged", "email_collection"],
                    "exfiltration": ["data_encrypted", "exfiltration_over_alternative_protocol"]
                },
                "tools": ["BLINDINGCAN", "HOPLIGHT", "ELECTRICFISH", "BADCALL", "FALLCHILL"],
                "malware_characteristics": {
                    "c2_protocol": "HTTPS",
                    "encryption": "custom_encryption",
                    "persistence_mechanism": "scheduled_tasks",
                    "anti_analysis": ["anti_vm", "anti_debugging", "code_signing", "string_obfuscation"]
                }
            },
            "APT29": {
                "name": "APT29 (Cozy Bear)",
                "attribution": "Russia (SVR)",
                "motivation": ["espionage", "intelligence_gathering"],
                "target_sectors": ["government", "think_tanks", "healthcare", "pharmaceuticals"],
                "sophistication_level": 10,
                "first_observed": "2008",
                "tactics": {
                    "initial_access": ["spear_phishing", "valid_accounts", "supply_chain_compromise"],
                    "execution": ["powershell", "command_line_interface", "windows_management_instrumentation"],
                    "persistence": ["wmi_event_subscription", "office_application_startup", "scheduled_task"],
                    "privilege_escalation": ["access_token_manipulation", "bypass_user_account_control"],
                    "defense_evasion": ["masquerading", "obfuscated_files", "indicator_removal_on_host"],
                    "credential_access": ["credential_dumping", "brute_force", "steal_web_session_cookie"],
                    "discovery": ["account_discovery", "network_share_discovery", "process_discovery"],
                    "lateral_movement": ["remote_desktop_protocol", "exploitation_of_remote_services", "internal_spearphishing"],
                    "collection": ["data_from_information_repositories", "email_collection", "data_from_network_shared_drive"],
                    "exfiltration": ["exfiltration_over_web_service", "scheduled_transfer", "data_encrypted"]
                },
                "tools": ["MiniDuke", "CosmicDuke", "HAMMERTOSS", "SeaDuke", "WellMess"],
                "malware_characteristics": {
                    "c2_protocol": "HTTPS",
                    "encryption": "AES",
                    "persistence_mechanism": "wmi_event_subscription",
                    "anti_analysis": ["anti_vm", "anti_debugging", "code_signing", "process_injection"]
                }
            }
        }
    
    def _build_attack_graph(self):
        """Build a graph representing APT attack paths and techniques."""
        # Add nodes for each tactic
        mitre_tactics = [
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "exfiltration", "command_and_control", "impact"
        ]
        
        for tactic in mitre_tactics:
            self.attack_graph.add_node(tactic, type="tactic")
        
        # Add edges between tactics representing typical attack flow
        attack_flow = [
            ("initial_access", "execution"),
            ("execution", "persistence"),
            ("persistence", "privilege_escalation"),
            ("privilege_escalation", "defense_evasion"),
            ("defense_evasion", "credential_access"),
            ("credential_access", "discovery"),
            ("discovery", "lateral_movement"),
            ("lateral_movement", "collection"),
            ("collection", "exfiltration"),
            ("exfiltration", "impact")
        ]
        
        for source, target in attack_flow:
            self.attack_graph.add_edge(source, target, relationship="attack_flow")
        
        # Add nodes for each technique used by APT groups
        for actor_id, actor_data in self.threat_actors.items():
            # Add a node for the threat actor
            self.attack_graph.add_node(actor_id, type="threat_actor", **actor_data)
            
            # Add technique nodes and connect them to tactics and the threat actor
            for tactic, techniques in actor_data["tactics"].items():
                for technique in techniques:
                    technique_id = f"{tactic}_{technique}"
                    
                    # Add the technique node if it doesn't exist
                    if not self.attack_graph.has_node(technique_id):
                        self.attack_graph.add_node(technique_id, type="technique", name=technique, tactic=tactic)
                        
                        # Connect the technique to its tactic
                        self.attack_graph.add_edge(tactic, technique_id, relationship="has_technique")
                    
                    # Connect the threat actor to the technique
                    self.attack_graph.add_edge(actor_id, technique_id, relationship="uses_technique")
            
            # Add tool nodes and connect them to the threat actor
            for tool in actor_data["tools"]:
                tool_id = f"tool_{tool}"
                
                # Add the tool node if it doesn't exist
                if not self.attack_graph.has_node(tool_id):
                    self.attack_graph.add_node(tool_id, type="tool", name=tool)
                
                # Connect the threat actor to the tool
                self.attack_graph.add_edge(actor_id, tool_id, relationship="uses_tool")
    
    def get_actor_profile(self, actor_id):
        """
        Get the profile of a specific threat actor.
        
        Args:
            actor_id (str): The ID of the threat actor
            
        Returns:
            dict: The threat actor profile
        """
        if actor_id in self.threat_actors:
            return self.threat_actors[actor_id]
        else:
            return {"error": f"Threat actor {actor_id} not found."}
    
    def list_available_actors(self):
        """
        List all available threat actors.
        
        Returns:
            list: List of available threat actors with basic information
        """
        return [
            {
                "id": actor_id,
                "name": actor_data["name"],
                "attribution": actor_data["attribution"],
                "sophistication_level": actor_data["sophistication_level"],
                "motivation": actor_data["motivation"],
                "target_sectors": actor_data["target_sectors"]
            }
            for actor_id, actor_data in self.threat_actors.items()
        ]
    
    def create_simulation(self, actor_id, target_environment, campaign_duration_days=30, objectives=None):
        """
        Create a new APT simulation campaign.
        
        Args:
            actor_id (str): The ID of the threat actor to simulate
            target_environment (dict): Description of the target environment
            campaign_duration_days (int): Duration of the campaign in days
            objectives (list): Specific objectives for the campaign
            
        Returns:
            dict: The created simulation configuration
        """
        if actor_id not in self.threat_actors:
            return {"error": f"Threat actor {actor_id} not found."}
        
        # Set default objectives if none provided
        if objectives is None:
            objectives = ["data_exfiltration", "persistence", "lateral_movement"]
        
        # Create a new simulation
        simulation_id = str(uuid.uuid4())
        start_date = datetime.now()
        end_date = start_date + timedelta(days=campaign_duration_days)
        
        simulation = {
            "id": simulation_id,
            "actor_id": actor_id,
            "actor_name": self.threat_actors[actor_id]["name"],
            "target_environment": target_environment,
            "objectives": objectives,
            "start_date": start_date,
            "end_date": end_date,
            "duration_days": campaign_duration_days,
            "status": "created",
            "attack_path": [],
            "timeline": [],
            "results": {},
            "creation_time": datetime.now()
        }
        
        self.current_simulation = simulation
        return simulation
    
    def plan_attack_campaign(self):
        """
        Plan the attack campaign for the current simulation.
        
        Returns:
            dict: The updated simulation with attack path
        """
        if not self.current_simulation:
            return {"error": "No active simulation. Create a simulation first."}
        
        actor_id = self.current_simulation["actor_id"]
        actor_data = self.threat_actors[actor_id]
        target_env = self.current_simulation["target_environment"]
        objectives = self.current_simulation["objectives"]
        
        # Plan attack path based on actor TTPs and target environment
        attack_path = []
        
        # Initial Access Phase
        initial_access_techniques = actor_data["tactics"].get("initial_access", [])
        if initial_access_techniques:
            # Select techniques based on target environment
            selected_technique = self._select_best_technique(initial_access_techniques, target_env, "initial_access")
            attack_path.append({
                "phase": "initial_access",
                "technique": selected_technique,
                "description": self._generate_technique_description(selected_technique, actor_id, target_env),
                "estimated_success_probability": self._calculate_success_probability(selected_technique, actor_id, target_env),
                "detection_evasion_level": self._calculate_detection_evasion(selected_technique, actor_id)
            })
        
        # Build the rest of the attack path through all tactics
        tactics_sequence = [
            "execution", "persistence", "privilege_escalation", "defense_evasion",
            "credential_access", "discovery", "lateral_movement", "collection", "exfiltration"
        ]
        
        for tactic in tactics_sequence:
            techniques = actor_data["tactics"].get(tactic, [])
            if techniques:
                selected_technique = self._select_best_technique(techniques, target_env, tactic)
                
                # Skip if not relevant to objectives
                if tactic == "lateral_movement" and "lateral_movement" not in objectives:
                    continue
                if tactic == "exfiltration" and "data_exfiltration" not in objectives:
                    continue
                if tactic == "persistence" and "persistence" not in objectives:
                    continue
                
                attack_path.append({
                    "phase": tactic,
                    "technique": selected_technique,
                    "description": self._generate_technique_description(selected_technique, actor_id, target_env),
                    "estimated_success_probability": self._calculate_success_probability(selected_technique, actor_id, target_env),
                    "detection_evasion_level": self._calculate_detection_evasion(selected_technique, actor_id)
                })
        
        # Add tools used in the attack
        tools_used = []
        for tool in actor_data["tools"]:
            if random.random() < 0.7:  # 70% chance to use each tool
                tools_used.append({
                    "name": tool,
                    "purpose": self._determine_tool_purpose(tool, actor_id),
                    "detection_difficulty": random.uniform(0.6, 0.9)  # Higher is harder to detect
                })
        
        # Update the simulation with the attack path and tools
        self.current_simulation["attack_path"] = attack_path
        self.current_simulation["tools_used"] = tools_used
        self.current_simulation["status"] = "planned"
        
        return self.current_simulation
    
    def _select_best_technique(self, techniques, target_env, tactic):
        """
        Select the best technique for the given tactic based on the target environment.
        
        Args:
            techniques (list): Available techniques for the tactic
            target_env (dict): Target environment description
            tactic (str): The tactic name
            
        Returns:
            str: The selected technique
        """
        # In a real implementation, this would use more sophisticated logic
        # to select the most appropriate technique based on the target environment
        
        # For now, use a simple scoring system
        technique_scores = {}
        
        for technique in techniques:
            score = random.uniform(0.5, 1.0)  # Base score
            
            # Adjust score based on target environment factors
            if "security_controls" in target_env:
                # Lower score if specific security controls counter this technique
                if tactic == "initial_access" and "email_filtering" in target_env["security_controls"] and technique == "spear_phishing":
                    score *= 0.7
                if tactic == "defense_evasion" and "edr" in target_env["security_controls"]:
                    score *= 0.8
                if tactic == "lateral_movement" and "network_segmentation" in target_env["security_controls"]:
                    score *= 0.7
            
            # Adjust score based on target environment type
            if "environment_type" in target_env:
                if target_env["environment_type"] == "cloud" and technique in ["registry_run_keys", "wmi_event_subscription"]:
                    score *= 0.5  # Less effective in cloud environments
                if target_env["environment_type"] == "on_premise" and technique in ["valid_accounts", "exploitation_of_remote_services"]:
                    score *= 1.2  # More effective in on-premise environments
            
            technique_scores[technique] = score
        
        # Select the technique with the highest score
        return max(technique_scores, key=technique_scores.get)
    
    def _generate_technique_description(self, technique, actor_id, target_env):
        """
        Generate a description of how the technique would be used in the attack.
        
        Args:
            technique (str): The technique name
            actor_id (str): The threat actor ID
            target_env (dict): Target environment description
            
        Returns:
            str: Description of the technique usage
        """
        # This would be more sophisticated in a real implementation
        # For now, use some predefined descriptions
        
        technique_descriptions = {
            "spear_phishing": f"The {self.threat_actors[actor_id]['name']} group crafts highly targeted phishing emails to employees, impersonating trusted entities. Emails contain malicious attachments or links to credential harvesting pages.",
            "strategic_web_compromise": f"The {self.threat_actors[actor_id]['name']} group compromises websites frequently visited by target organization employees (watering hole attack), injecting malicious code to exploit browser vulnerabilities.",
            "valid_accounts": f"The {self.threat_actors[actor_id]['name']} group uses previously stolen credentials to gain initial access to the environment, bypassing traditional security controls.",
            "powershell": f"The {self.threat_actors[actor_id]['name']} group uses fileless malware techniques with PowerShell scripts that load directly into memory, avoiding disk-based detection.",
            "wmi_event_subscription": f"The {self.threat_actors[actor_id]['name']} group establishes persistence using WMI event subscriptions that trigger malicious code when specific system events occur.",
            "access_token_manipulation": f"The {self.threat_actors[actor_id]['name']} group steals and manipulates access tokens to impersonate legitimate users and processes, elevating privileges.",
            "credential_dumping": f"The {self.threat_actors[actor_id]['name']} group extracts credentials from memory using custom tools, targeting LSASS process and credential stores.",
            "network_service_scanning": f"The {self.threat_actors[actor_id]['name']} group performs low-and-slow network scanning to identify vulnerable services and potential lateral movement paths.",
            "remote_desktop_protocol": f"The {self.threat_actors[actor_id]['name']} group uses compromised credentials to move laterally via RDP, blending in with legitimate administrative activity.",
            "data_encrypted": f"The {self.threat_actors[actor_id]['name']} group encrypts stolen data using custom algorithms before exfiltration to avoid detection by DLP solutions."
        }
        
        # Return the description if available, otherwise generate a generic one
        return technique_descriptions.get(
            technique, 
            f"The {self.threat_actors[actor_id]['name']} group employs {technique.replace('_', ' ')} techniques customized for the target environment."
        )
    
    def _calculate_success_probability(self, technique, actor_id, target_env):
        """
        Calculate the probability of success for a technique.
        
        Args:
            technique (str): The technique name
            actor_id (str): The threat actor ID
            target_env (dict): Target environment description
            
        Returns:
            float: Probability of success (0-1)
        """
        # Base probability based on actor sophistication
        base_probability = self.threat_actors[actor_id]["sophistication_level"] / 10
        
        # Adjust based on security controls
        if "security_controls" in target_env:
            controls = target_env["security_controls"]
            
            # Specific adjustments for different techniques and controls
            if technique == "spear_phishing" and "email_filtering" in controls:
                base_probability *= 0.7
            elif technique == "strategic_web_compromise" and "web_filtering" in controls:
                base_probability *= 0.8
            elif technique == "credential_dumping" and "edr" in controls:
                base_probability *= 0.6
            elif technique == "lateral_movement" and "network_segmentation" in controls:
                base_probability *= 0.7
            elif technique == "data_encrypted" and "dlp" in controls:
                base_probability *= 0.8
            
            # General adjustment for security maturity
            if "security_maturity" in target_env:
                maturity = target_env["security_maturity"]
                if maturity == "high":
                    base_probability *= 0.7
                elif maturity == "medium":
                    base_probability *= 0.85
                # Low maturity doesn't reduce probability
        
        # Ensure probability is between 0.1 and 0.95
        return max(0.1, min(0.95, base_probability))
    
    def _calculate_detection_evasion(self, technique, actor_id):
        """
        Calculate the detection evasion level for a technique.
        
        Args:
            technique (str): The technique name
            actor_id (str): The threat actor ID
            
        Returns:
            float: Detection evasion level (0-1)
        """
        # Base evasion level based on actor sophistication
        base_evasion = self.threat_actors[actor_id]["sophistication_level"] / 10
        
        # Adjust based on technique
        evasion_adjustments = {
            "obfuscated_files": 0.2,
            "masquerading": 0.15,
            "rootkit": 0.25,
            "timestomp": 0.1,
            "indicator_removal_on_host": 0.2,
            "process_injection": 0.2,
            "file_deletion": 0.1
        }
        
        adjustment = evasion_adjustments.get(technique, 0)
        evasion_level = base_evasion + adjustment
        
        # Ensure evasion level is between 0.1 and 0.95
        return max(0.1, min(0.95, evasion_level))
    
    def _determine_tool_purpose(self, tool, actor_id):
        """
        Determine the purpose of a tool used by the threat actor.
        
        Args:
            tool (str): The tool name
            actor_id (str): The threat actor ID
            
        Returns:
            str: The tool purpose
        """
        # This would be more sophisticated in a real implementation
        # For now, use some predefined purposes
        
        tool_purposes = {
            "BACKDOOR.BARKIOFORK": "Establish persistent remote access",
            "BACKDOOR.WAKEMINAP": "Maintain persistence and execute commands",
            "TROJAN.ECLTYS": "Steal credentials and sensitive data",
            "BACKDOOR.DALBOT": "Command and control communication",
            "X-Tunnel": "Secure communication channel for data exfiltration",
            "X-Agent": "Comprehensive remote access toolkit",
            "CHOPSTICK": "Keylogging and credential theft",
            "ADVSTORESHELL": "Persistence and backdoor functionality",
            "HAMMERTOSS": "Stealthy command and control using social media",
            "BLINDINGCAN": "Remote access and system reconnaissance",
            "HOPLIGHT": "Proxy tool for hiding malicious traffic",
            "ELECTRICFISH": "Tunneling traffic through compromised systems",
            "BADCALL": "Backdoor for command execution",
            "FALLCHILL": "Remote administration tool",
            "MiniDuke": "Initial compromise and downloader",
            "CosmicDuke": "Information stealing and persistence",
            "SeaDuke": "Second-stage backdoor",
            "WellMess": "Remote command execution and data exfiltration"
        }
        
        return tool_purposes.get(tool, "Multi-purpose malware for remote access and data theft")
    
    def execute_simulation(self):
        """
        Execute the planned attack simulation.
        
        Returns:
            dict: Simulation results
        """
        if not self.current_simulation or self.current_simulation["status"] != "planned":
            return {"error": "No planned simulation to execute. Plan an attack campaign first."}
        
        # Initialize timeline and results
        timeline = []
        results = {
            "overall_success": False,
            "objectives_achieved": [],
            "objectives_failed": [],
            "detection_points": [],
            "time_to_objective": {},
            "dwell_time": 0
        }
        
        # Set simulation start time
        start_time = datetime.now()
        current_time = start_time
        
        # Track the state of the simulation
        simulation_state = {
            "has_access": False,
            "has_persistence": False,
            "has_elevated_privileges": False,
            "has_lateral_movement": False,
            "has_collected_data": False,
            "has_exfiltrated_data": False,
            "detected": False,
            "detection_time": None
        }
        
        # Execute each phase in the attack path
        for phase in self.current_simulation["attack_path"]:
            # Skip if already detected
            if simulation_state["detected"]:
                phase_result = {
                    "status": "skipped",
                    "reason": "Campaign already detected"
                }
            else:
                # Determine if phase succeeds based on success probability
                success_roll = random.random()
                phase_success = success_roll < phase["estimated_success_probability"]
                
                # Determine if phase is detected based on evasion level
                detection_roll = random.random()
                phase_detected = detection_roll > phase["detection_evasion_level"]
                
                # Update simulation state based on phase outcome
                if phase_success:
                    if phase["phase"] == "initial_access":
                        simulation_state["has_access"] = True
                    elif phase["phase"] == "persistence":
                        simulation_state["has_persistence"] = True
                    elif phase["phase"] == "privilege_escalation":
                        simulation_state["has_elevated_privileges"] = True
                    elif phase["phase"] == "lateral_movement":
                        simulation_state["has_lateral_movement"] = True
                    elif phase["phase"] == "collection":
                        simulation_state["has_collected_data"] = True
                    elif phase["phase"] == "exfiltration":
                        simulation_state["has_exfiltrated_data"] = True
                
                # Check if phase was detected
                if phase_detected:
                    simulation_state["detected"] = True
                    simulation_state["detection_time"] = current_time
                    
                    results["detection_points"].append({
                        "phase": phase["phase"],
                        "technique": phase["technique"],
                        "time": current_time,
                        "time_since_start": (current_time - start_time).total_seconds() / 3600  # hours
                    })
                
                # Record phase result
                phase_result = {
                    "status": "success" if phase_success else "failure",
                    "detected": phase_detected,
                    "details": f"{'Successfully executed' if phase_success else 'Failed to execute'} {phase['technique']} technique"
                }
                
                # Advance time based on phase complexity
                time_advance = random.randint(1, 5) if phase_success else random.randint(4, 8)
                current_time += timedelta(hours=time_advance)
            
            # Add to timeline
            timeline.append({
                "time": current_time,
                "phase": phase["phase"],
                "technique": phase["technique"],
                "result": phase_result
            })
        
        # Determine overall success based on objectives
        objectives = self.current_simulation["objectives"]
        
        for objective in objectives:
            if objective == "persistence" and simulation_state["has_persistence"]:
                results["objectives_achieved"].append("persistence")
                results["time_to_objective"]["persistence"] = self._find_time_to_objective(timeline, "persistence")
            elif objective == "lateral_movement" and simulation_state["has_lateral_movement"]:
                results["objectives_achieved"].append("lateral_movement")
                results["time_to_objective"]["lateral_movement"] = self._find_time_to_objective(timeline, "lateral_movement")
            elif objective == "data_exfiltration" and simulation_state["has_exfiltrated_data"]:
                results["objectives_achieved"].append("data_exfiltration")
                results["time_to_objective"]["data_exfiltration"] = self._find_time_to_objective(timeline, "exfiltration")
            else:
                results["objectives_failed"].append(objective)
        
        # Calculate overall success
        results["overall_success"] = len(results["objectives_achieved"]) > 0 and not (len(results["objectives_achieved"]) < len(objectives) and simulation_state["detected"])
        
        # Calculate dwell time (time from initial access to detection or end)
        if simulation_state["detected"]:
            initial_access_time = timeline[0]["time"] if timeline else start_time
            results["dwell_time"] = (simulation_state["detection_time"] - initial_access_time).total_seconds() / 3600  # hours
        else:
            initial_access_time = timeline[0]["time"] if timeline else start_time
            results["dwell_time"] = (current_time - initial_access_time).total_seconds() / 3600  # hours
            results["detection_status"] = "undetected"
        
        # Update simulation with results
        self.current_simulation["timeline"] = timeline
        self.current_simulation["results"] = results
        self.current_simulation["status"] = "executed"
        self.current_simulation["execution_time"] = datetime.now()
        
        # Add to simulation results history
        self.simulation_results.append(self.current_simulation)
        
        return self.current_simulation
    
    def _find_time_to_objective(self, timeline, objective_phase):
        """
        Find the time it took to achieve an objective.
        
        Args:
            timeline (list): The simulation timeline
            objective_phase (str): The phase corresponding to the objective
            
        Returns:
            float: Time to objective in hours
        """
        start_time = timeline[0]["time"] if timeline else None
        
        for event in timeline:
            if event["phase"] == objective_phase and event["result"]["status"] == "success":
                return (event["time"] - start_time).total_seconds() / 3600 if start_time else 0
        
        return None
    
    def generate_report(self, simulation_id=None):
        """
        Generate a comprehensive report for a simulation.
        
        Args:
            simulation_id (str): The ID of the simulation to report on
            
        Returns:
            dict: The simulation report
        """
        # Use current simulation if no ID provided
        simulation = None
        
        if simulation_id:
            # Find simulation by ID
            for sim in self.simulation_results:
                if sim["id"] == simulation_id:
                    simulation = sim
                    break
            
            if not simulation:
                return {"error": f"Simulation with ID {simulation_id} not found."}
        else:
            # Use current simulation
            if not self.current_simulation or self.current_simulation["status"] != "executed":
                return {"error": "No executed simulation to report on."}
            
            simulation = self.current_simulation
        
        # Generate report
        actor_data = self.threat_actors[simulation["actor_id"]]
        
        report = {
            "title": f"APT Simulation Report: {actor_data['name']}",
            "simulation_id": simulation["id"],
            "generation_date": datetime.now(),
            "executive_summary": self._generate_executive_summary(simulation),
            "threat_actor_profile": {
                "name": actor_data["name"],
                "attribution": actor_data["attribution"],
                "sophistication_level": actor_data["sophistication_level"],
                "motivation": actor_data["motivation"],
                "target_sectors": actor_data["target_sectors"]
            },
            "simulation_overview": {
                "target_environment": simulation["target_environment"],
                "objectives": simulation["objectives"],
                "duration": simulation["duration_days"],
                "start_date": simulation["start_date"],
                "end_date": simulation["end_date"]
            },
            "attack_campaign": {
                "attack_path": simulation["attack_path"],
                "tools_used": simulation.get("tools_used", []),
                "timeline": simulation["timeline"]
            },
            "results": simulation["results"],
            "security_recommendations": self._generate_security_recommendations(simulation)
        }
        
        return report
    
    def _generate_executive_summary(self, simulation):
        """
        Generate an executive summary for the simulation report.
        
        Args:
            simulation (dict): The simulation data
            
        Returns:
            str: Executive summary
        """
        results = simulation["results"]
        actor_name = self.threat_actors[simulation["actor_id"]]["name"]
        
        # Determine overall outcome
        if results["overall_success"]:
            outcome = "successfully achieved"
        else:
            outcome = "failed to achieve all"
        
        # Summarize objectives
        objectives_achieved = len(results["objectives_achieved"])
        total_objectives = len(simulation["objectives"])
        
        # Summarize detection
        if "detection_points" in results and results["detection_points"]:
            detection_summary = f"The attack was detected during the {results['detection_points'][0]['phase']} phase after {results['dwell_time']:.1f} hours."
        else:
            detection_summary = f"The attack remained undetected for the entire campaign duration of {results['dwell_time']:.1f} hours."
        
        # Generate summary
        summary = f"""
This report summarizes the results of an Advanced Persistent Threat (APT) simulation campaign conducted using the tactics, techniques, and procedures (TTPs) of {actor_name}. The simulated threat actor {outcome} their objectives, completing {objectives_achieved} out of {total_objectives} planned objectives. {detection_summary}

The simulation revealed {'significant' if objectives_achieved > 0 else 'potential'} security gaps that could be exploited by a sophisticated threat actor. {'The successful achievement of objectives indicates that the current security posture may not be sufficient to defend against a determined APT group with similar capabilities.' if objectives_achieved > 0 else 'While the attack was not fully successful, the security team should address the identified vulnerabilities to improve the overall security posture.'}
"""
        
        return summary.strip()
    
    def _generate_security_recommendations(self, simulation):
        """
        Generate security recommendations based on simulation results.
        
        Args:
            simulation (dict): The simulation data
            
        Returns:
            list: Security recommendations
        """
        recommendations = []
        results = simulation["results"]
        attack_path = simulation["attack_path"]
        
        # Add recommendations based on successful attack phases
        successful_phases = []
        for event in simulation["timeline"]:
            if event["result"]["status"] == "success" and event["phase"] not in successful_phases:
                successful_phases.append(event["phase"])
        
        # General recommendations based on successful phases
        phase_recommendations = {
            "initial_access": {
                "title": "Strengthen Initial Access Controls",
                "description": "Improve defenses against initial compromise attempts.",
                "actions": [
                    "Implement advanced email filtering and anti-phishing solutions",
                    "Conduct regular phishing awareness training for all employees",
                    "Deploy web filtering and browser isolation technologies",
                    "Implement strict attachment scanning and sandboxing"
                ]
            },
            "execution": {
                "title": "Enhance Malicious Code Execution Prevention",
                "description": "Prevent execution of unauthorized code in the environment.",
                "actions": [
                    "Implement application whitelisting",
                    "Deploy advanced endpoint protection with behavior monitoring",
                    "Restrict PowerShell and command-line execution",
                    "Enable Windows Attack Surface Reduction rules"
                ]
            },
            "persistence": {
                "title": "Improve Persistence Detection",
                "description": "Detect and prevent attackers from maintaining access.",
                "actions": [
                    "Monitor for unauthorized changes to startup locations and scheduled tasks",
                    "Implement regular system integrity checks",
                    "Deploy EDR solutions with persistence technique detection",
                    "Conduct regular threat hunting for persistence mechanisms"
                ]
            },
            "privilege_escalation": {
                "title": "Strengthen Privilege Management",
                "description": "Prevent attackers from gaining higher privileges.",
                "actions": [
                    "Implement least privilege principles across all systems",
                    "Deploy Privileged Access Management (PAM) solutions",
                    "Regularly audit and review administrative accounts",
                    "Patch systems regularly to address privilege escalation vulnerabilities"
                ]
            },
            "lateral_movement": {
                "title": "Limit Lateral Movement Capabilities",
                "description": "Restrict an attacker's ability to move within the network.",
                "actions": [
                    "Implement network segmentation and micro-segmentation",
                    "Deploy internal network monitoring and traffic analysis",
                    "Restrict administrative tool usage (e.g., PsExec, WMI)",
                    "Implement multi-factor authentication for sensitive systems"
                ]
            },
            "exfiltration": {
                "title": "Enhance Data Exfiltration Controls",
                "description": "Prevent unauthorized data removal from the environment.",
                "actions": [
                    "Deploy Data Loss Prevention (DLP) solutions",
                    "Implement egress filtering and monitoring",
                    "Encrypt sensitive data at rest and in transit",
                    "Monitor for unusual outbound traffic patterns"
                ]
            }
        }
        
        # Add relevant recommendations
        for phase in successful_phases:
            if phase in phase_recommendations:
                recommendations.append(phase_recommendations[phase])
        
        # Add detection-specific recommendations if the attack was detected late or not at all
        if not results.get("detection_points") or results.get("dwell_time", 0) > 24:
            recommendations.append({
                "title": "Improve Threat Detection Capabilities",
                "description": "Enhance ability to detect sophisticated threats earlier in the attack lifecycle.",
                "actions": [
                    "Deploy an advanced Security Information and Event Management (SIEM) solution",
                    "Implement User and Entity Behavior Analytics (UEBA)",
                    "Establish a 24/7 security monitoring capability",
                    "Conduct regular threat hunting exercises",
                    "Consider Managed Detection and Response (MDR) services"
                ]
            })
        
        # Add specific recommendations based on the threat actor
        actor_id = simulation["actor_id"]
        actor_data = self.threat_actors[actor_id]
        
        actor_specific_recommendations = {
            "APT1": {
                "title": "Counter China-Based Threat Actors",
                "description": f"Specific measures to counter {actor_data['name']} and similar threat actors.",
                "actions": [
                    "Monitor for China-based IP addresses and infrastructure",
                    "Deploy network traffic analysis to detect command and control patterns",
                    "Implement strict control over RDP and VPN access",
                    "Monitor for data staging and unusual database queries"
                ]
            },
            "APT28": {
                "title": "Counter Russia-Based Threat Actors",
                "description": f"Specific measures to counter {actor_data['name']} and similar threat actors.",
                "actions": [
                    "Monitor for known Russian APT infrastructure and IOCs",
                    "Implement advanced PowerShell logging and monitoring",
                    "Deploy memory-based threat detection",
                    "Conduct regular security assessments focused on zero-day vulnerabilities"
                ]
            },
            "Lazarus": {
                "title": "Counter North Korea-Based Threat Actors",
                "description": f"Specific measures to counter {actor_data['name']} and similar threat actors.",
                "actions": [
                    "Implement enhanced monitoring for financial systems",
                    "Deploy advanced anti-malware with focus on wiper malware detection",
                    "Monitor for watering hole attacks and supply chain compromises",
                    "Conduct regular security assessments of public-facing applications"
                ]
            },
            "APT29": {
                "title": "Counter Sophisticated Intelligence-Gathering Threat Actors",
                "description": f"Specific measures to counter {actor_data['name']} and similar threat actors.",
                "actions": [
                    "Implement advanced threat detection for living-off-the-land techniques",
                    "Deploy enhanced monitoring for cloud environments",
                    "Conduct regular threat hunting for sophisticated persistence mechanisms",
                    "Implement strict control over third-party integrations and supply chain"
                ]
            }
        }
        
        if actor_id in actor_specific_recommendations:
            recommendations.append(actor_specific_recommendations[actor_id])
        
        return recommendations
    
    def export_results(self, format="json"):
        """Export simulation results in the specified format."""
        if format == "json":
            return json.dumps({
                "simulation_results": self.simulation_results
            }, default=str, indent=2)
        else:
            # Could implement other formats like CSV, HTML, etc.
            return "Unsupported format"


# Example usage
if __name__ == "__main__":
    # Create the APT simulation engine
    apt_sim = APTSimulationEngine()
    
    # List available threat actors
    actors = apt_sim.list_available_actors()
    print(f"Available threat actors: {len(actors)}")
    
    # Create a simulation for APT29 (Cozy Bear)
    target_env = {
        "name": "Example Corporation",
        "environment_type": "hybrid",
        "security_maturity": "medium",
        "security_controls": [
            "firewall",
            "antivirus",
            "email_filtering",
            "edr",
            "dlp"
        ]
    }
    
    simulation = apt_sim.create_simulation(
        actor_id="APT29",
        target_environment=target_env,
        campaign_duration_days=30,
        objectives=["data_exfiltration", "persistence"]
    )
    
    # Plan the attack campaign
    planned_simulation = apt_sim.plan_attack_campaign()
    
    # Execute the simulation
    executed_simulation = apt_sim.execute_simulation()
    
    # Generate a report
    report = apt_sim.generate_report()
    
    print(json.dumps(report["executive_summary"], indent=2))