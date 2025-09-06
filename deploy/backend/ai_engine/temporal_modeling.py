"""
Temporal Attack Modeling System

This module implements a system for multi-dimensional analysis of how security posture
evolves over time, with predictive breach modeling capabilities.
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import networkx as nx
from collections import defaultdict
import matplotlib.pyplot as plt
import random

try:
    from .predictive_discovery import PredictiveVulnerabilityDiscovery
except ImportError:
    print("Warning: Unable to import PredictiveVulnerabilityDiscovery. Some functionality may be limited.")


class TemporalAttackModeling:
    """
    A system that models how security posture and attack vectors evolve over time,
    providing predictive breach modeling and temporal vulnerability analysis.
    """

    def __init__(self):
        self.security_posture_history = []
        self.attack_vector_evolution = {}
        self.breach_predictions = []
        self.temporal_graph = nx.DiGraph()
        self.time_windows = ["daily", "weekly", "monthly", "quarterly", "yearly"]
        self.confidence_threshold = 0.6
        self.prediction_horizon_days = 90  # Default to 90-day prediction horizon
        
        # Initialize with some baseline security controls and their effectiveness
        self.initialize_security_controls()
        
        # Initialize with some known attack vector evolution patterns
        self.initialize_attack_vectors()
        
        # Try to initialize the predictive vulnerability discovery system
        try:
            self.pvd = PredictiveVulnerabilityDiscovery()
        except:
            self.pvd = None
            print("Warning: PredictiveVulnerabilityDiscovery not available.")
    
    def initialize_security_controls(self):
        """Initialize baseline security controls and their effectiveness."""
        self.security_controls = {
            "network": {
                "firewall": {"effectiveness": 0.8, "decay_rate": 0.05, "last_updated": datetime.now()},
                "ids_ips": {"effectiveness": 0.75, "decay_rate": 0.08, "last_updated": datetime.now()},
                "vpn": {"effectiveness": 0.7, "decay_rate": 0.03, "last_updated": datetime.now()},
                "network_segmentation": {"effectiveness": 0.85, "decay_rate": 0.02, "last_updated": datetime.now()}
            },
            "application": {
                "waf": {"effectiveness": 0.7, "decay_rate": 0.1, "last_updated": datetime.now()},
                "input_validation": {"effectiveness": 0.65, "decay_rate": 0.07, "last_updated": datetime.now()},
                "output_encoding": {"effectiveness": 0.6, "decay_rate": 0.06, "last_updated": datetime.now()},
                "api_gateway": {"effectiveness": 0.75, "decay_rate": 0.05, "last_updated": datetime.now()}
            },
            "endpoint": {
                "antivirus": {"effectiveness": 0.6, "decay_rate": 0.15, "last_updated": datetime.now()},
                "edr": {"effectiveness": 0.8, "decay_rate": 0.1, "last_updated": datetime.now()},
                "disk_encryption": {"effectiveness": 0.9, "decay_rate": 0.01, "last_updated": datetime.now()},
                "patch_management": {"effectiveness": 0.7, "decay_rate": 0.2, "last_updated": datetime.now()}
            },
            "identity": {
                "mfa": {"effectiveness": 0.85, "decay_rate": 0.03, "last_updated": datetime.now()},
                "sso": {"effectiveness": 0.75, "decay_rate": 0.04, "last_updated": datetime.now()},
                "pam": {"effectiveness": 0.8, "decay_rate": 0.05, "last_updated": datetime.now()},
                "rbac": {"effectiveness": 0.7, "decay_rate": 0.03, "last_updated": datetime.now()}
            },
            "data": {
                "dlp": {"effectiveness": 0.7, "decay_rate": 0.06, "last_updated": datetime.now()},
                "encryption_at_rest": {"effectiveness": 0.9, "decay_rate": 0.01, "last_updated": datetime.now()},
                "encryption_in_transit": {"effectiveness": 0.85, "decay_rate": 0.02, "last_updated": datetime.now()},
                "data_classification": {"effectiveness": 0.6, "decay_rate": 0.04, "last_updated": datetime.now()}
            }
        }
    
    def initialize_attack_vectors(self):
        """Initialize known attack vector evolution patterns."""
        self.attack_vectors = {
            "phishing": {
                "evolution_stages": [
                    {"name": "Basic Email Phishing", "effectiveness": 0.5, "year_observed": 2010},
                    {"name": "Spear Phishing", "effectiveness": 0.65, "year_observed": 2013},
                    {"name": "Business Email Compromise", "effectiveness": 0.75, "year_observed": 2016},
                    {"name": "AI-Generated Phishing", "effectiveness": 0.85, "year_observed": 2022}
                ],
                "predicted_next_stage": {
                    "name": "Context-Aware Adaptive Phishing",
                    "effectiveness": 0.9,
                    "estimated_year": 2024,
                    "confidence": 0.8
                }
            },
            "ransomware": {
                "evolution_stages": [
                    {"name": "File Encryption", "effectiveness": 0.6, "year_observed": 2013},
                    {"name": "Data Exfiltration + Encryption", "effectiveness": 0.75, "year_observed": 2019},
                    {"name": "Supply Chain Ransomware", "effectiveness": 0.85, "year_observed": 2021}
                ],
                "predicted_next_stage": {
                    "name": "AI-Orchestrated Ransomware",
                    "effectiveness": 0.9,
                    "estimated_year": 2024,
                    "confidence": 0.75
                }
            },
            "zero_day_exploitation": {
                "evolution_stages": [
                    {"name": "Targeted Zero-Day", "effectiveness": 0.7, "year_observed": 2010},
                    {"name": "Zero-Day Exploit Kits", "effectiveness": 0.8, "year_observed": 2015},
                    {"name": "Supply Chain Zero-Day", "effectiveness": 0.85, "year_observed": 2020}
                ],
                "predicted_next_stage": {
                    "name": "AI-Discovered Zero-Days",
                    "effectiveness": 0.95,
                    "estimated_year": 2025,
                    "confidence": 0.7
                }
            }
        }
        
        # Build initial temporal graph from attack vectors
        self._build_initial_temporal_graph()
    
    def _build_initial_temporal_graph(self):
        """Build the initial temporal graph from attack vectors and security controls."""
        # Add attack vector nodes
        for vector_type, vector_data in self.attack_vectors.items():
            for stage in vector_data["evolution_stages"]:
                node_id = f"{vector_type}_{stage['name']}"
                self.temporal_graph.add_node(
                    node_id,
                    type="attack_vector",
                    vector_type=vector_type,
                    name=stage["name"],
                    effectiveness=stage["effectiveness"],
                    year_observed=stage["year_observed"]
                )
                
                # Add temporal edges between evolution stages
                if vector_data["evolution_stages"].index(stage) > 0:
                    prev_stage = vector_data["evolution_stages"][vector_data["evolution_stages"].index(stage) - 1]
                    prev_node_id = f"{vector_type}_{prev_stage['name']}"
                    self.temporal_graph.add_edge(
                        prev_node_id,
                        node_id,
                        relationship="evolves_to",
                        time_delta=stage["year_observed"] - prev_stage["year_observed"]
                    )
            
            # Add predicted next stage
            next_stage = vector_data["predicted_next_stage"]
            next_node_id = f"{vector_type}_{next_stage['name']}"
            self.temporal_graph.add_node(
                next_node_id,
                type="predicted_attack_vector",
                vector_type=vector_type,
                name=next_stage["name"],
                effectiveness=next_stage["effectiveness"],
                estimated_year=next_stage["estimated_year"],
                confidence=next_stage["confidence"]
            )
            
            # Add edge from last known stage to predicted stage
            last_known_stage = vector_data["evolution_stages"][-1]
            last_known_node_id = f"{vector_type}_{last_known_stage['name']}"
            self.temporal_graph.add_edge(
                last_known_node_id,
                next_node_id,
                relationship="predicted_evolution",
                time_delta=next_stage["estimated_year"] - last_known_stage["year_observed"],
                confidence=next_stage["confidence"]
            )
        
        # Add security control nodes
        for control_category, controls in self.security_controls.items():
            for control_name, control_data in controls.items():
                node_id = f"{control_category}_{control_name}"
                self.temporal_graph.add_node(
                    node_id,
                    type="security_control",
                    category=control_category,
                    name=control_name,
                    effectiveness=control_data["effectiveness"],
                    decay_rate=control_data["decay_rate"],
                    last_updated=control_data["last_updated"]
                )
        
        # Add edges between attack vectors and security controls
        self._add_attack_defense_edges()
    
    def _add_attack_defense_edges(self):
        """Add edges between attack vectors and security controls."""
        # Define effectiveness of security controls against attack vectors
        effectiveness_matrix = {
            "phishing": {
                "network_ids_ips": 0.3,
                "endpoint_antivirus": 0.4,
                "endpoint_edr": 0.6,
                "identity_mfa": 0.8
            },
            "ransomware": {
                "endpoint_antivirus": 0.5,
                "endpoint_edr": 0.7,
                "data_backup": 0.9,
                "network_segmentation": 0.6
            },
            "zero_day_exploitation": {
                "network_ids_ips": 0.4,
                "application_waf": 0.5,
                "endpoint_edr": 0.6,
                "patch_management": 0.3  # Limited effectiveness against zero-days
            }
        }
        
        # Add edges based on effectiveness matrix
        for vector_type, controls in effectiveness_matrix.items():
            for stage in self.attack_vectors[vector_type]["evolution_stages"]:
                attack_node_id = f"{vector_type}_{stage['name']}"
                
                for control_id, effectiveness in controls.items():
                    if self.temporal_graph.has_node(control_id):
                        self.temporal_graph.add_edge(
                            control_id,
                            attack_node_id,
                            relationship="mitigates",
                            effectiveness=effectiveness
                        )
    
    def update_security_posture(self, date=None, security_updates=None):
        """
        Update the security posture based on changes to security controls.
        
        Args:
            date (datetime): The date of the security posture update
            security_updates (dict): Updates to security controls
        
        Returns:
            dict: Updated security posture snapshot
        """
        if date is None:
            date = datetime.now()
        
        # Apply security updates if provided
        if security_updates:
            for category, controls in security_updates.items():
                for control, updates in controls.items():
                    if category in self.security_controls and control in self.security_controls[category]:
                        for key, value in updates.items():
                            self.security_controls[category][control][key] = value
                        
                        # Update last_updated timestamp
                        self.security_controls[category][control]["last_updated"] = date
                        
                        # Update the corresponding node in the temporal graph
                        node_id = f"{category}_{control}"
                        if self.temporal_graph.has_node(node_id):
                            for key, value in updates.items():
                                self.temporal_graph.nodes[node_id][key] = value
                            self.temporal_graph.nodes[node_id]["last_updated"] = date
        
        # Calculate current effectiveness of all security controls
        # (accounting for decay since last update)
        current_posture = self._calculate_current_effectiveness(date)
        
        # Add this snapshot to the security posture history
        posture_snapshot = {
            "date": date,
            "overall_security_score": self._calculate_overall_security_score(current_posture),
            "security_controls": current_posture,
            "vulnerability_exposure": self._calculate_vulnerability_exposure(current_posture)
        }
        
        self.security_posture_history.append(posture_snapshot)
        
        # Update breach predictions based on new security posture
        self._update_breach_predictions(date)
        
        return posture_snapshot
    
    def _calculate_current_effectiveness(self, current_date):
        """
        Calculate current effectiveness of all security controls accounting for decay.
        
        Args:
            current_date (datetime): The current date for calculation
            
        Returns:
            dict: Current effectiveness of all security controls
        """
        current_posture = {}
        
        for category, controls in self.security_controls.items():
            current_posture[category] = {}
            
            for control, data in controls.items():
                # Calculate days since last update
                days_since_update = (current_date - data["last_updated"]).days
                
                # Apply decay formula: effectiveness * (1 - decay_rate)^days
                decayed_effectiveness = data["effectiveness"] * (1 - data["decay_rate"]) ** (days_since_update / 365)
                
                # Ensure effectiveness doesn't go below a minimum threshold
                decayed_effectiveness = max(0.1, decayed_effectiveness)
                
                current_posture[category][control] = {
                    "effectiveness": decayed_effectiveness,
                    "original_effectiveness": data["effectiveness"],
                    "decay_rate": data["decay_rate"],
                    "days_since_update": days_since_update
                }
                
                # Update the node in the temporal graph
                node_id = f"{category}_{control}"
                if self.temporal_graph.has_node(node_id):
                    self.temporal_graph.nodes[node_id]["current_effectiveness"] = decayed_effectiveness
                    self.temporal_graph.nodes[node_id]["days_since_update"] = days_since_update
        
        return current_posture
    
    def _calculate_overall_security_score(self, current_posture):
        """
        Calculate an overall security score based on the current security posture.
        
        Args:
            current_posture (dict): Current effectiveness of all security controls
            
        Returns:
            float: Overall security score between 0 and 1
        """
        # Weights for different security control categories
        category_weights = {
            "network": 0.2,
            "application": 0.25,
            "endpoint": 0.2,
            "identity": 0.2,
            "data": 0.15
        }
        
        weighted_scores = []
        
        for category, controls in current_posture.items():
            category_score = sum(control["effectiveness"] for control in controls.values()) / len(controls)
            weighted_scores.append(category_score * category_weights.get(category, 0.2))
        
        return sum(weighted_scores)
    
    def _calculate_vulnerability_exposure(self, current_posture):
        """
        Calculate vulnerability exposure based on current security posture.
        
        Args:
            current_posture (dict): Current effectiveness of all security controls
            
        Returns:
            dict: Vulnerability exposure metrics
        """
        # Calculate exposure to different attack vectors
        attack_vector_exposure = {}
        
        for vector_type, vector_data in self.attack_vectors.items():
            # Get the latest evolution stage
            latest_stage = vector_data["evolution_stages"][-1]
            attack_effectiveness = latest_stage["effectiveness"]
            
            # Calculate defense effectiveness against this attack vector
            relevant_controls = []
            
            for category, controls in current_posture.items():
                for control, data in controls.items():
                    node_id = f"{category}_{control}"
                    attack_node_id = f"{vector_type}_{latest_stage['name']}"
                    
                    # Check if there's a mitigation relationship in the graph
                    if (self.temporal_graph.has_edge(node_id, attack_node_id) and 
                        self.temporal_graph.edges[node_id, attack_node_id]["relationship"] == "mitigates"):
                        mitigation_effectiveness = self.temporal_graph.edges[node_id, attack_node_id]["effectiveness"]
                        control_effectiveness = data["effectiveness"]
                        relevant_controls.append(mitigation_effectiveness * control_effectiveness)
            
            # Calculate overall defense effectiveness (using diminishing returns formula)
            if relevant_controls:
                # Sort controls by effectiveness (descending)
                relevant_controls.sort(reverse=True)
                
                # Apply diminishing returns formula
                defense_effectiveness = relevant_controls[0]
                for i in range(1, len(relevant_controls)):
                    # Each additional control is less effective
                    defense_effectiveness += relevant_controls[i] * (1 - defense_effectiveness)
            else:
                defense_effectiveness = 0
            
            # Calculate exposure (attack effectiveness minus defense effectiveness)
            exposure = attack_effectiveness * (1 - defense_effectiveness)
            
            attack_vector_exposure[vector_type] = {
                "attack_effectiveness": attack_effectiveness,
                "defense_effectiveness": defense_effectiveness,
                "exposure": exposure
            }
        
        # Calculate overall vulnerability exposure
        overall_exposure = sum(data["exposure"] for data in attack_vector_exposure.values()) / len(attack_vector_exposure)
        
        return {
            "overall_exposure": overall_exposure,
            "attack_vector_exposure": attack_vector_exposure
        }
    
    def _update_breach_predictions(self, current_date):
        """
        Update breach predictions based on current security posture and attack vector evolution.
        
        Args:
            current_date (datetime): The current date
        """
        # Clear previous predictions
        self.breach_predictions = []
        
        # Get the latest security posture
        if not self.security_posture_history:
            return
        
        latest_posture = self.security_posture_history[-1]
        
        # For each attack vector, predict potential breaches
        for vector_type, exposure_data in latest_posture["vulnerability_exposure"]["attack_vector_exposure"].items():
            # Skip if exposure is below threshold
            if exposure_data["exposure"] < self.confidence_threshold:
                continue
            
            # Calculate breach probability based on exposure
            breach_probability = exposure_data["exposure"] ** 2  # Non-linear relationship
            
            # Estimate time to breach based on exposure and attack effectiveness
            days_to_breach = int(365 * (1 - breach_probability))
            predicted_breach_date = current_date + timedelta(days=days_to_breach)
            
            # Get the latest attack stage
            latest_stage = self.attack_vectors[vector_type]["evolution_stages"][-1]["name"]
            
            # Create breach prediction
            prediction = {
                "attack_vector": vector_type,
                "attack_stage": latest_stage,
                "breach_probability": breach_probability,
                "predicted_breach_date": predicted_breach_date,
                "confidence": breach_probability * 0.8,  # Slightly lower confidence than probability
                "potential_impact": self._estimate_breach_impact(vector_type, breach_probability),
                "recommended_mitigations": self._recommend_mitigations(vector_type)
            }
            
            self.breach_predictions.append(prediction)
        
        # Sort predictions by breach probability (descending)
        self.breach_predictions.sort(key=lambda x: x["breach_probability"], reverse=True)
    
    def _estimate_breach_impact(self, vector_type, breach_probability):
        """
        Estimate the potential impact of a breach.
        
        Args:
            vector_type (str): The type of attack vector
            breach_probability (float): The probability of a breach
            
        Returns:
            dict: Impact assessment
        """
        # Define base impact metrics for different attack vectors
        base_impacts = {
            "phishing": {
                "data_exposure": 0.6,
                "operational_disruption": 0.3,
                "financial_loss": 0.5,
                "reputational_damage": 0.7
            },
            "ransomware": {
                "data_exposure": 0.7,
                "operational_disruption": 0.9,
                "financial_loss": 0.8,
                "reputational_damage": 0.7
            },
            "zero_day_exploitation": {
                "data_exposure": 0.8,
                "operational_disruption": 0.7,
                "financial_loss": 0.6,
                "reputational_damage": 0.8
            }
        }
        
        # Get base impact for this vector type
        impact = base_impacts.get(vector_type, {
            "data_exposure": 0.5,
            "operational_disruption": 0.5,
            "financial_loss": 0.5,
            "reputational_damage": 0.5
        })
        
        # Scale impact by breach probability
        scaled_impact = {key: value * breach_probability for key, value in impact.items()}
        
        # Calculate overall impact score
        overall_impact = sum(scaled_impact.values()) / len(scaled_impact)
        
        # Determine impact level
        if overall_impact >= 0.7:
            impact_level = "critical"
        elif overall_impact >= 0.5:
            impact_level = "high"
        elif overall_impact >= 0.3:
            impact_level = "medium"
        else:
            impact_level = "low"
        
        return {
            "metrics": scaled_impact,
            "overall_impact": overall_impact,
            "impact_level": impact_level
        }
    
    def _recommend_mitigations(self, vector_type):
        """
        Recommend mitigations for a specific attack vector.
        
        Args:
            vector_type (str): The type of attack vector
            
        Returns:
            list: Recommended mitigations
        """
        # Define mitigation recommendations for different attack vectors
        mitigations = {
            "phishing": [
                {
                    "control": "Security Awareness Training",
                    "effectiveness": 0.7,
                    "implementation_time": "1-2 weeks",
                    "description": "Regular phishing simulation exercises and security awareness training."
                },
                {
                    "control": "Email Filtering",
                    "effectiveness": 0.6,
                    "implementation_time": "1 week",
                    "description": "Advanced email filtering with AI-powered phishing detection."
                },
                {
                    "control": "Multi-Factor Authentication",
                    "effectiveness": 0.8,
                    "implementation_time": "2-4 weeks",
                    "description": "Implement MFA for all email and critical system access."
                }
            ],
            "ransomware": [
                {
                    "control": "Regular Backups",
                    "effectiveness": 0.9,
                    "implementation_time": "1-2 weeks",
                    "description": "Implement 3-2-1 backup strategy with offline backups."
                },
                {
                    "control": "Network Segmentation",
                    "effectiveness": 0.7,
                    "implementation_time": "1-3 months",
                    "description": "Segment networks to limit lateral movement."
                },
                {
                    "control": "Endpoint Detection and Response",
                    "effectiveness": 0.8,
                    "implementation_time": "2-4 weeks",
                    "description": "Deploy EDR solutions with behavioral analysis capabilities."
                }
            ],
            "zero_day_exploitation": [
                {
                    "control": "Defense in Depth",
                    "effectiveness": 0.7,
                    "implementation_time": "3-6 months",
                    "description": "Implement multiple layers of security controls."
                },
                {
                    "control": "Threat Hunting",
                    "effectiveness": 0.6,
                    "implementation_time": "1-2 months",
                    "description": "Proactive threat hunting to detect unusual activities."
                },
                {
                    "control": "Zero Trust Architecture",
                    "effectiveness": 0.8,
                    "implementation_time": "6-12 months",
                    "description": "Implement zero trust principles for all system access."
                }
            ]
        }
        
        return mitigations.get(vector_type, [
            {
                "control": "Security Assessment",
                "effectiveness": 0.6,
                "implementation_time": "2-4 weeks",
                "description": "Conduct a comprehensive security assessment to identify vulnerabilities."
            }
        ])
    
    def analyze_security_posture_trend(self, time_window="monthly"):
        """
        Analyze the trend in security posture over time.
        
        Args:
            time_window (str): Time window for analysis (daily, weekly, monthly, quarterly, yearly)
            
        Returns:
            dict: Security posture trend analysis
        """
        if not self.security_posture_history or len(self.security_posture_history) < 2:
            return {"error": "Insufficient security posture history for trend analysis."}
        
        # Convert security posture history to DataFrame for easier analysis
        posture_data = []
        for snapshot in self.security_posture_history:
            data = {
                "date": snapshot["date"],
                "overall_security_score": snapshot["overall_security_score"],
                "overall_exposure": snapshot["vulnerability_exposure"]["overall_exposure"]
            }
            
            # Add category-level security scores
            for category, controls in snapshot["security_controls"].items():
                category_score = sum(control["effectiveness"] for control in controls.values()) / len(controls)
                data[f"{category}_score"] = category_score
            
            # Add attack vector exposures
            for vector, exposure in snapshot["vulnerability_exposure"]["attack_vector_exposure"].items():
                data[f"{vector}_exposure"] = exposure["exposure"]
            
            posture_data.append(data)
        
        df = pd.DataFrame(posture_data)
        
        # Resample data based on time window
        if time_window == "daily":
            resampled = df.set_index("date").resample("D").mean()
        elif time_window == "weekly":
            resampled = df.set_index("date").resample("W").mean()
        elif time_window == "monthly":
            resampled = df.set_index("date").resample("M").mean()
        elif time_window == "quarterly":
            resampled = df.set_index("date").resample("Q").mean()
        elif time_window == "yearly":
            resampled = df.set_index("date").resample("Y").mean()
        else:
            resampled = df.set_index("date").resample("M").mean()  # Default to monthly
        
        # Calculate trends
        trends = {}
        
        # Overall security score trend
        if len(resampled) >= 2:
            first_score = resampled["overall_security_score"].iloc[0]
            last_score = resampled["overall_security_score"].iloc[-1]
            score_change = last_score - first_score
            score_change_pct = (score_change / first_score) * 100 if first_score > 0 else 0
            
            trends["overall_security_score"] = {
                "first_value": first_score,
                "last_value": last_score,
                "absolute_change": score_change,
                "percentage_change": score_change_pct,
                "trend_direction": "improving" if score_change > 0 else "declining" if score_change < 0 else "stable"
            }
            
            # Overall exposure trend
            first_exposure = resampled["overall_exposure"].iloc[0]
            last_exposure = resampled["overall_exposure"].iloc[-1]
            exposure_change = last_exposure - first_exposure
            exposure_change_pct = (exposure_change / first_exposure) * 100 if first_exposure > 0 else 0
            
            trends["overall_exposure"] = {
                "first_value": first_exposure,
                "last_value": last_exposure,
                "absolute_change": exposure_change,
                "percentage_change": exposure_change_pct,
                "trend_direction": "improving" if exposure_change < 0 else "worsening" if exposure_change > 0 else "stable"
            }
            
            # Category-level trends
            for category in ["network", "application", "endpoint", "identity", "data"]:
                col = f"{category}_score"
                if col in resampled.columns:
                    first_val = resampled[col].iloc[0]
                    last_val = resampled[col].iloc[-1]
                    change = last_val - first_val
                    change_pct = (change / first_val) * 100 if first_val > 0 else 0
                    
                    trends[f"{category}_score"] = {
                        "first_value": first_val,
                        "last_value": last_val,
                        "absolute_change": change,
                        "percentage_change": change_pct,
                        "trend_direction": "improving" if change > 0 else "declining" if change < 0 else "stable"
                    }
            
            # Attack vector exposure trends
            for vector in ["phishing", "ransomware", "zero_day_exploitation"]:
                col = f"{vector}_exposure"
                if col in resampled.columns:
                    first_val = resampled[col].iloc[0]
                    last_val = resampled[col].iloc[-1]
                    change = last_val - first_val
                    change_pct = (change / first_val) * 100 if first_val > 0 else 0
                    
                    trends[f"{vector}_exposure"] = {
                        "first_value": first_val,
                        "last_value": last_val,
                        "absolute_change": change,
                        "percentage_change": change_pct,
                        "trend_direction": "improving" if change < 0 else "worsening" if change > 0 else "stable"
                    }
        
        return {
            "time_window": time_window,
            "data_points": len(resampled),
            "start_date": resampled.index[0].strftime("%Y-%m-%d") if len(resampled) > 0 else None,
            "end_date": resampled.index[-1].strftime("%Y-%m-%d") if len(resampled) > 0 else None,
            "trends": trends,
            "time_series_data": resampled.reset_index().to_dict(orient="records") if not resampled.empty else []
        }
    
    def predict_security_posture(self, days_ahead=90, num_simulations=100):
        """
        Predict future security posture using Monte Carlo simulation.
        
        Args:
            days_ahead (int): Number of days to predict ahead
            num_simulations (int): Number of Monte Carlo simulations to run
            
        Returns:
            dict: Predicted security posture with confidence intervals
        """
        if not self.security_posture_history:
            return {"error": "Insufficient security posture history for prediction."}
        
        # Get the latest security posture
        latest_posture = self.security_posture_history[-1]
        latest_date = latest_posture["date"]
        
        # Initialize simulation results
        simulation_results = {
            "overall_security_score": [],
            "overall_exposure": [],
            "attack_vector_exposure": defaultdict(list)
        }
        
        # Run Monte Carlo simulations
        for _ in range(num_simulations):
            # Start with the latest security posture
            current_posture = latest_posture.copy()
            current_date = latest_date
            
            # Simulate security posture evolution over time
            for day in range(days_ahead):
                current_date = current_date + timedelta(days=1)
                
                # Simulate random security events and control updates
                security_updates = self._simulate_security_updates(current_date)
                
                # Update security posture
                current_posture = self.update_security_posture(current_date, security_updates)
                
                # If this is the target prediction day, record the results
                if day == days_ahead - 1:
                    simulation_results["overall_security_score"].append(current_posture["overall_security_score"])
                    simulation_results["overall_exposure"].append(current_posture["vulnerability_exposure"]["overall_exposure"])
                    
                    for vector, exposure in current_posture["vulnerability_exposure"]["attack_vector_exposure"].items():
                        simulation_results["attack_vector_exposure"][vector].append(exposure["exposure"])
        
        # Calculate prediction statistics
        prediction_stats = {
            "prediction_date": latest_date + timedelta(days=days_ahead),
            "overall_security_score": self._calculate_prediction_stats(simulation_results["overall_security_score"]),
            "overall_exposure": self._calculate_prediction_stats(simulation_results["overall_exposure"]),
            "attack_vector_exposure": {}
        }
        
        for vector, exposures in simulation_results["attack_vector_exposure"].items():
            prediction_stats["attack_vector_exposure"][vector] = self._calculate_prediction_stats(exposures)
        
        return prediction_stats
    
    def _simulate_security_updates(self, current_date):
        """
        Simulate random security updates for Monte Carlo simulation.
        
        Args:
            current_date (datetime): The current simulation date
            
        Returns:
            dict: Simulated security updates
        """
        security_updates = {}
        
        # Simulate random security control updates
        # (e.g., patching, configuration changes, new controls)
        if random.random() < 0.1:  # 10% chance of a security update on any given day
            # Select a random security control category
            category = random.choice(list(self.security_controls.keys()))
            security_updates[category] = {}
            
            # Select a random control in that category
            control = random.choice(list(self.security_controls[category].keys()))
            security_updates[category][control] = {}
            
            # Simulate an improvement in effectiveness
            current_effectiveness = self.security_controls[category][control]["effectiveness"]
            improvement = random.uniform(0.05, 0.2)  # 5-20% improvement
            new_effectiveness = min(0.95, current_effectiveness + improvement)
            
            security_updates[category][control]["effectiveness"] = new_effectiveness
            security_updates[category][control]["last_updated"] = current_date
        
        # Simulate random security control degradation
        # (e.g., new vulnerabilities, configuration drift)
        if random.random() < 0.05:  # 5% chance of a security degradation on any given day
            # Select a random security control category
            category = random.choice(list(self.security_controls.keys()))
            
            if category not in security_updates:
                security_updates[category] = {}
            
            # Select a random control in that category
            control = random.choice(list(self.security_controls[category].keys()))
            
            if control not in security_updates[category]:
                security_updates[category][control] = {}
            
            # Simulate a degradation in effectiveness
            current_effectiveness = self.security_controls[category][control]["effectiveness"]
            degradation = random.uniform(0.05, 0.15)  # 5-15% degradation
            new_effectiveness = max(0.1, current_effectiveness - degradation)
            
            security_updates[category][control]["effectiveness"] = new_effectiveness
            security_updates[category][control]["last_updated"] = current_date
        
        return security_updates
    
    def _calculate_prediction_stats(self, values):
        """
        Calculate prediction statistics from simulation results.
        
        Args:
            values (list): List of simulated values
            
        Returns:
            dict: Prediction statistics
        """
        values = np.array(values)
        
        return {
            "mean": float(np.mean(values)),
            "median": float(np.median(values)),
            "std_dev": float(np.std(values)),
            "min": float(np.min(values)),
            "max": float(np.max(values)),
            "percentiles": {
                "5": float(np.percentile(values, 5)),
                "25": float(np.percentile(values, 25)),
                "75": float(np.percentile(values, 75)),
                "95": float(np.percentile(values, 95))
            }
        }
    
    def identify_critical_time_points(self):
        """
        Identify critical time points where security posture changes significantly.
        
        Returns:
            list: Critical time points with significant security posture changes
        """
        if len(self.security_posture_history) < 3:
            return []
        
        critical_points = []
        
        # Convert security posture history to DataFrame
        posture_data = []
        for snapshot in self.security_posture_history:
            data = {
                "date": snapshot["date"],
                "overall_security_score": snapshot["overall_security_score"],
                "overall_exposure": snapshot["vulnerability_exposure"]["overall_exposure"]
            }
            posture_data.append(data)
        
        df = pd.DataFrame(posture_data)
        
        # Calculate rolling mean and standard deviation
        window_size = min(5, len(df) // 2) if len(df) > 10 else 3
        df["score_rolling_mean"] = df["overall_security_score"].rolling(window=window_size).mean()
        df["score_rolling_std"] = df["overall_security_score"].rolling(window=window_size).std()
        df["exposure_rolling_mean"] = df["overall_exposure"].rolling(window=window_size).mean()
        df["exposure_rolling_std"] = df["overall_exposure"].rolling(window=window_size).std()
        
        # Identify points where the score or exposure deviates significantly from the rolling mean
        for i in range(window_size, len(df)):
            score_z_score = abs(df["overall_security_score"].iloc[i] - df["score_rolling_mean"].iloc[i]) / df["score_rolling_std"].iloc[i] if df["score_rolling_std"].iloc[i] > 0 else 0
            exposure_z_score = abs(df["overall_exposure"].iloc[i] - df["exposure_rolling_mean"].iloc[i]) / df["exposure_rolling_std"].iloc[i] if df["exposure_rolling_std"].iloc[i] > 0 else 0
            
            if score_z_score > 2 or exposure_z_score > 2:  # More than 2 standard deviations
                critical_points.append({
                    "date": df["date"].iloc[i],
                    "overall_security_score": df["overall_security_score"].iloc[i],
                    "overall_exposure": df["overall_exposure"].iloc[i],
                    "score_z_score": score_z_score,
                    "exposure_z_score": exposure_z_score,
                    "significance": "high" if max(score_z_score, exposure_z_score) > 3 else "medium"
                })
        
        return critical_points
    
    def visualize_temporal_security_posture(self, output_file=None):
        """
        Visualize the temporal security posture.
        
        Args:
            output_file (str): Path to save the visualization (if None, display interactively)
            
        Returns:
            matplotlib.figure.Figure: The visualization figure
        """
        if not self.security_posture_history:
            return None
        
        # Convert security posture history to DataFrame
        posture_data = []
        for snapshot in self.security_posture_history:
            data = {
                "date": snapshot["date"],
                "overall_security_score": snapshot["overall_security_score"],
                "overall_exposure": snapshot["vulnerability_exposure"]["overall_exposure"]
            }
            
            # Add category-level security scores
            for category, controls in snapshot["security_controls"].items():
                category_score = sum(control["effectiveness"] for control in controls.values()) / len(controls)
                data[f"{category}_score"] = category_score
            
            # Add attack vector exposures
            for vector, exposure in snapshot["vulnerability_exposure"]["attack_vector_exposure"].items():
                data[f"{vector}_exposure"] = exposure["exposure"]
            
            posture_data.append(data)
        
        df = pd.DataFrame(posture_data)
        
        # Create visualization
        fig, axes = plt.subplots(2, 1, figsize=(12, 10), sharex=True)
        
        # Plot overall security score
        df.plot(x="date", y="overall_security_score", ax=axes[0], color="green", marker="o")
        axes[0].set_title("Temporal Security Posture")
        axes[0].set_ylabel("Security Score")
        axes[0].set_ylim(0, 1)
        axes[0].grid(True)
        
        # Plot overall exposure
        df.plot(x="date", y="overall_exposure", ax=axes[1], color="red", marker="o")
        axes[1].set_ylabel("Vulnerability Exposure")
        axes[1].set_ylim(0, 1)
        axes[1].grid(True)
        
        # Add breach predictions if available
        if self.breach_predictions:
            for prediction in self.breach_predictions:
                breach_date = prediction["predicted_breach_date"]
                if breach_date > df["date"].min() and breach_date < df["date"].max() + timedelta(days=30):
                    axes[1].axvline(x=breach_date, color="darkred", linestyle="--", alpha=0.7)
                    axes[1].text(breach_date, 0.9, f"{prediction['attack_vector']} breach", 
                                rotation=90, verticalalignment="top")
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
        
        return fig
    
    def export_results(self, format="json"):
        """Export temporal modeling results in the specified format."""
        if format == "json":
            return json.dumps({
                "security_posture_history": self.security_posture_history,
                "breach_predictions": self.breach_predictions,
                "attack_vectors": self.attack_vectors,
                "security_controls": self.security_controls
            }, default=str, indent=2)
        else:
            # Could implement other formats like CSV, HTML, etc.
            return "Unsupported format"


# Example usage
if __name__ == "__main__":
    # Create the temporal attack modeling system
    tam = TemporalAttackModeling()
    
    # Simulate security posture over time
    start_date = datetime(2023, 1, 1)
    
    # Initial security posture
    tam.update_security_posture(start_date)
    
    # Simulate security posture changes over 6 months
    for month in range(1, 7):
        current_date = start_date + timedelta(days=30 * month)
        
        # Simulate some security updates
        security_updates = {
            "network": {
                "firewall": {"effectiveness": 0.85}
            },
            "endpoint": {
                "edr": {"effectiveness": 0.9}
            }
        }
        
        tam.update_security_posture(current_date, security_updates)
    
    # Analyze security posture trend
    trend_analysis = tam.analyze_security_posture_trend()
    print(json.dumps(trend_analysis, indent=2, default=str))
    
    # Predict future security posture
    prediction = tam.predict_security_posture()
    print(json.dumps(prediction, indent=2, default=str))
    
    # Identify critical time points
    critical_points = tam.identify_critical_time_points()
    print(json.dumps(critical_points, indent=2, default=str))
    
    # Visualize temporal security posture
    tam.visualize_temporal_security_posture("temporal_security_posture.png")