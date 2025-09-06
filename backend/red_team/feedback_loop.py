#!/usr/bin/env python3

"""
Feedback Loop System for Red Team Automation

This module implements a comprehensive feedback loop system that analyzes
the results of automated red team scenarios, generates insights, and
improves future attack simulations.
"""

import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import KMeans

logger = logging.getLogger(__name__)


class FeedbackAnalyzer:
    """Analyzes the results of red team scenarios and generates insights"""
    
    def __init__(self):
        self.scenario_results = []
        self.success_metrics = {}
        self.vulnerability_trends = {}
        self.target_susceptibility = {}
        
    def add_scenario_result(self, scenario_result: Dict) -> None:
        """Add a new scenario result to the analyzer"""
        # Add timestamp if not present
        if "timestamp" not in scenario_result:
            scenario_result["timestamp"] = datetime.now().isoformat()
            
        self.scenario_results.append(scenario_result)
        
        # Update metrics based on the new result
        self._update_success_metrics(scenario_result)
        self._update_vulnerability_trends(scenario_result)
        self._update_target_susceptibility(scenario_result)
        
    def _update_success_metrics(self, result: Dict) -> None:
        """Update success metrics based on scenario result"""
        scenario_type = result.get("scenario_type")
        if not scenario_type:
            return
            
        if scenario_type not in self.success_metrics:
            self.success_metrics[scenario_type] = {
                "total": 0,
                "successful": 0,
                "success_rate": 0.0,
                "trend": []
            }
            
        metrics = self.success_metrics[scenario_type]
        metrics["total"] += 1
        
        if result.get("success", False):
            metrics["successful"] += 1
            
        metrics["success_rate"] = metrics["successful"] / metrics["total"]
        metrics["trend"].append({
            "timestamp": result.get("timestamp"),
            "success": result.get("success", False)
        })
        
    def _update_vulnerability_trends(self, result: Dict) -> None:
        """Update vulnerability trends based on scenario result"""
        # Handle network penetration results
        if result.get("scenario_type") == "network_penetration":
            for vuln in result.get("vulnerable_services", []):
                vuln_type = vuln.get("vulnerability")
                if not vuln_type:
                    continue
                    
                if vuln_type not in self.vulnerability_trends:
                    self.vulnerability_trends[vuln_type] = {
                        "count": 0,
                        "severity_distribution": {},
                        "exploitation_success": 0,
                        "exploitation_attempts": 0
                    }
                    
                self.vulnerability_trends[vuln_type]["count"] += 1
                
                severity = vuln.get("severity")
                if severity:
                    if severity not in self.vulnerability_trends[vuln_type]["severity_distribution"]:
                        self.vulnerability_trends[vuln_type]["severity_distribution"][severity] = 0
                    self.vulnerability_trends[vuln_type]["severity_distribution"][severity] += 1
                
                # Check if this vulnerability was exploited
                for exploit in result.get("exploitation_results", []):
                    if exploit.get("vulnerability") == vuln:
                        self.vulnerability_trends[vuln_type]["exploitation_attempts"] += 1
                        if exploit.get("success", False):
                            self.vulnerability_trends[vuln_type]["exploitation_success"] += 1
        
        # Handle web application results
        elif result.get("scenario_type") == "web_application":
            for vuln in result.get("vulnerabilities", []):
                vuln_type = vuln.get("type")
                if not vuln_type:
                    continue
                    
                if vuln_type not in self.vulnerability_trends:
                    self.vulnerability_trends[vuln_type] = {
                        "count": 0,
                        "severity_distribution": {},
                        "exploitation_success": 0,
                        "exploitation_attempts": 0
                    }
                    
                self.vulnerability_trends[vuln_type]["count"] += 1
                
                severity = vuln.get("severity")
                if severity:
                    if severity not in self.vulnerability_trends[vuln_type]["severity_distribution"]:
                        self.vulnerability_trends[vuln_type]["severity_distribution"][severity] = 0
                    self.vulnerability_trends[vuln_type]["severity_distribution"][severity] += 1
                
                # Check if this vulnerability was exploited
                for exploit in result.get("exploitation_results", []):
                    if exploit.get("vulnerability") == vuln:
                        self.vulnerability_trends[vuln_type]["exploitation_attempts"] += 1
                        if exploit.get("success", False):
                            self.vulnerability_trends[vuln_type]["exploitation_success"] += 1
    
    def _update_target_susceptibility(self, result: Dict) -> None:
        """Update target susceptibility based on scenario result"""
        # Handle social engineering results
        if result.get("scenario_type") == "social_engineering":
            campaign_results = result.get("campaign_results", {})
            department_breakdown = campaign_results.get("department_breakdown", {})
            
            for dept, data in department_breakdown.items():
                if dept not in self.target_susceptibility:
                    self.target_susceptibility[dept] = {
                        "campaigns": 0,
                        "susceptibility_sum": 0.0,
                        "average_susceptibility": 0.0,
                        "trend": []
                    }
                
                susceptibility_rate = data.get("susceptibility_rate", 0.0)
                self.target_susceptibility[dept]["campaigns"] += 1
                self.target_susceptibility[dept]["susceptibility_sum"] += susceptibility_rate
                self.target_susceptibility[dept]["average_susceptibility"] = (
                    self.target_susceptibility[dept]["susceptibility_sum"] / 
                    self.target_susceptibility[dept]["campaigns"]
                )
                
                self.target_susceptibility[dept]["trend"].append({
                    "timestamp": result.get("timestamp"),
                    "susceptibility_rate": susceptibility_rate
                })
    
    def get_success_metrics(self) -> Dict:
        """Get the current success metrics"""
        return self.success_metrics
    
    def get_vulnerability_trends(self) -> Dict:
        """Get the current vulnerability trends"""
        return self.vulnerability_trends
    
    def get_target_susceptibility(self) -> Dict:
        """Get the current target susceptibility data"""
        return self.target_susceptibility
    
    def generate_insights(self) -> Dict:
        """Generate insights from the collected data"""
        insights = {
            "most_successful_scenarios": self._get_most_successful_scenarios(),
            "most_common_vulnerabilities": self._get_most_common_vulnerabilities(),
            "most_susceptible_departments": self._get_most_susceptible_departments(),
            "trend_analysis": self._analyze_trends(),
            "recommendations": self._generate_recommendations()
        }
        
        return insights
    
    def _get_most_successful_scenarios(self) -> List[Dict]:
        """Get the most successful scenario types"""
        scenario_success = []
        
        for scenario_type, metrics in self.success_metrics.items():
            if metrics["total"] >= 3:  # Only consider scenario types with at least 3 runs
                scenario_success.append({
                    "scenario_type": scenario_type,
                    "success_rate": metrics["success_rate"],
                    "total_runs": metrics["total"]
                })
        
        # Sort by success rate (descending)
        scenario_success.sort(key=lambda x: x["success_rate"], reverse=True)
        
        return scenario_success[:5]  # Return top 5
    
    def _get_most_common_vulnerabilities(self) -> List[Dict]:
        """Get the most commonly found vulnerabilities"""
        vulnerabilities = []
        
        for vuln_type, data in self.vulnerability_trends.items():
            exploitation_rate = 0.0
            if data["exploitation_attempts"] > 0:
                exploitation_rate = data["exploitation_success"] / data["exploitation_attempts"]
                
            vulnerabilities.append({
                "vulnerability_type": vuln_type,
                "count": data["count"],
                "exploitation_rate": exploitation_rate,
                "severity_distribution": data["severity_distribution"]
            })
        
        # Sort by count (descending)
        vulnerabilities.sort(key=lambda x: x["count"], reverse=True)
        
        return vulnerabilities[:10]  # Return top 10
    
    def _get_most_susceptible_departments(self) -> List[Dict]:
        """Get the most susceptible departments"""
        departments = []
        
        for dept, data in self.target_susceptibility.items():
            if data["campaigns"] >= 2:  # Only consider departments with at least 2 campaigns
                departments.append({
                    "department": dept,
                    "average_susceptibility": data["average_susceptibility"],
                    "campaigns": data["campaigns"]
                })
        
        # Sort by average susceptibility (descending)
        departments.sort(key=lambda x: x["average_susceptibility"], reverse=True)
        
        return departments
    
    def _analyze_trends(self) -> Dict:
        """Analyze trends in the data"""
        trends = {
            "success_rate_trend": self._analyze_success_rate_trend(),
            "vulnerability_discovery_trend": self._analyze_vulnerability_discovery_trend(),
            "susceptibility_trend": self._analyze_susceptibility_trend()
        }
        
        return trends
    
    def _analyze_success_rate_trend(self) -> Dict:
        """Analyze the trend in scenario success rates"""
        # Group results by week
        weekly_success = {}
        
        for result in self.scenario_results:
            timestamp = result.get("timestamp")
            if not timestamp:
                continue
                
            try:
                dt = datetime.fromisoformat(timestamp)
                week_key = dt.strftime("%Y-%U")  # Year and week number
                
                if week_key not in weekly_success:
                    weekly_success[week_key] = {
                        "total": 0,
                        "successful": 0,
                        "week_start": (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")
                    }
                    
                weekly_success[week_key]["total"] += 1
                if result.get("success", False):
                    weekly_success[week_key]["successful"] += 1
            except (ValueError, TypeError):
                continue
        
        # Calculate success rates and format for output
        trend_data = []
        for week_key, data in sorted(weekly_success.items()):
            success_rate = 0.0
            if data["total"] > 0:
                success_rate = data["successful"] / data["total"]
                
            trend_data.append({
                "week": week_key,
                "week_start": data["week_start"],
                "success_rate": success_rate,
                "total_scenarios": data["total"]
            })
        
        # Calculate trend direction
        trend_direction = "stable"
        if len(trend_data) >= 2:
            first_half = trend_data[:len(trend_data)//2]
            second_half = trend_data[len(trend_data)//2:]
            
            first_half_avg = sum(d["success_rate"] for d in first_half) / len(first_half) if first_half else 0
            second_half_avg = sum(d["success_rate"] for d in second_half) / len(second_half) if second_half else 0
            
            if second_half_avg > first_half_avg * 1.1:  # 10% increase
                trend_direction = "increasing"
            elif second_half_avg < first_half_avg * 0.9:  # 10% decrease
                trend_direction = "decreasing"
        
        return {
            "data": trend_data,
            "direction": trend_direction
        }
    
    def _analyze_vulnerability_discovery_trend(self) -> Dict:
        """Analyze the trend in vulnerability discoveries"""
        # Group vulnerabilities by week
        weekly_vulnerabilities = {}
        
        for result in self.scenario_results:
            timestamp = result.get("timestamp")
            if not timestamp:
                continue
                
            try:
                dt = datetime.fromisoformat(timestamp)
                week_key = dt.strftime("%Y-%U")  # Year and week number
                
                if week_key not in weekly_vulnerabilities:
                    weekly_vulnerabilities[week_key] = {
                        "count": 0,
                        "by_severity": {
                            "Critical": 0,
                            "High": 0,
                            "Medium": 0,
                            "Low": 0
                        },
                        "week_start": (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")
                    }
                
                # Count vulnerabilities from network penetration scenarios
                if result.get("scenario_type") == "network_penetration":
                    for vuln in result.get("vulnerable_services", []):
                        weekly_vulnerabilities[week_key]["count"] += 1
                        severity = vuln.get("severity", "Medium")
                        if severity in weekly_vulnerabilities[week_key]["by_severity"]:
                            weekly_vulnerabilities[week_key]["by_severity"][severity] += 1
                
                # Count vulnerabilities from web application scenarios
                elif result.get("scenario_type") == "web_application":
                    for vuln in result.get("vulnerabilities", []):
                        weekly_vulnerabilities[week_key]["count"] += 1
                        severity = vuln.get("severity", "Medium")
                        if severity in weekly_vulnerabilities[week_key]["by_severity"]:
                            weekly_vulnerabilities[week_key]["by_severity"][severity] += 1
            except (ValueError, TypeError):
                continue
        
        # Format for output
        trend_data = []
        for week_key, data in sorted(weekly_vulnerabilities.items()):
            trend_data.append({
                "week": week_key,
                "week_start": data["week_start"],
                "total_vulnerabilities": data["count"],
                "by_severity": data["by_severity"]
            })
        
        # Calculate trend direction for critical and high vulnerabilities
        trend_direction = "stable"
        if len(trend_data) >= 2:
            first_half = trend_data[:len(trend_data)//2]
            second_half = trend_data[len(trend_data)//2:]
            
            first_half_severe = sum(d["by_severity"]["Critical"] + d["by_severity"]["High"] for d in first_half) / len(first_half) if first_half else 0
            second_half_severe = sum(d["by_severity"]["Critical"] + d["by_severity"]["High"] for d in second_half) / len(second_half) if second_half else 0
            
            if second_half_severe > first_half_severe * 1.1:  # 10% increase
                trend_direction = "increasing"
            elif second_half_severe < first_half_severe * 0.9:  # 10% decrease
                trend_direction = "decreasing"
        
        return {
            "data": trend_data,
            "direction": trend_direction
        }
    
    def _analyze_susceptibility_trend(self) -> Dict:
        """Analyze the trend in target susceptibility"""
        # Prepare department trends
        department_trends = {}
        
        for dept, data in self.target_susceptibility.items():
            if len(data["trend"]) < 2:  # Need at least 2 data points for a trend
                continue
                
            # Sort trend data by timestamp
            sorted_trend = sorted(data["trend"], key=lambda x: x.get("timestamp", ""))
            
            # Calculate trend direction
            first_half = sorted_trend[:len(sorted_trend)//2]
            second_half = sorted_trend[len(sorted_trend)//2:]
            
            first_half_avg = sum(d["susceptibility_rate"] for d in first_half) / len(first_half)
            second_half_avg = sum(d["susceptibility_rate"] for d in second_half) / len(second_half)
            
            trend_direction = "stable"
            if second_half_avg > first_half_avg * 1.1:  # 10% increase
                trend_direction = "increasing"
            elif second_half_avg < first_half_avg * 0.9:  # 10% decrease
                trend_direction = "decreasing"
                
            department_trends[dept] = {
                "average_susceptibility": data["average_susceptibility"],
                "trend_direction": trend_direction,
                "data_points": len(data["trend"])
            }
        
        return department_trends
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate recommendations based on the analysis"""
        recommendations = []
        
        # Recommendation based on most common vulnerabilities
        common_vulns = self._get_most_common_vulnerabilities()
        if common_vulns:
            top_vuln = common_vulns[0]
            recommendations.append({
                "type": "vulnerability_remediation",
                "priority": "high" if top_vuln.get("count", 0) > 5 else "medium",
                "description": f"Focus on remediating {top_vuln.get('vulnerability_type')} vulnerabilities, which were found {top_vuln.get('count')} times",
                "details": {
                    "vulnerability_type": top_vuln.get("vulnerability_type"),
                    "count": top_vuln.get("count"),
                    "exploitation_rate": top_vuln.get("exploitation_rate")
                }
            })
        
        # Recommendation based on most susceptible departments
        susceptible_depts = self._get_most_susceptible_departments()
        if susceptible_depts:
            top_dept = susceptible_depts[0]
            if top_dept.get("average_susceptibility", 0) > 0.3:  # Only recommend if susceptibility > 30%
                recommendations.append({
                    "type": "security_awareness",
                    "priority": "high" if top_dept.get("average_susceptibility", 0) > 0.5 else "medium",
                    "description": f"Conduct targeted security awareness training for the {top_dept.get('department')} department",
                    "details": {
                        "department": top_dept.get("department"),
                        "susceptibility_rate": top_dept.get("average_susceptibility"),
                        "campaigns": top_dept.get("campaigns")
                    }
                })
        
        # Recommendation based on success rate trends
        success_trends = self._analyze_success_rate_trend()
        if success_trends.get("direction") == "increasing":
            recommendations.append({
                "type": "security_posture",
                "priority": "high",
                "description": "Red team success rate is increasing over time, indicating potential degradation in security posture",
                "details": {
                    "trend_direction": success_trends.get("direction"),
                    "recent_success_rate": success_trends.get("data", [{}])[-1].get("success_rate", 0) if success_trends.get("data") else 0
                }
            })
        
        # Recommendation for scenario diversity if needed
        scenario_types = set(result.get("scenario_type") for result in self.scenario_results if result.get("scenario_type"))
        if len(scenario_types) < 3:
            recommendations.append({
                "type": "scenario_diversity",
                "priority": "medium",
                "description": "Increase the diversity of attack scenarios to provide more comprehensive security testing",
                "details": {
                    "current_scenario_types": list(scenario_types),
                    "recommended_additions": list(set(["network_penetration", "web_application", "social_engineering"]) - scenario_types)
                }
            })
        
        return recommendations
    
    def export_data(self, format: str = "json") -> Any:
        """Export the collected data in the specified format"""
        if format.lower() == "json":
            return json.dumps({
                "scenario_results": self.scenario_results,
                "success_metrics": self.success_metrics,
                "vulnerability_trends": self.vulnerability_trends,
                "target_susceptibility": self.target_susceptibility,
                "insights": self.generate_insights()
            }, default=str)  # default=str handles datetime serialization
        elif format.lower() == "pandas":
            # Convert to pandas DataFrames for analysis
            results_df = pd.DataFrame(self.scenario_results)
            return {
                "scenario_results": results_df,
                "insights": self.generate_insights()
            }
        else:
            raise ValueError(f"Unsupported export format: {format}")


class ScenarioOptimizer:
    """Optimizes attack scenarios based on feedback and historical data"""
    
    def __init__(self, feedback_analyzer: FeedbackAnalyzer):
        self.feedback_analyzer = feedback_analyzer
        self.scenario_history = []
        self.optimization_models = {}
        
    def add_scenario_history(self, scenario_data: Dict) -> None:
        """Add historical scenario data for optimization"""
        if "timestamp" not in scenario_data:
            scenario_data["timestamp"] = datetime.now().isoformat()
            
        self.scenario_history.append(scenario_data)
        
    def optimize_scenario(self, scenario_type: str, base_config: Dict) -> Dict:
        """Optimize a scenario configuration based on historical data"""
        if scenario_type == "network_penetration":
            return self._optimize_network_scenario(base_config)
        elif scenario_type == "web_application":
            return self._optimize_web_scenario(base_config)
        elif scenario_type == "social_engineering":
            return self._optimize_social_scenario(base_config)
        else:
            # For unknown scenario types, return the base config unchanged
            return base_config
        
    def _optimize_network_scenario(self, base_config: Dict) -> Dict:
        """Optimize a network penetration scenario"""
        # Get relevant historical data
        network_history = [s for s in self.scenario_history 
                          if s.get("scenario_type") == "network_penetration"]
        
        if len(network_history) < 5:  # Need at least 5 historical runs for optimization
            return base_config
        
        # Extract features and success indicators from history
        features = []
        success = []
        
        for scenario in network_history:
            # Extract relevant features
            scan_type = 1 if scenario.get("scan_type") == "stealth" else 0
            target_network_size = len(scenario.get("discovered_hosts", []))
            vuln_count = len(scenario.get("vulnerable_services", []))
            
            features.append([scan_type, target_network_size, vuln_count])
            success.append(1 if scenario.get("success", False) else 0)
        
        # Train a simple model if we don't have one yet
        if "network_penetration" not in self.optimization_models:
            try:
                model = RandomForestClassifier(n_estimators=10)
                model.fit(features, success)
                self.optimization_models["network_penetration"] = model
            except Exception as e:
                logger.error(f"Error training network scenario model: {e}")
                return base_config
        
        # Optimize the configuration
        optimized_config = base_config.copy()
        
        # Determine the best scan type based on historical success
        stealth_success = [s.get("success", False) for s in network_history 
                          if s.get("scan_type") == "stealth"]
        aggressive_success = [s.get("success", False) for s in network_history 
                             if s.get("scan_type") == "aggressive"]
        
        stealth_rate = sum(stealth_success) / len(stealth_success) if stealth_success else 0
        aggressive_rate = sum(aggressive_success) / len(aggressive_success) if aggressive_success else 0
        
        # Choose the scan type with higher success rate
        optimized_config["scan_type"] = "stealth" if stealth_rate >= aggressive_rate else "aggressive"
        
        return optimized_config
    
    def _optimize_web_scenario(self, base_config: Dict) -> Dict:
        """Optimize a web application scenario"""
        # Get relevant historical data
        web_history = [s for s in self.scenario_history 
                      if s.get("scenario_type") == "web_application"]
        
        if len(web_history) < 5:  # Need at least 5 historical runs for optimization
            return base_config
        
        # Analyze which pages tend to have more vulnerabilities
        page_vulnerability_count = {}
        
        for scenario in web_history:
            for vuln in scenario.get("vulnerabilities", []):
                url = vuln.get("url", "")
                if url:
                    path = url.split("/")[-1] if "/" in url else url
                    if path not in page_vulnerability_count:
                        page_vulnerability_count[path] = {
                            "count": 0,
                            "exploited": 0
                        }
                    
                    page_vulnerability_count[path]["count"] += 1
                    
                    # Check if this vulnerability was successfully exploited
                    for exploit in scenario.get("exploitation_results", []):
                        if exploit.get("vulnerability") == vuln and exploit.get("success", False):
                            page_vulnerability_count[path]["exploited"] += 1
        
        # Sort pages by exploitation success
        sorted_pages = sorted(page_vulnerability_count.items(), 
                             key=lambda x: x[1]["exploited"], 
                             reverse=True)
        
        # Optimize the configuration to focus on high-value pages
        optimized_config = base_config.copy()
        
        if sorted_pages and "target_url" in base_config:
            base_url = base_config["target_url"].rstrip("/")
            high_value_page = sorted_pages[0][0]
            
            # Update target URL to focus on the highest-value page
            if not base_url.endswith(high_value_page):
                optimized_config["target_url"] = f"{base_url}/{high_value_page}"
        
        return optimized_config
    
    def _optimize_social_scenario(self, base_config: Dict) -> Dict:
        """Optimize a social engineering scenario"""
        # Get relevant historical data
        social_history = [s for s in self.scenario_history 
                         if s.get("scenario_type") == "social_engineering"]
        
        if len(social_history) < 3:  # Need at least 3 historical runs for optimization
            return base_config
        
        # Analyze which attack types and departments have higher success rates
        attack_type_success = {}
        department_susceptibility = {}
        
        for scenario in social_history:
            attack_type = scenario.get("attack_type")
            if attack_type:
                if attack_type not in attack_type_success:
                    attack_type_success[attack_type] = {
                        "total": 0,
                        "success": 0
                    }
                
                attack_type_success[attack_type]["total"] += 1
                if scenario.get("success", False):
                    attack_type_success[attack_type]["success"] += 1
            
            # Analyze department susceptibility
            campaign_results = scenario.get("campaign_results", {})
            dept_breakdown = campaign_results.get("department_breakdown", {})
            
            for dept, data in dept_breakdown.items():
                if dept not in department_susceptibility:
                    department_susceptibility[dept] = []
                
                susceptibility_rate = data.get("susceptibility_rate", 0.0)
                department_susceptibility[dept].append(susceptibility_rate)
        
        # Calculate success rates for attack types
        attack_success_rates = {}
        for attack_type, data in attack_type_success.items():
            if data["total"] > 0:
                attack_success_rates[attack_type] = data["success"] / data["total"]
        
        # Calculate average susceptibility for departments
        dept_avg_susceptibility = {}
        for dept, rates in department_susceptibility.items():
            if rates:
                dept_avg_susceptibility[dept] = sum(rates) / len(rates)
        
        # Optimize the configuration
        optimized_config = base_config.copy()
        
        # Choose the most effective attack type
        if attack_success_rates:
            best_attack_type = max(attack_success_rates.items(), key=lambda x: x[1])[0]
            optimized_config["attack_type"] = best_attack_type
        
        # Add targeting information for most susceptible departments
        if dept_avg_susceptibility:
            sorted_depts = sorted(dept_avg_susceptibility.items(), key=lambda x: x[1], reverse=True)
            top_departments = [dept for dept, _ in sorted_depts[:3]]  # Top 3 most susceptible departments
            
            optimized_config["target_departments"] = top_departments
        
        return optimized_config
    
    def identify_patterns(self) -> Dict:
        """Identify patterns in successful and unsuccessful scenarios"""
        if len(self.scenario_history) < 10:  # Need sufficient history for pattern analysis
            return {"status": "insufficient_data"}
        
        patterns = {
            "network_penetration": self._analyze_network_patterns(),
            "web_application": self._analyze_web_patterns(),
            "social_engineering": self._analyze_social_patterns()
        }
        
        return patterns
    
    def _analyze_network_patterns(self) -> Dict:
        """Analyze patterns in network penetration scenarios"""
        network_history = [s for s in self.scenario_history 
                          if s.get("scenario_type") == "network_penetration"]
        
        if len(network_history) < 5:
            return {"status": "insufficient_data"}
        
        # Extract features for analysis
        features = []
        success_labels = []
        
        for scenario in network_history:
            # Basic features
            scan_type_val = 1 if scenario.get("scan_type") == "stealth" else 0
            host_count = len(scenario.get("discovered_hosts", []))
            vuln_count = len(scenario.get("vulnerable_services", []))
            high_severity_count = sum(1 for v in scenario.get("vulnerable_services", []) 
                                     if v.get("severity") in ["High", "Critical"])
            
            features.append([scan_type_val, host_count, vuln_count, high_severity_count])
            success_labels.append(1 if scenario.get("success", False) else 0)
        
        # Use isolation forest to identify anomalies in successful scenarios
        try:
            successful_indices = [i for i, s in enumerate(success_labels) if s == 1]
            if len(successful_indices) >= 3:  # Need at least 3 successful scenarios
                successful_features = [features[i] for i in successful_indices]
                
                model = IsolationForest(contamination=0.1)
                model.fit(successful_features)
                
                # Identify the most normal (typical) successful scenario
                scores = model.decision_function(successful_features)
                typical_idx = successful_indices[np.argmax(scores)]
                typical_scenario = network_history[typical_idx]
                
                return {
                    "status": "success",
                    "typical_successful_scenario": {
                        "scan_type": typical_scenario.get("scan_type"),
                        "host_count": len(typical_scenario.get("discovered_hosts", [])),
                        "vulnerability_count": len(typical_scenario.get("vulnerable_services", [])),
                        "high_severity_count": sum(1 for v in typical_scenario.get("vulnerable_services", []) 
                                                if v.get("severity") in ["High", "Critical"])
                    }
                }
            else:
                return {"status": "insufficient_successful_scenarios"}
        except Exception as e:
            logger.error(f"Error analyzing network patterns: {e}")
            return {"status": "analysis_error", "error": str(e)}
    
    def _analyze_web_patterns(self) -> Dict:
        """Analyze patterns in web application scenarios"""
        web_history = [s for s in self.scenario_history 
                      if s.get("scenario_type") == "web_application"]
        
        if len(web_history) < 5:
            return {"status": "insufficient_data"}
        
        # Analyze vulnerability types that lead to successful exploitation
        successful_vuln_types = {}
        
        for scenario in web_history:
            for exploit in scenario.get("exploitation_results", []):
                if exploit.get("success", False):
                    vuln = exploit.get("vulnerability", {})
                    vuln_type = vuln.get("type")
                    
                    if vuln_type:
                        if vuln_type not in successful_vuln_types:
                            successful_vuln_types[vuln_type] = 0
                        successful_vuln_types[vuln_type] += 1
        
        # Sort by frequency
        sorted_vulns = sorted(successful_vuln_types.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "status": "success",
            "most_exploitable_vulnerabilities": sorted_vulns,
            "recommendation": "Focus on the most frequently exploited vulnerability types"
        }
    
    def _analyze_social_patterns(self) -> Dict:
        """Analyze patterns in social engineering scenarios"""
        social_history = [s for s in self.scenario_history 
                         if s.get("scenario_type") == "social_engineering"]
        
        if len(social_history) < 3:
            return {"status": "insufficient_data"}
        
        # Analyze department susceptibility patterns
        department_data = {}
        
        for scenario in social_history:
            campaign_results = scenario.get("campaign_results", {})
            dept_breakdown = campaign_results.get("department_breakdown", {})
            
            for dept, data in dept_breakdown.items():
                if dept not in department_data:
                    department_data[dept] = []
                
                susceptibility_rate = data.get("susceptibility_rate", 0.0)
                department_data[dept].append(susceptibility_rate)
        
        # Calculate average and variance for each department
        department_stats = {}
        for dept, rates in department_data.items():
            if len(rates) >= 2:  # Need at least 2 data points
                avg = sum(rates) / len(rates)
                variance = sum((r - avg) ** 2 for r in rates) / len(rates)
                
                department_stats[dept] = {
                    "average_susceptibility": avg,
                    "variance": variance,
                    "data_points": len(rates)
                }
        
        # Identify departments with high susceptibility and low variance (consistently vulnerable)
        consistent_targets = []
        for dept, stats in department_stats.items():
            if stats["average_susceptibility"] > 0.4 and stats["variance"] < 0.05:
                consistent_targets.append({
                    "department": dept,
                    "average_susceptibility": stats["average_susceptibility"],
                    "consistency": "high"  # Low variance means high consistency
                })
        
        return {
            "status": "success",
            "department_statistics": department_stats,
            "consistent_targets": consistent_targets,
            "recommendation": "Focus on departments with consistently high susceptibility"
        }


class FeedbackLoop:
    """Main feedback loop system that connects scenario results with optimization"""
    
    def __init__(self):
        self.analyzer = FeedbackAnalyzer()
        self.optimizer = ScenarioOptimizer(self.analyzer)
        self.improvement_metrics = {
            "iterations": 0,
            "success_rate_improvement": 0.0,
            "vulnerability_discovery_improvement": 0.0
        }
    
    def process_scenario_result(self, scenario_result: Dict) -> Dict:
        """Process a scenario result and generate insights"""
        # Add the result to both analyzer and optimizer
        self.analyzer.add_scenario_result(scenario_result)
        self.optimizer.add_scenario_history(scenario_result)
        
        # Update iteration count
        self.improvement_metrics["iterations"] += 1
        
        # Generate insights
        insights = self.analyzer.generate_insights()
        
        # Update improvement metrics if we have enough data
        if self.improvement_metrics["iterations"] >= 5:
            self._update_improvement_metrics()
        
        return insights
    
    def optimize_scenario(self, scenario_type: str, base_config: Dict) -> Dict:
        """Optimize a scenario configuration based on feedback"""
        return self.optimizer.optimize_scenario(scenario_type, base_config)
    
    def _update_improvement_metrics(self) -> None:
        """Update metrics that track improvement over time"""
        # Get success rate trend
        success_trend = self.analyzer._analyze_success_rate_trend()
        trend_data = success_trend.get("data", [])
        
        if len(trend_data) >= 2:
            # Compare first and last success rates
            first_rate = trend_data[0].get("success_rate", 0)
            last_rate = trend_data[-1].get("success_rate", 0)
            
            # Calculate relative improvement
            if first_rate > 0:
                relative_improvement = (last_rate - first_rate) / first_rate
                self.improvement_metrics["success_rate_improvement"] = relative_improvement
        
        # Get vulnerability discovery trend
        vuln_trend = self.analyzer._analyze_vulnerability_discovery_trend()
        vuln_data = vuln_trend.get("data", [])
        
        if len(vuln_data) >= 2:
            # Compare first and last vulnerability counts
            first_count = vuln_data[0].get("total_vulnerabilities", 0)
            last_count = vuln_data[-1].get("total_vulnerabilities", 0)
            
            # Calculate relative improvement (more vulnerabilities found is better)
            if first_count > 0:
                relative_improvement = (last_count - first_count) / first_count
                self.improvement_metrics["vulnerability_discovery_improvement"] = relative_improvement
    
    def get_improvement_metrics(self) -> Dict:
        """Get the current improvement metrics"""
        return self.improvement_metrics
    
    def generate_report(self) -> Dict:
        """Generate a comprehensive feedback report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "iterations": self.improvement_metrics["iterations"],
            "insights": self.analyzer.generate_insights(),
            "patterns": self.optimizer.identify_patterns(),
            "improvement_metrics": self.get_improvement_metrics(),
            "recommendations": self._generate_strategic_recommendations()
        }
        
        return report
    
    def _generate_strategic_recommendations(self) -> List[Dict]:
        """Generate strategic recommendations based on all available data"""
        recommendations = []
        
        # Get insights and patterns
        insights = self.analyzer.generate_insights()
        patterns = self.optimizer.identify_patterns()
        
        # Add recommendations from insights
        if "recommendations" in insights:
            recommendations.extend(insights["recommendations"])
        
        # Add recommendations based on improvement metrics
        if self.improvement_metrics["success_rate_improvement"] < 0:
            # Success rate is decreasing, which is good for security
            recommendations.append({
                "type": "security_improvement",
                "priority": "high",
                "description": "Security posture is improving as red team success rate is decreasing",
                "details": {
                    "improvement": abs(self.improvement_metrics["success_rate_improvement"]) * 100,
                    "iterations": self.improvement_metrics["iterations"]
                }
            })
        elif self.improvement_metrics["success_rate_improvement"] > 0.1:
            # Success rate is increasing significantly, which is bad for security
            recommendations.append({
                "type": "security_degradation",
                "priority": "critical",
                "description": "Security posture may be degrading as red team success rate is increasing significantly",
                "details": {
                    "degradation": self.improvement_metrics["success_rate_improvement"] * 100,
                    "iterations": self.improvement_metrics["iterations"]
                }
            })
        
        # Add recommendation based on vulnerability discovery improvement
        if self.improvement_metrics["vulnerability_discovery_improvement"] > 0.2:
            recommendations.append({
                "type": "testing_improvement",
                "priority": "medium",
                "description": "Red team effectiveness is improving as more vulnerabilities are being discovered over time",
                "details": {
                    "improvement": self.improvement_metrics["vulnerability_discovery_improvement"] * 100,
                    "iterations": self.improvement_metrics["iterations"]
                }
            })
        
        return recommendations
    
    def export_data(self, format: str = "json") -> Any:
        """Export all feedback loop data"""
        return self.analyzer.export_data(format)