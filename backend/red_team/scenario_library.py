#!/usr/bin/env python3

"""
Scenario Library for Red Team Automation

This module implements a comprehensive library of attack scenarios that can be
used by the continuous red team automation engine. It provides a centralized
repository for scenario templates, management, and categorization.
"""

import json
import os
import uuid
from typing import Dict, List, Optional, Union, Any
from datetime import datetime

from . import AttackScenario
from .scenarios import NetworkPenetrationScenario, WebApplicationScenario, SocialEngineeringScenario


class ScenarioTemplate:
    """Template for creating attack scenarios"""
    
    def __init__(self, name: str, description: str, scenario_type: str, 
                 parameters: Dict[str, Any], mitre_techniques: List[str]):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.scenario_type = scenario_type
        self.parameters = parameters
        self.mitre_techniques = mitre_techniques
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        
    def to_dict(self) -> Dict:
        """Convert template to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "scenario_type": self.scenario_type,
            "parameters": self.parameters,
            "mitre_techniques": self.mitre_techniques,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScenarioTemplate':
        """Create template from dictionary"""
        template = cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            scenario_type=data.get("scenario_type", ""),
            parameters=data.get("parameters", {}),
            mitre_techniques=data.get("mitre_techniques", [])
        )
        
        # Restore ID and timestamps if available
        if "id" in data:
            template.id = data["id"]
        if "created_at" in data:
            template.created_at = data["created_at"]
        if "updated_at" in data:
            template.updated_at = data["updated_at"]
            
        return template
    
    def create_scenario(self, parameter_values: Dict[str, Any]) -> Optional[AttackScenario]:
        """Create a scenario instance from this template"""
        # Merge default parameters with provided values
        params = self.parameters.copy()
        params.update(parameter_values)
        
        # Create the appropriate scenario type
        if self.scenario_type == "network_penetration":
            return NetworkPenetrationScenario(
                name=self.name,
                target_network=params.get("target_network", "192.168.1.0/24"),
                scan_type=params.get("scan_type", "stealth")
            )
        elif self.scenario_type == "web_application":
            return WebApplicationScenario(
                name=self.name,
                target_url=params.get("target_url", "https://example.com")
            )
        elif self.scenario_type == "social_engineering":
            return SocialEngineeringScenario(
                name=self.name,
                target_organization=params.get("target_organization", "example.com"),
                attack_type=params.get("attack_type", "phishing")
            )
        else:
            return None


class ScenarioCategory:
    """Category for organizing attack scenarios"""
    
    def __init__(self, name: str, description: str):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.templates = []
        
    def add_template(self, template: ScenarioTemplate) -> None:
        """Add a template to this category"""
        self.templates.append(template)
        
    def remove_template(self, template_id: str) -> bool:
        """Remove a template from this category"""
        for i, template in enumerate(self.templates):
            if template.id == template_id:
                self.templates.pop(i)
                return True
        return False
    
    def get_template(self, template_id: str) -> Optional[ScenarioTemplate]:
        """Get a template by ID"""
        for template in self.templates:
            if template.id == template_id:
                return template
        return None
    
    def to_dict(self) -> Dict:
        """Convert category to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "templates": [t.to_dict() for t in self.templates]
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScenarioCategory':
        """Create category from dictionary"""
        category = cls(
            name=data.get("name", ""),
            description=data.get("description", "")
        )
        
        # Restore ID if available
        if "id" in data:
            category.id = data["id"]
            
        # Add templates
        for template_data in data.get("templates", []):
            template = ScenarioTemplate.from_dict(template_data)
            category.templates.append(template)
            
        return category


class ScenarioLibrary:
    """Library for managing attack scenario templates"""
    
    def __init__(self, storage_path: Optional[str] = None):
        self.categories = []
        self.storage_path = storage_path
        
        # Initialize with default categories
        self._initialize_default_categories()
        
        # Load from storage if available
        if storage_path and os.path.exists(storage_path):
            self.load()
        
    def _initialize_default_categories(self) -> None:
        """Initialize default categories and templates"""
        # Network Penetration category
        network_category = ScenarioCategory(
            name="Network Penetration",
            description="Scenarios for testing network security"
        )
        
        # Add network templates
        network_templates = [
            ScenarioTemplate(
                name="Internal Network Scan",
                description="Scan and enumerate internal network for vulnerabilities",
                scenario_type="network_penetration",
                parameters={
                    "target_network": "192.168.1.0/24",
                    "scan_type": "stealth"
                },
                mitre_techniques=["T1046", "T1595"]
            ),
            ScenarioTemplate(
                name="External Perimeter Assessment",
                description="Assess the security of external-facing network infrastructure",
                scenario_type="network_penetration",
                parameters={
                    "target_network": "203.0.113.0/24",
                    "scan_type": "aggressive"
                },
                mitre_techniques=["T1046", "T1590"]
            ),
            ScenarioTemplate(
                name="Lateral Movement Simulation",
                description="Simulate lateral movement across network segments",
                scenario_type="network_penetration",
                parameters={
                    "target_network": "10.0.0.0/16",
                    "scan_type": "stealth"
                },
                mitre_techniques=["T1046", "T1210"]
            )
        ]
        
        for template in network_templates:
            network_category.add_template(template)
            
        self.categories.append(network_category)
        
        # Web Application category
        web_category = ScenarioCategory(
            name="Web Application",
            description="Scenarios for testing web application security"
        )
        
        # Add web templates
        web_templates = [
            ScenarioTemplate(
                name="OWASP Top 10 Assessment",
                description="Test for OWASP Top 10 vulnerabilities",
                scenario_type="web_application",
                parameters={
                    "target_url": "https://example.com"
                },
                mitre_techniques=["T1190", "T1592"]
            ),
            ScenarioTemplate(
                name="API Security Testing",
                description="Test the security of REST APIs",
                scenario_type="web_application",
                parameters={
                    "target_url": "https://api.example.com"
                },
                mitre_techniques=["T1190", "T1059"]
            ),
            ScenarioTemplate(
                name="Authentication Bypass Testing",
                description="Test for authentication and authorization weaknesses",
                scenario_type="web_application",
                parameters={
                    "target_url": "https://login.example.com"
                },
                mitre_techniques=["T1190", "T1212"]
            )
        ]
        
        for template in web_templates:
            web_category.add_template(template)
            
        self.categories.append(web_category)
        
        # Social Engineering category
        social_category = ScenarioCategory(
            name="Social Engineering",
            description="Scenarios for testing human security awareness"
        )
        
        # Add social engineering templates
        social_templates = [
            ScenarioTemplate(
                name="Phishing Campaign",
                description="Conduct a simulated phishing campaign",
                scenario_type="social_engineering",
                parameters={
                    "target_organization": "example.com",
                    "attack_type": "phishing"
                },
                mitre_techniques=["T1566", "T1534"]
            ),
            ScenarioTemplate(
                name="Vishing Assessment",
                description="Conduct a voice phishing assessment",
                scenario_type="social_engineering",
                parameters={
                    "target_organization": "example.com",
                    "attack_type": "vishing"
                },
                mitre_techniques=["T1566", "T1598"]
            ),
            ScenarioTemplate(
                name="Physical Security Testing",
                description="Test physical security controls and awareness",
                scenario_type="social_engineering",
                parameters={
                    "target_organization": "example.com",
                    "attack_type": "physical"
                },
                mitre_techniques=["T1200", "T1091"]
            )
        ]
        
        for template in social_templates:
            social_category.add_template(template)
            
        self.categories.append(social_category)
    
    def add_category(self, category: ScenarioCategory) -> None:
        """Add a category to the library"""
        self.categories.append(category)
        
    def remove_category(self, category_id: str) -> bool:
        """Remove a category from the library"""
        for i, category in enumerate(self.categories):
            if category.id == category_id:
                self.categories.pop(i)
                return True
        return False
    
    def get_category(self, category_id: str) -> Optional[ScenarioCategory]:
        """Get a category by ID"""
        for category in self.categories:
            if category.id == category_id:
                return category
        return None
    
    def get_category_by_name(self, name: str) -> Optional[ScenarioCategory]:
        """Get a category by name"""
        for category in self.categories:
            if category.name == name:
                return category
        return None
    
    def get_template(self, template_id: str) -> Optional[ScenarioTemplate]:
        """Get a template by ID from any category"""
        for category in self.categories:
            template = category.get_template(template_id)
            if template:
                return template
        return None
    
    def search_templates(self, query: str) -> List[ScenarioTemplate]:
        """Search for templates by name or description"""
        results = []
        query = query.lower()
        
        for category in self.categories:
            for template in category.templates:
                if query in template.name.lower() or query in template.description.lower():
                    results.append(template)
                    
        return results
    
    def filter_by_mitre_technique(self, technique_id: str) -> List[ScenarioTemplate]:
        """Filter templates by MITRE ATT&CK technique ID"""
        results = []
        
        for category in self.categories:
            for template in category.templates:
                if technique_id in template.mitre_techniques:
                    results.append(template)
                    
        return results
    
    def create_scenario(self, template_id: str, parameter_values: Dict[str, Any]) -> Optional[AttackScenario]:
        """Create a scenario from a template"""
        template = self.get_template(template_id)
        if template:
            return template.create_scenario(parameter_values)
        return None
    
    def save(self) -> bool:
        """Save the library to storage"""
        if not self.storage_path:
            return False
            
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            
            # Convert to dictionary and save as JSON
            data = {
                "categories": [c.to_dict() for c in self.categories]
            }
            
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            return True
        except Exception as e:
            print(f"Error saving scenario library: {e}")
            return False
    
    def load(self) -> bool:
        """Load the library from storage"""
        if not self.storage_path or not os.path.exists(self.storage_path):
            return False
            
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                
            # Clear existing categories
            self.categories = []
            
            # Load categories from data
            for category_data in data.get("categories", []):
                category = ScenarioCategory.from_dict(category_data)
                self.categories.append(category)
                
            return True
        except Exception as e:
            print(f"Error loading scenario library: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get statistics about the library"""
        total_templates = 0
        templates_by_type = {}
        techniques_coverage = set()
        
        for category in self.categories:
            total_templates += len(category.templates)
            
            for template in category.templates:
                # Count by scenario type
                scenario_type = template.scenario_type
                if scenario_type not in templates_by_type:
                    templates_by_type[scenario_type] = 0
                templates_by_type[scenario_type] += 1
                
                # Collect MITRE techniques
                for technique in template.mitre_techniques:
                    techniques_coverage.add(technique)
        
        return {
            "total_categories": len(self.categories),
            "total_templates": total_templates,
            "templates_by_type": templates_by_type,
            "mitre_techniques_coverage": len(techniques_coverage),
            "mitre_techniques": sorted(list(techniques_coverage))
        }


# Example usage
def create_default_library(storage_path: Optional[str] = None) -> ScenarioLibrary:
    """Create a default scenario library"""
    library = ScenarioLibrary(storage_path)
    
    # Save if storage path is provided
    if storage_path:
        library.save()
        
    return library