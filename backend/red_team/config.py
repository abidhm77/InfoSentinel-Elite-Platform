#!/usr/bin/env python3

"""
Red Team Automation Configuration Module

This module provides configuration management for the continuous red team
automation platform, including default settings, environment variable handling,
and configuration file loading.
"""

import json
import os
import logging
from typing import Dict, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)


class ConfigManager:
    """Configuration manager for the Red Team Automation Platform"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = self._load_default_config()
        
        # Load from file if provided
        if config_path:
            self.load_from_file(config_path)
            
        # Apply environment variable overrides
        self._apply_env_overrides()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "engine": {
                "max_concurrent_scenarios": 5,
                "default_interval_hours": 24,
                "execution_timeout_minutes": 60,
                "auto_start": False
            },
            "library": {
                "storage_path": "scenario_library.json",
                "auto_save": True,
                "save_interval_minutes": 30
            },
            "feedback": {
                "analysis_threshold": 0.7,
                "improvement_metrics": [
                    "detection_rate", 
                    "time_to_detect", 
                    "false_positive_rate",
                    "coverage_score",
                    "evasion_success_rate"
                ],
                "learning_rate": 0.1,
                "history_retention_days": 90
            },
            "integration": {
                "enabled": True,
                "ueba": {
                    "api_endpoint": "http://localhost:8000/api/ueba",
                    "api_key": "${UEBA_API_KEY}"
                },
                "deception": {
                    "api_endpoint": "http://localhost:8000/api/deception",
                    "api_key": "${DECEPTION_API_KEY}"
                },
                "zero_day_hunting": {
                    "api_endpoint": "http://localhost:8000/api/zero_day_hunting",
                    "api_key": "${ZERO_DAY_HUNTING_API_KEY}"
                }
            },
            "reporting": {
                "output_dir": "reports",
                "formats": ["json", "pdf", "html"],
                "include_mitre_mapping": True,
                "include_remediation": True,
                "auto_generate": False,
                "auto_generate_interval_hours": 168  # Weekly
            },
            "logging": {
                "level": "INFO",
                "file": "red_team_automation.log",
                "max_size_mb": 10,
                "backup_count": 5,
                "console": True
            },
            "security": {
                "encryption_enabled": True,
                "encryption_key": "${ENCRYPTION_KEY}",
                "secure_storage": True,
                "api_authentication": True,
                "api_token": "${API_TOKEN}"
            },
            "mitre": {
                "framework_version": "v10.0",
                "data_source": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                "update_interval_days": 30
            },
            "scenarios": {
                "network_penetration": {
                    "enabled": True,
                    "default_scan_type": "stealth",
                    "port_scan_timeout": 300,
                    "max_hosts": 1000
                },
                "web_application": {
                    "enabled": True,
                    "default_scan_depth": "medium",
                    "request_timeout": 30,
                    "max_requests_per_second": 10
                },
                "social_engineering": {
                    "enabled": True,
                    "default_campaign_size": 10,
                    "templates_dir": "templates/social"
                }
            }
        }
    
    def load_from_file(self, config_path: str) -> bool:
        """Load configuration from a file"""
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                
            # Merge with current config
            self._merge_config(file_config)
            logger.info(f"Loaded configuration from {config_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {e}")
            return False
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """Merge a new configuration with the current one"""
        for section, values in new_config.items():
            if section in self.config and isinstance(self.config[section], dict) and isinstance(values, dict):
                # Recursively merge nested dictionaries
                self._merge_dict(self.config[section], values)
            else:
                # Replace or add non-dict values
                self.config[section] = values
    
    def _merge_dict(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Recursively merge source dict into target dict"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                self._merge_dict(target[key], value)
            else:
                # Replace or add non-dict values
                target[key] = value
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to the configuration"""
        # Process all string values in the config for environment variable placeholders
        self._process_env_vars(self.config)
    
    def _process_env_vars(self, config_section: Dict[str, Any]) -> None:
        """Recursively process environment variable placeholders in the config"""
        for key, value in config_section.items():
            if isinstance(value, dict):
                # Recursively process nested dictionaries
                self._process_env_vars(value)
            elif isinstance(value, str) and value.startswith("${"} and value.endswith("}"):
                # Extract environment variable name
                env_var = value[2:-1]
                
                # Get value from environment or keep placeholder if not found
                env_value = os.environ.get(env_var)
                if env_value is not None:
                    config_section[key] = env_value
                    logger.debug(f"Applied environment override for {key}")
    
    def save_to_file(self, config_path: Optional[str] = None) -> bool:
        """Save the current configuration to a file"""
        if config_path is None:
            config_path = self.config_path
            
        if not config_path:
            logger.error("No configuration file path specified")
            return False
            
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
                
            logger.info(f"Saved configuration to {config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration to {config_path}: {e}")
            return False
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get a configuration value"""
        if section not in self.config:
            return default
            
        if key is None:
            return self.config[section]
            
        return self.config[section].get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value"""
        if section not in self.config:
            self.config[section] = {}
            
        self.config[section][key] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get the entire configuration"""
        return self.config


# Default configuration file paths to check
DEFAULT_CONFIG_PATHS = [
    "./config.json",
    "./config/red_team_config.json",
    "~/.infosentinel/red_team_config.json",
    "/etc/infosentinel/red_team_config.json"
]


def load_config(config_path: Optional[str] = None) -> ConfigManager:
    """Load configuration from the specified path or search default locations"""
    # If path is provided, use it directly
    if config_path:
        return ConfigManager(config_path)
        
    # Otherwise, try default paths
    for path in DEFAULT_CONFIG_PATHS:
        # Expand user directory if needed
        expanded_path = os.path.expanduser(path)
        
        if os.path.exists(expanded_path):
            logger.info(f"Found configuration file at {expanded_path}")
            return ConfigManager(expanded_path)
    
    # No config file found, use defaults
    logger.info("No configuration file found, using defaults")
    return ConfigManager()


# Example usage
def create_default_config(output_path: str) -> bool:
    """Create a default configuration file"""
    config = ConfigManager()
    return config.save_to_file(output_path)