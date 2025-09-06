#!/usr/bin/env python3

"""
Red Team Automation Utilities Module

This module provides utility functions and helper classes for the continuous red team
automation platform, including logging, encryption, MITRE ATT&CK integration, and more.
"""

import json
import os
import logging
import hashlib
import base64
import uuid
import datetime
import requests
from typing import Dict, List, Any, Optional, Union, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Setup logging
logger = logging.getLogger(__name__)


class LoggingManager:
    """Manages logging configuration for the Red Team Automation Platform"""
    
    @staticmethod
    def setup_logging(config: Dict[str, Any]) -> None:
        """Configure logging based on provided configuration"""
        log_config = config.get('logging', {})
        
        # Set log level
        log_level_str = log_config.get('level', 'INFO')
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:  
            root_logger.removeHandler(handler)
        
        # Add console handler if enabled
        if log_config.get('console', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
        
        # Add file handler if configured
        log_file = log_config.get('file')
        if log_file:
            try:
                from logging.handlers import RotatingFileHandler
                
                # Create log directory if it doesn't exist
                log_dir = os.path.dirname(log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                # Setup rotating file handler
                max_size = log_config.get('max_size_mb', 10) * 1024 * 1024  # Convert to bytes
                backup_count = log_config.get('backup_count', 5)
                
                file_handler = RotatingFileHandler(
                    log_file, 
                    maxBytes=max_size, 
                    backupCount=backup_count
                )
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)
                
                logger.info(f"Logging to file: {log_file}")
            except Exception as e:
                logger.error(f"Failed to setup file logging: {e}")
        
        logger.info(f"Logging initialized at level {log_level_str}")


class SecurityManager:
    """Manages security operations for the Red Team Automation Platform"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('security', {})
        self.encryption_enabled = self.config.get('encryption_enabled', True)
        self._cipher = None
        
        if self.encryption_enabled:
            self._initialize_encryption()
    
    def _initialize_encryption(self) -> None:
        """Initialize encryption with the provided key or generate a new one"""
        try:
            encryption_key = self.config.get('encryption_key')
            
            if not encryption_key:
                logger.warning("No encryption key provided, generating a temporary one")
                encryption_key = Fernet.generate_key().decode('utf-8')
            
            # If the key is not in the correct format, derive a proper key
            if not encryption_key.startswith('b') or len(encryption_key) != 44:
                # Derive a proper key using PBKDF2
                salt = b'InfoSentinel'  # Fixed salt for consistency
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
            else:
                key = encryption_key.encode()
            
            self._cipher = Fernet(key)
            logger.info("Encryption initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            self.encryption_enabled = False
    
    def encrypt(self, data: str) -> str:
        """Encrypt the provided string data"""
        if not self.encryption_enabled or not self._cipher:
            logger.warning("Encryption is disabled or not initialized")
            return data
        
        try:
            return self._cipher.encrypt(data.encode()).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt the provided encrypted string data"""
        if not self.encryption_enabled or not self._cipher:
            logger.warning("Encryption is disabled or not initialized")
            return encrypted_data
        
        try:
            return self._cipher.decrypt(encrypted_data.encode()).decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return encrypted_data
    
    def hash_password(self, password: str) -> str:
        """Create a secure hash of a password"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            100000
        )
        return base64.b64encode(salt + key).decode('utf-8')
    
    def verify_password(self, stored_hash: str, password: str) -> bool:
        """Verify a password against its stored hash"""
        try:
            decoded = base64.b64decode(stored_hash.encode('utf-8'))
            salt, key = decoded[:32], decoded[32:]
            new_key = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode('utf-8'), 
                salt, 
                100000
            )
            return key == new_key
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def generate_api_token(self) -> str:
        """Generate a secure API token"""
        return str(uuid.uuid4())
    
    def validate_api_token(self, token: str) -> bool:
        """Validate an API token against the configured token"""
        configured_token = self.config.get('api_token')
        if not configured_token or not self.config.get('api_authentication', True):
            return True
        
        return token == configured_token


class MitreAttackManager:
    """Manages MITRE ATT&CK framework integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('mitre', {})
        self.framework_version = self.config.get('framework_version', 'v10.0')
        self.data_source = self.config.get('data_source')
        self.update_interval = self.config.get('update_interval_days', 30)
        self.last_update = None
        self.techniques = {}
        self.tactics = {}
        self.groups = {}
        
        # Load MITRE ATT&CK data
        self._load_data()
    
    def _load_data(self) -> None:
        """Load MITRE ATT&CK data from source or cache"""
        cache_file = f"mitre_attack_{self.framework_version}.json"
        
        # Check if we need to update the cache
        need_update = True
        if os.path.exists(cache_file):
            try:
                # Check file modification time
                mtime = os.path.getmtime(cache_file)
                last_update = datetime.datetime.fromtimestamp(mtime)
                now = datetime.datetime.now()
                days_since_update = (now - last_update).days
                
                if days_since_update < self.update_interval:
                    # Load from cache
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        
                    self._process_data(data)
                    self.last_update = last_update
                    need_update = False
                    logger.info(f"Loaded MITRE ATT&CK data from cache ({days_since_update} days old)")
            except Exception as e:
                logger.error(f"Error loading MITRE ATT&CK data from cache: {e}")
        
        if need_update:
            try:
                # Fetch from data source
                if self.data_source:
                    logger.info(f"Fetching MITRE ATT&CK data from {self.data_source}")
                    response = requests.get(self.data_source, timeout=30)
                    response.raise_for_status()
                    data = response.json()
                    
                    # Save to cache
                    with open(cache_file, 'w') as f:
                        json.dump(data, f)
                    
                    self._process_data(data)
                    self.last_update = datetime.datetime.now()
                    logger.info("Updated MITRE ATT&CK data successfully")
                else:
                    logger.warning("No MITRE ATT&CK data source configured")
            except Exception as e:
                logger.error(f"Error updating MITRE ATT&CK data: {e}")
                
                # Try to load from cache as fallback
                if os.path.exists(cache_file):
                    try:
                        with open(cache_file, 'r') as f:
                            data = json.load(f)
                        
                        self._process_data(data)
                        logger.info("Loaded MITRE ATT&CK data from cache as fallback")
                    except Exception as e2:
                        logger.error(f"Error loading MITRE ATT&CK data from cache: {e2}")
    
    def _process_data(self, data: Dict[str, Any]) -> None:
        """Process MITRE ATT&CK data into usable format"""
        if 'objects' not in data:
            logger.error("Invalid MITRE ATT&CK data format")
            return
        
        # Reset collections
        self.techniques = {}
        self.tactics = {}
        self.groups = {}
        
        # Process objects
        for obj in data['objects']:
            obj_type = obj.get('type')
            
            if obj_type == 'attack-pattern':
                # This is a technique
                technique_id = obj.get('external_references', [{}])[0].get('external_id')
                if technique_id and technique_id.startswith('T'):
                    self.techniques[technique_id] = {
                        'id': technique_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactics': [],
                        'platforms': obj.get('x_mitre_platforms', []),
                        'detection': obj.get('x_mitre_detection', ''),
                        'url': next((ref.get('url', '') for ref in obj.get('external_references', []) 
                                    if ref.get('source_name') == 'mitre-attack'), '')
                    }
                    
                    # Extract tactics
                    for kill_chain in obj.get('kill_chain_phases', []):
                        if kill_chain.get('kill_chain_name') == 'mitre-attack':
                            phase_name = kill_chain.get('phase_name')
                            if phase_name:
                                self.techniques[technique_id]['tactics'].append(phase_name)
            
            elif obj_type == 'x-mitre-tactic':
                # This is a tactic
                tactic_id = obj.get('external_references', [{}])[0].get('external_id')
                if tactic_id and tactic_id.startswith('TA'):
                    shortname = obj.get('x_mitre_shortname', '')
                    self.tactics[shortname] = {
                        'id': tactic_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'shortname': shortname,
                        'url': next((ref.get('url', '') for ref in obj.get('external_references', []) 
                                    if ref.get('source_name') == 'mitre-attack'), '')
                    }
            
            elif obj_type == 'intrusion-set':
                # This is a threat group
                group_id = obj.get('external_references', [{}])[0].get('external_id')
                if group_id and group_id.startswith('G'):
                    self.groups[group_id] = {
                        'id': group_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'aliases': obj.get('aliases', []),
                        'url': next((ref.get('url', '') for ref in obj.get('external_references', []) 
                                    if ref.get('source_name') == 'mitre-attack'), '')
                    }
        
        logger.info(f"Processed MITRE ATT&CK data: {len(self.techniques)} techniques, "
                   f"{len(self.tactics)} tactics, {len(self.groups)} groups")
    
    def get_technique(self, technique_id: str) -> Dict[str, Any]:
        """Get details for a specific technique by ID"""
        return self.techniques.get(technique_id, {})
    
    def get_tactic(self, tactic_shortname: str) -> Dict[str, Any]:
        """Get details for a specific tactic by shortname"""
        return self.tactics.get(tactic_shortname, {})
    
    def get_group(self, group_id: str) -> Dict[str, Any]:
        """Get details for a specific threat group by ID"""
        return self.groups.get(group_id, {})
    
    def get_techniques_by_tactic(self, tactic_shortname: str) -> List[Dict[str, Any]]:
        """Get all techniques for a specific tactic"""
        return [technique for technique in self.techniques.values() 
                if tactic_shortname in technique.get('tactics', [])]
    
    def get_all_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Get all techniques"""
        return self.techniques
    
    def get_all_tactics(self) -> Dict[str, Dict[str, Any]]:
        """Get all tactics"""
        return self.tactics
    
    def get_all_groups(self) -> Dict[str, Dict[str, Any]]:
        """Get all threat groups"""
        return self.groups


class ReportGenerator:
    """Generates reports for red team automation activities"""
    
    def __init__(self, config: Dict[str, Any], mitre_manager: Optional[MitreAttackManager] = None):
        self.config = config.get('reporting', {})
        self.output_dir = self.config.get('output_dir', 'reports')
        self.formats = self.config.get('formats', ['json'])
        self.include_mitre = self.config.get('include_mitre_mapping', True)
        self.include_remediation = self.config.get('include_remediation', True)
        self.mitre_manager = mitre_manager
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_scenario_report(self, scenario_data: Dict[str, Any], report_id: Optional[str] = None) -> Dict[str, str]:
        """Generate a report for a scenario execution"""
        if not report_id:
            report_id = f"scenario_{scenario_data.get('id', str(uuid.uuid4()))}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Prepare report data
        report = {
            'id': report_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'scenario': scenario_data,
            'summary': self._generate_summary(scenario_data),
        }
        
        # Add MITRE ATT&CK mappings if enabled and available
        if self.include_mitre and self.mitre_manager and 'techniques' in scenario_data:
            report['mitre_mapping'] = self._generate_mitre_mapping(scenario_data['techniques'])
        
        # Add remediation recommendations if enabled
        if self.include_remediation and 'findings' in scenario_data:
            report['remediation'] = self._generate_remediation(scenario_data['findings'])
        
        # Generate reports in all configured formats
        output_files = {}
        for fmt in self.formats:
            output_file = self._write_report(report, fmt, report_id)
            if output_file:
                output_files[fmt] = output_file
        
        return output_files
    
    def _generate_summary(self, scenario_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the scenario execution"""
        findings = scenario_data.get('findings', [])
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate success metrics
        success_rate = scenario_data.get('success_rate', 0)
        detection_time = scenario_data.get('detection_time', 'N/A')
        evasion_rate = scenario_data.get('evasion_rate', 0)
        
        return {
            'name': scenario_data.get('name', 'Unknown Scenario'),
            'type': scenario_data.get('type', 'Unknown'),
            'execution_time': scenario_data.get('execution_time', 'N/A'),
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'success_rate': success_rate,
            'detection_time': detection_time,
            'evasion_rate': evasion_rate,
            'overall_risk': self._calculate_risk_score(findings, success_rate)
        }
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]], success_rate: float) -> str:
        """Calculate an overall risk score based on findings and success rate"""
        if not findings:
            return "Low"
        
        # Assign weights to different severity levels
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0,
            'unknown': 2
        }
        
        # Calculate weighted score
        total_weight = 0
        for finding in findings:
            severity = finding.get('severity', 'unknown').lower()
            total_weight += severity_weights.get(severity, 2)
        
        # Adjust by success rate (higher success = higher risk)
        adjusted_score = total_weight * (success_rate / 100)
        
        # Map to risk categories
        if adjusted_score > 50:
            return "Critical"
        elif adjusted_score > 30:
            return "High"
        elif adjusted_score > 15:
            return "Medium"
        elif adjusted_score > 5:
            return "Low"
        else:
            return "Minimal"
    
    def _generate_mitre_mapping(self, techniques: List[str]) -> List[Dict[str, Any]]:
        """Generate MITRE ATT&CK technique mappings"""
        mappings = []
        
        for technique_id in techniques:
            technique_data = self.mitre_manager.get_technique(technique_id) if self.mitre_manager else {}
            
            if technique_data:
                mappings.append({
                    'technique_id': technique_id,
                    'name': technique_data.get('name', 'Unknown'),
                    'description': technique_data.get('description', ''),
                    'tactics': technique_data.get('tactics', []),
                    'url': technique_data.get('url', '')
                })
            else:
                mappings.append({
                    'technique_id': technique_id,
                    'name': 'Unknown',
                    'description': 'Technique details not available',
                    'tactics': [],
                    'url': ''
                })
        
        return mappings
    
    def _generate_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations for findings"""
        remediation = []
        
        for finding in findings:
            if 'remediation' in finding:
                remediation.append({
                    'finding_id': finding.get('id', ''),
                    'title': finding.get('title', 'Unknown Finding'),
                    'severity': finding.get('severity', 'unknown'),
                    'recommendation': finding['remediation'],
                    'effort': finding.get('remediation_effort', 'medium'),
                    'priority': self._calculate_remediation_priority(finding)
                })
        
        # Sort by priority (highest first)
        return sorted(remediation, key=lambda x: {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3
        }.get(x['priority'].lower(), 4))
    
    def _calculate_remediation_priority(self, finding: Dict[str, Any]) -> str:
        """Calculate remediation priority based on severity and other factors"""
        severity = finding.get('severity', 'unknown').lower()
        
        # Default priority mapping based on severity
        priority_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'low',
            'unknown': 'medium'
        }
        
        # Start with default priority
        priority = priority_map.get(severity, 'medium')
        
        # Adjust based on exploitability
        if finding.get('exploitable', False):
            # Increase priority for exploitable findings
            if priority == 'medium':
                priority = 'high'
            elif priority == 'low':
                priority = 'medium'
        
        # Adjust based on affected assets
        if finding.get('affects_critical_assets', False):
            # Increase priority for findings affecting critical assets
            if priority == 'high':
                priority = 'critical'
            elif priority == 'medium':
                priority = 'high'
            elif priority == 'low':
                priority = 'medium'
        
        return priority
    
    def _write_report(self, report: Dict[str, Any], format_type: str, report_id: str) -> Optional[str]:
        """Write the report to a file in the specified format"""
        filename = os.path.join(self.output_dir, f"{report_id}.{format_type}")
        
        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
                return filename
            
            elif format_type == 'html':
                # Simple HTML report template
                html_content = self._generate_html_report(report)
                with open(filename, 'w') as f:
                    f.write(html_content)
                return filename
            
            elif format_type == 'pdf':
                # PDF generation would typically use a library like reportlab or weasyprint
                # This is a placeholder for actual PDF generation
                logger.warning("PDF report generation not fully implemented")
                return None
            
            else:
                logger.warning(f"Unsupported report format: {format_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error writing {format_type} report: {e}")
            return None
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate an HTML report from the report data"""
        # This is a simple HTML template - in a real implementation, you would use a proper templating engine
        summary = report.get('summary', {})
        scenario = report.get('scenario', {})
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Red Team Automation Report: {summary.get('name', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                .critical {{ color: #d9534f; }}
                .high {{ color: #f0ad4e; }}
                .medium {{ color: #5bc0de; }}
                .low {{ color: #5cb85c; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Red Team Automation Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Scenario:</strong> {summary.get('name', 'Unknown')}</p>
                <p><strong>Type:</strong> {summary.get('type', 'Unknown')}</p>
                <p><strong>Execution Time:</strong> {summary.get('execution_time', 'N/A')}</p>
                <p><strong>Total Findings:</strong> {summary.get('total_findings', 0)}</p>
                <p><strong>Overall Risk:</strong> <span class="{summary.get('overall_risk', 'Low').lower()}">{summary.get('overall_risk', 'Low')}</span></p>
            </div>
        """
        
        # Add findings section if available
        if 'findings' in scenario:
            html += """
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            """
            
            for finding in scenario['findings']:
                severity = finding.get('severity', 'unknown').lower()
                html += f"""
                <tr>
                    <td>{finding.get('title', 'Unknown')}</td>
                    <td class="{severity}">{finding.get('severity', 'Unknown')}</td>
                    <td>{finding.get('description', '')}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add MITRE ATT&CK mapping if available
        if 'mitre_mapping' in report:
            html += """
            <h2>MITRE ATT&CK Techniques</h2>
            <table>
                <tr>
                    <th>Technique ID</th>
                    <th>Name</th>
                    <th>Tactics</th>
                </tr>
            """
            
            for technique in report['mitre_mapping']:
                html += f"""
                <tr>
                    <td>{technique.get('technique_id', '')}</td>
                    <td>{technique.get('name', 'Unknown')}</td>
                    <td>{', '.join(technique.get('tactics', []))}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add remediation section if available
        if 'remediation' in report:
            html += """
            <h2>Remediation Recommendations</h2>
            <table>
                <tr>
                    <th>Finding</th>
                    <th>Priority</th>
                    <th>Recommendation</th>
                </tr>
            """
            
            for item in report['remediation']:
                priority = item.get('priority', 'medium').lower()
                html += f"""
                <tr>
                    <td>{item.get('title', 'Unknown')}</td>
                    <td class="{priority}">{item.get('priority', 'Medium')}</td>
                    <td>{item.get('recommendation', '')}</td>
                </tr>
                """
            
            html += "</table>"
        
        html += """
        </body>
        </html>
        """
        
        return html


# Utility functions
def generate_unique_id() -> str:
    """Generate a unique ID for scenarios, findings, etc."""
    return str(uuid.uuid4())


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def parse_timespan(timespan: str) -> int:
    """Parse a timespan string (e.g., '1h', '30m', '1d') to seconds"""
    if not timespan:
        return 0
    
    # Extract number and unit
    import re
    match = re.match(r'^(\d+)([smhdw])$', timespan.lower())
    if not match:
        raise ValueError(f"Invalid timespan format: {timespan}")
    
    value, unit = match.groups()
    value = int(value)
    
    # Convert to seconds
    if unit == 's':
        return value
    elif unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    elif unit == 'w':
        return value * 604800
    
    return 0