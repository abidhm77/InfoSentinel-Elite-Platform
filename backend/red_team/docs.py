#!/usr/bin/env python3

"""
Red Team Automation Documentation Generator

This module provides documentation generation capabilities for the continuous red team
automation platform, including API documentation, user guides, and technical specifications.
"""

import os
import json
import inspect
import importlib
import datetime
from typing import Dict, List, Any, Optional, Union, Callable

# Import platform modules
from backend.red_team.automation_engine import AdvancedAutomationEngine
from backend.red_team.scenarios import NetworkPenetrationScenario, WebApplicationScenario, SocialEngineeringScenario
from backend.red_team.feedback_loop import FeedbackLoop
from backend.red_team.scenario_library import ScenarioLibrary
from backend.red_team.config import ConfigManager
from backend.red_team.utils import SecurityManager, MitreAttackManager, ReportGenerator
from backend.red_team.integration import IntegrationManager


class DocumentationGenerator:
    """Generates documentation for the Red Team Automation Platform"""
    
    def __init__(self, output_dir: str = "docs"):
        self.output_dir = output_dir
        self.modules = {
            "automation_engine": AdvancedAutomationEngine,
            "scenarios": {
                "NetworkPenetrationScenario": NetworkPenetrationScenario,
                "WebApplicationScenario": WebApplicationScenario,
                "SocialEngineeringScenario": SocialEngineeringScenario
            },
            "feedback_loop": FeedbackLoop,
            "scenario_library": ScenarioLibrary,
            "config": ConfigManager,
            "utils": {
                "SecurityManager": SecurityManager,
                "MitreAttackManager": MitreAttackManager,
                "ReportGenerator": ReportGenerator
            },
            "integration": IntegrationManager
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_all_documentation(self) -> None:
        """Generate all documentation files"""
        self.generate_api_documentation()
        self.generate_user_guide()
        self.generate_technical_specification()
        self.generate_integration_guide()
        self.generate_scenario_documentation()
    
    def generate_api_documentation(self) -> str:
        """Generate API documentation for all modules"""
        api_doc = {
            "title": "Red Team Automation Platform API Documentation",
            "version": "1.0.0",
            "generated_at": datetime.datetime.now().isoformat(),
            "modules": {}
        }
        
        # Process each module
        for module_name, module_obj in self.modules.items():
            if isinstance(module_obj, dict):
                # Module contains multiple classes
                api_doc["modules"][module_name] = {
                    "classes": {}
                }
                
                for class_name, class_obj in module_obj.items():
                    api_doc["modules"][module_name]["classes"][class_name] = self._document_class(class_obj)
            else:
                # Single class module
                api_doc["modules"][module_name] = self._document_class(module_obj)
        
        # Write to file
        output_file = os.path.join(self.output_dir, "api_documentation.json")
        with open(output_file, 'w') as f:
            json.dump(api_doc, f, indent=2)
        
        return output_file
    
    def _document_class(self, cls) -> Dict[str, Any]:
        """Document a class including its methods and attributes"""
        doc = {
            "name": cls.__name__,
            "docstring": inspect.getdoc(cls) or "",
            "methods": {},
            "attributes": []
        }
        
        # Get all methods
        for name, method in inspect.getmembers(cls, predicate=inspect.isfunction):
            if not name.startswith('_') or name == "__init__":
                doc["methods"][name] = self._document_method(method)
        
        # Try to get attributes from a sample instance or class variables
        try:
            # This is a simplistic approach and might not work for all classes
            sample_instance = cls()
            for attr in dir(sample_instance):
                if not attr.startswith('_') and not callable(getattr(sample_instance, attr)):
                    doc["attributes"].append(attr)
        except Exception:
            # If we can't instantiate, just look at class variables
            for attr in dir(cls):
                if not attr.startswith('_') and not callable(getattr(cls, attr)):
                    doc["attributes"].append(attr)
        
        return doc
    
    def _document_method(self, method) -> Dict[str, Any]:
        """Document a method including its signature and docstring"""
        doc = {
            "name": method.__name__,
            "docstring": inspect.getdoc(method) or "",
            "signature": str(inspect.signature(method)),
            "parameters": []
        }
        
        # Get parameters
        for param_name, param in inspect.signature(method).parameters.items():
            if param_name != 'self':
                param_doc = {
                    "name": param_name,
                    "default": str(param.default) if param.default is not inspect.Parameter.empty else None,
                    "annotation": str(param.annotation) if param.annotation is not inspect.Parameter.empty else None
                }
                doc["parameters"].append(param_doc)
        
        return doc
    
    def generate_user_guide(self) -> str:
        """Generate a user guide in Markdown format"""
        user_guide = """
# Red Team Automation Platform User Guide

## Introduction

The Continuous Red Team Automation Platform is designed to provide organizations with 24/7 autonomous security testing capabilities. This user guide will help you get started with the platform and explain how to use its various features.

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Network access to target systems

### Installing the Platform

1. Clone the repository or download the source code
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate a default configuration:
   ```bash
   python -m backend.red_team.main --generate-config
   ```

## Configuration

The platform can be configured through a JSON configuration file. By default, the platform looks for configuration files in the following locations:

1. `./config.json`
2. `./config/red_team_config.json`
3. `~/.infosentinel/red_team_config.json`
4. `/etc/infosentinel/red_team_config.json`

You can also specify a custom configuration file:

```bash
python -m backend.red_team.main --config /path/to/config.json
```

### Configuration Options

- **Engine Settings**: Control the automation engine behavior
  - `max_concurrent_scenarios`: Maximum number of scenarios to run concurrently
  - `default_interval_hours`: Default interval for recurring scenarios
  - `execution_timeout_minutes`: Maximum execution time for a scenario
  - `auto_start`: Whether to start the engine automatically

- **Library Settings**: Configure the scenario library
  - `storage_path`: Path to store scenario templates
  - `auto_save`: Whether to automatically save changes
  - `save_interval_minutes`: How often to save changes

- **Feedback Settings**: Configure the feedback loop
  - `analysis_threshold`: Threshold for analysis
  - `improvement_metrics`: Metrics to track for improvement
  - `learning_rate`: Rate at which to apply improvements
  - `history_retention_days`: How long to keep historical data

- **Integration Settings**: Configure integration with other components
  - `enabled`: Whether integrations are enabled
  - `ueba`, `deception`, `zero_day_hunting`: Component-specific settings

- **Reporting Settings**: Configure report generation
  - `output_dir`: Directory to store reports
  - `formats`: Report formats to generate
  - `include_mitre_mapping`: Whether to include MITRE ATT&CK mappings
  - `include_remediation`: Whether to include remediation recommendations

## Using the Command-Line Interface

The platform provides a command-line interface (CLI) for interacting with the automation engine.

### Starting the Engine

```bash
python -m backend.red_team.cli start-engine
```

### Stopping the Engine

```bash
python -m backend.red_team.cli stop-engine
```

### Running a Scenario

```bash
python -m backend.red_team.cli run-scenario --template <template_name> --target <target>
```

Example:
```bash
python -m backend.red_team.cli run-scenario --template network_penetration --target 192.168.1.0/24
```

### Scheduling a Scenario

```bash
python -m backend.red_team.cli schedule-scenario --template <template_name> --target <target> --interval <hours>
```

Example:
```bash
python -m backend.red_team.cli schedule-scenario --template web_application --target https://example.com --interval 24
```

### Canceling a Scheduled Scenario

```bash
python -m backend.red_team.cli cancel-scenario --id <scenario_id>
```

### Viewing Scenario Results

```bash
python -m backend.red_team.cli view-results --id <scenario_id>
```

### Generating a Report

```bash
python -m backend.red_team.cli generate-report --id <scenario_id> --format json,html,pdf
```

### Managing Scenario Templates

```bash
# List all templates
python -m backend.red_team.cli list-templates

# Add a new template
python -m backend.red_team.cli add-template --name <name> --type <type> --params <json_params>

# Remove a template
python -m backend.red_team.cli remove-template --id <template_id>
```

## Scenario Types

The platform supports several types of attack scenarios:

### Network Penetration

Simulates network-based attacks including port scanning, vulnerability assessment, and exploitation.

Parameters:
- `target`: Target network range (e.g., 192.168.1.0/24)
- `scan_type`: Type of scan (stealth, comprehensive, quick)
- `ports`: Ports to scan (e.g., 1-1000, 22,80,443)
- `timeout`: Scan timeout in seconds

### Web Application

Simulates web application attacks including OWASP Top 10 vulnerabilities.

Parameters:
- `target`: Target URL
- `scan_depth`: Depth of scan (quick, medium, comprehensive)
- `auth`: Authentication details (if required)
- `headers`: Custom headers
- `cookies`: Custom cookies

### Social Engineering

Simulates social engineering attacks including phishing campaigns.

Parameters:
- `target`: Target email addresses
- `campaign_type`: Type of campaign (phishing, spear_phishing, vishing)
- `template`: Email template to use
- `sender`: Sender email address
- `subject`: Email subject

## Viewing Reports

Reports are generated in the configured output directory and can be viewed using standard tools:

- JSON reports: Any text editor or JSON viewer
- HTML reports: Web browser
- PDF reports: PDF viewer

## Troubleshooting

### Common Issues

- **Engine fails to start**: Check configuration file and permissions
- **Scenario execution fails**: Check network connectivity and target availability
- **Integration errors**: Verify API endpoints and credentials

### Logging

Logs are stored in the configured log file (default: `red_team_automation.log`). You can adjust the log level in the configuration file.

### Getting Help

For additional help, contact the InfoSentinel security team.

## Security Considerations

The platform includes several security features, but you should also consider the following:

- Run the platform in a controlled environment
- Use proper authentication and authorization
- Regularly update the platform and its dependencies
- Monitor the platform's activities
- Obtain proper authorization before testing production systems
"""
        
        # Write to file
        output_file = os.path.join(self.output_dir, "user_guide.md")
        with open(output_file, 'w') as f:
            f.write(user_guide)
        
        return output_file
    
    def generate_technical_specification(self) -> str:
        """Generate a technical specification document in Markdown format"""
        tech_spec = """
# Red Team Automation Platform Technical Specification

## System Architecture

### Overview

The Continuous Red Team Automation Platform is designed as a modular system with several key components that work together to provide autonomous security testing capabilities.

### Component Diagram

```
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
| Automation Engine   |<--->| Scenario Library   |<--->| Feedback Loop      |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
          ^                           ^                           ^
          |                           |                           |
          v                           v                           v
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
| Integration Manager |<--->| Configuration      |<--->| Reporting System   |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
          ^                                                       ^
          |                                                       |
          v                                                       v
+---------------------+                               +---------------------+
|                     |                               |                     |
| External Components |                               | CLI / API           |
|                     |                               |                     |
+---------------------+                               +---------------------+
```

### Core Components

#### Automation Engine

The Automation Engine is responsible for orchestrating the execution of attack scenarios. It manages scheduling, execution, and result collection.

**Key Classes:**
- `AdvancedAutomationEngine`: Main engine class
- `ScheduledScenario`: Represents a scheduled scenario execution
- `ScenarioBuilder`: Builds scenario instances from templates

**Key Features:**
- Concurrent scenario execution
- Scheduled and on-demand execution
- Execution monitoring and timeout handling
- Result collection and processing

#### Scenario Library

The Scenario Library manages attack scenario templates and provides an interface for creating, retrieving, and managing templates.

**Key Classes:**
- `ScenarioLibrary`: Main library class
- `ScenarioTemplate`: Represents a scenario template
- `ScenarioCategory`: Organizes templates into categories

**Key Features:**
- Template storage and retrieval
- Template versioning
- Category management
- MITRE ATT&CK mapping

#### Feedback Loop

The Feedback Loop analyzes scenario execution results and provides insights for improving future executions.

**Key Classes:**
- `FeedbackLoop`: Main feedback loop class
- `FeedbackAnalyzer`: Analyzes scenario results
- `ScenarioOptimizer`: Optimizes scenarios based on feedback

**Key Features:**
- Result analysis
- Trend identification
- Scenario optimization
- Improvement tracking

#### Integration Manager

The Integration Manager handles communication with external components such as UEBA, Deception Technology, and Zero-Day Hunting systems.

**Key Classes:**
- `IntegrationManager`: Main integration manager class
- `BaseIntegration`: Base class for integrations
- `UEBAIntegration`, `DeceptionIntegration`, `ZeroDayHuntingIntegration`: Specific integrations

**Key Features:**
- Event publishing
- Event subscription
- API communication
- Authentication handling

#### Configuration Manager

The Configuration Manager handles loading, parsing, and providing access to configuration settings.

**Key Classes:**
- `ConfigManager`: Main configuration manager class

**Key Features:**
- Configuration file loading
- Environment variable support
- Default configuration
- Configuration validation

#### Reporting System

The Reporting System generates reports from scenario execution results.

**Key Classes:**
- `ReportGenerator`: Main report generator class

**Key Features:**
- Multiple output formats (JSON, HTML, PDF)
- MITRE ATT&CK mapping
- Remediation recommendations
- Finding severity classification

### Scenario Types

#### Network Penetration

**Class:** `NetworkPenetrationScenario`

**Execution Flow:**
1. Network discovery
2. Port scanning
3. Service identification
4. Vulnerability assessment
5. Exploitation simulation
6. Post-exploitation simulation
7. Result collection

#### Web Application

**Class:** `WebApplicationScenario`

**Execution Flow:**
1. Target reconnaissance
2. Surface mapping
3. Vulnerability scanning
4. Authentication testing
5. Authorization testing
6. Input validation testing
7. Business logic testing
8. Result collection

#### Social Engineering

**Class:** `SocialEngineeringScenario`

**Execution Flow:**
1. Target identification
2. Campaign preparation
3. Payload generation
4. Delivery simulation
5. User interaction simulation
6. Result collection

## Data Flow

### Scenario Execution

```
1. User/Scheduler -> Automation Engine: Execute scenario
2. Automation Engine -> Scenario Library: Get scenario template
3. Scenario Library -> Automation Engine: Return template
4. Automation Engine -> Scenario: Create and execute
5. Scenario -> External Systems: Simulate attacks
6. External Systems -> Scenario: Return results
7. Scenario -> Automation Engine: Return execution results
8. Automation Engine -> Feedback Loop: Process results
9. Feedback Loop -> Automation Engine: Return insights
10. Automation Engine -> Reporting System: Generate report
11. Reporting System -> User: Return report
```

### Integration Events

```
1. Automation Engine -> Integration Manager: Publish event
2. Integration Manager -> External Components: Forward event
3. External Components -> Integration Manager: Return response
4. Integration Manager -> Automation Engine: Forward response
```

## Security Model

### Authentication

The platform uses token-based authentication for API access. Tokens are generated and validated by the Security Manager.

### Encryption

Sensitive data is encrypted using the Fernet symmetric encryption algorithm provided by the cryptography library.

### Secure Storage

Credentials and sensitive parameters are stored in an encrypted format using the Security Manager.

### Access Control

The platform implements role-based access control for API endpoints and CLI commands.

## Performance Considerations

### Concurrency

The Automation Engine supports concurrent scenario execution with a configurable limit to prevent resource exhaustion.

### Resource Usage

Scenario execution is monitored for resource usage, and timeouts are enforced to prevent runaway processes.

### Scalability

The platform is designed to scale horizontally by distributing scenario execution across multiple nodes.

## Error Handling

### Logging

The platform uses a structured logging system with configurable levels and outputs.

### Exception Handling

Exceptions are caught, logged, and handled appropriately at each level of the system.

### Retry Mechanism

Failed operations can be retried with configurable backoff periods.

## Testing Strategy

### Unit Tests

Each component has unit tests that verify its functionality in isolation.

### Integration Tests

Integration tests verify that components work together correctly.

### System Tests

System tests verify that the entire platform functions correctly in a realistic environment.

## Deployment

### Requirements

- Python 3.8 or higher
- Required Python packages (see requirements.txt)
- Network access to target systems

### Installation

The platform can be installed from source or using pip.

### Configuration

The platform is configured using a JSON configuration file with environment variable support.

### Monitoring

The platform includes monitoring endpoints for health checks and metrics.
"""
        
        # Write to file
        output_file = os.path.join(self.output_dir, "technical_specification.md")
        with open(output_file, 'w') as f:
            f.write(tech_spec)
        
        return output_file
    
    def generate_integration_guide(self) -> str:
        """Generate an integration guide in Markdown format"""
        integration_guide = """
# Red Team Automation Platform Integration Guide

## Overview

The Continuous Red Team Automation Platform provides integration capabilities that allow it to interact with other security components in your environment. This guide explains how to integrate the platform with other systems.

## Integration Architecture

The platform uses an event-based integration model where events are published to and received from external components. The Integration Manager handles all communication with external systems.

```
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
| Red Team Automation |<--->| Integration Manager |<--->| External Components |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
```

## Supported Integrations

The platform includes built-in support for the following integrations:

### UEBA Integration

Integrates with User and Entity Behavior Analytics systems to share attack data and receive behavioral insights.

**Configuration:**
```json
{
  "integration": {
    "ueba": {
      "api_endpoint": "http://localhost:8000/api/ueba",
      "api_key": "${UEBA_API_KEY}"
    }
  }
}
```

**Events Published:**
- `scenario_executed`: When a scenario is executed
- `attack_detected`: When an attack is simulated
- `vulnerability_found`: When a vulnerability is discovered

**Events Subscribed:**
- `behavior_anomaly`: When a behavioral anomaly is detected
- `user_risk_change`: When a user's risk score changes

### Deception Technology Integration

Integrates with Deception Technology systems to share attack data and receive deception alerts.

**Configuration:**
```json
{
  "integration": {
    "deception": {
      "api_endpoint": "http://localhost:8000/api/deception",
      "api_key": "${DECEPTION_API_KEY}"
    }
  }
}
```

**Events Published:**
- `scenario_executed`: When a scenario is executed
- `attack_detected`: When an attack is simulated

**Events Subscribed:**
- `honeypot_triggered`: When a honeypot is triggered
- `decoy_accessed`: When a decoy is accessed

### Zero-Day Hunting Integration

Integrates with Zero-Day Hunting systems to share vulnerability data and receive zero-day alerts.

**Configuration:**
```json
{
  "integration": {
    "zero_day_hunting": {
      "api_endpoint": "http://localhost:8000/api/zero_day_hunting",
      "api_key": "${ZERO_DAY_HUNTING_API_KEY}"
    }
  }
}
```

**Events Published:**
- `vulnerability_found`: When a vulnerability is discovered
- `exploit_attempted`: When an exploit is attempted

**Events Subscribed:**
- `zero_day_discovered`: When a zero-day vulnerability is discovered
- `exploit_available`: When a new exploit becomes available

## Custom Integrations

You can create custom integrations by extending the `BaseIntegration` class and registering it with the Integration Manager.

### Creating a Custom Integration

```python
from backend.red_team.integration import BaseIntegration

class CustomIntegration(BaseIntegration):
    def __init__(self, config):
        super().__init__("custom", config)
        # Initialize custom integration
        
    def handle_event(self, event):
        # Handle events from the platform
        print(f"Received event: {event}")
        
    def publish_event(self, event):
        # Publish events to the external system
        print(f"Publishing event: {event}")
        
    def subscribe(self, event_type, callback):
        # Subscribe to events from the external system
        print(f"Subscribing to {event_type} events")
```

### Registering a Custom Integration

```python
from backend.red_team.integration import IntegrationManager
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create integration manager
integration_manager = IntegrationManager(config)

# Create and register custom integration
custom_integration = CustomIntegration(config.get("integration", {}).get("custom", {}))
integration_manager.register_integration("custom", custom_integration)
```

## Event Format

Events are JSON objects with the following structure:

```json
{
  "type": "event_type",
  "source": "event_source",
  "timestamp": "2023-01-01T12:00:00",
  "id": "event_id",
  "data": {
    "key1": "value1",
    "key2": "value2"
  }
}
```

### Common Event Types

- `scenario_executed`: When a scenario is executed
- `attack_detected`: When an attack is simulated
- `vulnerability_found`: When a vulnerability is discovered
- `report_generated`: When a report is generated

## API Reference

### Integration Manager

#### Publishing Events

```python
from backend.red_team.integration import IntegrationManager
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create integration manager
integration_manager = IntegrationManager(config)

# Publish an event
integration_manager.publish_event({
    "type": "scenario_executed",
    "source": "red_team_automation",
    "timestamp": "2023-01-01T12:00:00",
    "id": "event_id",
    "data": {
        "scenario_id": "scenario_id",
        "success": True,
        "findings": []
    }
})
```

#### Subscribing to Events

```python
from backend.red_team.integration import IntegrationManager
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create integration manager
integration_manager = IntegrationManager(config)

# Define callback function
def handle_event(event):
    print(f"Received event: {event}")

# Subscribe to events
integration_manager.subscribe("ueba", "behavior_anomaly", handle_event)
```

## Security Considerations

### Authentication

All API communications should use authentication. The platform supports token-based authentication for API endpoints.

### Encryption

Sensitive data should be encrypted in transit using HTTPS/TLS.

### Authorization

Ensure that the integration has appropriate permissions to access the required resources.

### Logging

All integration activities are logged for audit purposes.

## Troubleshooting

### Common Issues

- **Connection Errors**: Check network connectivity and firewall rules
- **Authentication Errors**: Verify API keys and credentials
- **Timeout Errors**: Check if the external system is responding within the expected timeframe

### Logging

Integration-related logs are stored in the configured log file with the prefix `[INTEGRATION]`.

### Testing Integrations

You can test integrations using the CLI:

```bash
python -m backend.red_team.cli test-integration --name ueba
```

## Example: SIEM Integration

### Configuration

```json
{
  "integration": {
    "siem": {
      "api_endpoint": "https://siem.example.com/api",
      "api_key": "${SIEM_API_KEY}",
      "event_types": ["scenario_executed", "attack_detected", "vulnerability_found"]
    }
  }
}
```

### Implementation

```python
from backend.red_team.integration import BaseIntegration
import requests

class SIEMIntegration(BaseIntegration):
    def __init__(self, config):
        super().__init__("siem", config)
        self.api_endpoint = config.get("api_endpoint", "")
        self.api_key = config.get("api_key", "")
        self.event_types = config.get("event_types", [])
        
    def handle_event(self, event):
        # Only forward configured event types
        if event.get("type") in self.event_types:
            self._send_to_siem(event)
    
    def _send_to_siem(self, event):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.api_endpoint}/events",
                headers=headers,
                json=event,
                timeout=10
            )
            response.raise_for_status()
            self.logger.info(f"Event sent to SIEM: {event.get('id')}")
        except Exception as e:
            self.logger.error(f"Error sending event to SIEM: {e}")
```

### Registration

```python
from backend.red_team.integration import IntegrationManager
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create integration manager
integration_manager = IntegrationManager(config)

# Create and register SIEM integration
siem_integration = SIEMIntegration(config.get("integration", {}).get("siem", {}))
integration_manager.register_integration("siem", siem_integration)
```
"""
        
        # Write to file
        output_file = os.path.join(self.output_dir, "integration_guide.md")
        with open(output_file, 'w') as f:
            f.write(integration_guide)
        
        return output_file
    
    def generate_scenario_documentation(self) -> str:
        """Generate documentation for attack scenarios in Markdown format"""
        scenario_doc = """
# Red Team Automation Platform Scenario Documentation

## Overview

The Continuous Red Team Automation Platform includes several pre-configured attack scenarios that simulate different types of security threats. This document provides detailed information about each scenario type, including parameters, execution flow, and MITRE ATT&CK mappings.

## Network Penetration Scenario

### Description

The Network Penetration Scenario simulates network-based attacks against a target network or host. It includes port scanning, vulnerability assessment, and exploitation simulation.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target | string | Yes | Target network range (e.g., 192.168.1.0/24) or host (e.g., 192.168.1.10) |
| scan_type | string | No | Type of scan: stealth, comprehensive, quick (default: stealth) |
| ports | string | No | Ports to scan (e.g., 1-1000, 22,80,443) (default: top 1000) |
| timeout | int | No | Scan timeout in seconds (default: 300) |
| max_hosts | int | No | Maximum number of hosts to scan (default: 1000) |
| exclude_hosts | string | No | Hosts to exclude from scanning (e.g., 192.168.1.5, 192.168.1.10) |
| scan_techniques | array | No | Specific scan techniques to use (e.g., SYN, ACK, FIN) |
| vulnerability_assessment | boolean | No | Whether to perform vulnerability assessment (default: true) |
| exploitation | boolean | No | Whether to simulate exploitation (default: true) |
| post_exploitation | boolean | No | Whether to simulate post-exploitation (default: false) |

### Execution Flow

1. **Network Discovery**: Identify hosts in the target network
2. **Port Scanning**: Scan for open ports on identified hosts
3. **Service Identification**: Identify services running on open ports
4. **Vulnerability Assessment**: Identify vulnerabilities in discovered services
5. **Exploitation Simulation**: Simulate exploitation of identified vulnerabilities
6. **Post-Exploitation Simulation**: Simulate post-exploitation activities
7. **Result Collection**: Collect and analyze results

### MITRE ATT&CK Mappings

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1046 | Network Service Scanning | Discovery |
| T1018 | Remote System Discovery | Discovery |
| T1082 | System Information Discovery | Discovery |
| T1016 | System Network Configuration Discovery | Discovery |
| T1049 | System Network Connections Discovery | Discovery |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1133 | External Remote Services | Initial Access |
| T1078 | Valid Accounts | Initial Access |

### Example Usage

```python
from backend.red_team.scenarios import NetworkPenetrationScenario
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create scenario
scenario = NetworkPenetrationScenario(
    name="Internal Network Scan",
    target="192.168.1.0/24",
    config=config,
    scan_type="stealth",
    ports="1-1000",
    timeout=300,
    vulnerability_assessment=True,
    exploitation=False
)

# Execute scenario
results = scenario.execute()

# Print results
print(f"Findings: {len(results.get('findings', []))}")
for finding in results.get('findings', []):
    print(f"- {finding.get('title')} ({finding.get('severity')})")
```

## Web Application Scenario

### Description

The Web Application Scenario simulates attacks against web applications, including OWASP Top 10 vulnerabilities, authentication testing, and business logic testing.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target | string | Yes | Target URL (e.g., https://example.com) |
| scan_depth | string | No | Depth of scan: quick, medium, comprehensive (default: medium) |
| auth | object | No | Authentication details (if required) |
| headers | object | No | Custom headers to include in requests |
| cookies | object | No | Custom cookies to include in requests |
| request_timeout | int | No | Request timeout in seconds (default: 30) |
| max_requests | int | No | Maximum number of requests to send (default: 1000) |
| max_requests_per_second | int | No | Maximum requests per second (default: 10) |
| follow_redirects | boolean | No | Whether to follow redirects (default: true) |
| test_xss | boolean | No | Whether to test for XSS vulnerabilities (default: true) |
| test_sqli | boolean | No | Whether to test for SQL injection vulnerabilities (default: true) |
| test_csrf | boolean | No | Whether to test for CSRF vulnerabilities (default: true) |
| test_auth | boolean | No | Whether to test authentication mechanisms (default: true) |
| test_business_logic | boolean | No | Whether to test business logic (default: true) |

### Execution Flow

1. **Target Reconnaissance**: Gather information about the target application
2. **Surface Mapping**: Identify pages, forms, and API endpoints
3. **Vulnerability Scanning**: Scan for common vulnerabilities
4. **Authentication Testing**: Test authentication mechanisms
5. **Authorization Testing**: Test authorization controls
6. **Input Validation Testing**: Test input validation controls
7. **Business Logic Testing**: Test business logic flows
8. **Result Collection**: Collect and analyze results

### MITRE ATT&CK Mappings

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1212 | Exploitation for Credential Access | Credential Access |
| T1213 | Data from Web Application | Collection |
| T1059 | Command and Scripting Interpreter | Execution |
| T1505.003 | Web Shell | Persistence |
| T1102 | Web Service | Command and Control |

### Example Usage

```python
from backend.red_team.scenarios import WebApplicationScenario
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create scenario
scenario = WebApplicationScenario(
    name="Company Website Scan",
    target="https://example.com",
    config=config,
    scan_depth="comprehensive",
    auth={
        "username": "test_user",
        "password": "test_password"
    },
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    },
    test_xss=True,
    test_sqli=True,
    test_csrf=True
)

# Execute scenario
results = scenario.execute()

# Print results
print(f"Findings: {len(results.get('findings', []))}")
for finding in results.get('findings', []):
    print(f"- {finding.get('title')} ({finding.get('severity')})")
```

## Social Engineering Scenario

### Description

The Social Engineering Scenario simulates social engineering attacks, including phishing campaigns, spear phishing, and vishing (voice phishing).

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target | string | Yes | Target email addresses or phone numbers |
| campaign_type | string | No | Type of campaign: phishing, spear_phishing, vishing (default: phishing) |
| template | string | No | Email or call template to use |
| sender | string | No | Sender email address or phone number |
| subject | string | No | Email subject (for phishing campaigns) |
| attachment | boolean | No | Whether to include an attachment (default: false) |
| attachment_type | string | No | Type of attachment: pdf, doc, xls, zip (default: pdf) |
| landing_page | string | No | URL of landing page (for phishing campaigns) |
| call_script | string | No | Call script (for vishing campaigns) |
| campaign_size | int | No | Number of targets to include (default: 10) |
| campaign_duration | int | No | Duration of campaign in hours (default: 24) |

### Execution Flow

1. **Target Identification**: Identify and validate targets
2. **Campaign Preparation**: Prepare campaign materials
3. **Payload Generation**: Generate payloads (emails, attachments, landing pages)
4. **Delivery Simulation**: Simulate delivery of payloads
5. **User Interaction Simulation**: Simulate user interactions
6. **Result Collection**: Collect and analyze results

### MITRE ATT&CK Mappings

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1566 | Phishing | Initial Access |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |
| T1566.003 | Spearphishing via Service | Initial Access |
| T1598 | Phishing for Information | Reconnaissance |
| T1598.001 | Spearphishing Service | Reconnaissance |
| T1598.002 | Spearphishing Attachment | Reconnaissance |
| T1598.003 | Spearphishing Link | Reconnaissance |

### Example Usage

```python
from backend.red_team.scenarios import SocialEngineeringScenario
from backend.red_team.config import load_config

# Load configuration
config = load_config()

# Create scenario
scenario = SocialEngineeringScenario(
    name="Password Reset Phishing Campaign",
    target="user@example.com, user2@example.com",
    config=config,
    campaign_type="phishing",
    template="password_reset",
    sender="support@example-security.com",
    subject="Urgent: Password Reset Required",
    landing_page="https://example-security.com/reset",
    campaign_size=10,
    campaign_duration=24
)

# Execute scenario
results = scenario.execute()

# Print results
print(f"Findings: {len(results.get('findings', []))}")
for finding in results.get('findings', []):
    print(f"- {finding.get('title')} ({finding.get('severity')})")
```

## Creating Custom Scenarios

### Extending the Base Scenario Class

You can create custom scenarios by extending the `AttackScenario` base class:

```python
from backend.red_team import AttackScenario

class CustomScenario(AttackScenario):
    def __init__(self, name, target, config, **kwargs):
        super().__init__(name, target, config, **kwargs)
        self.type = "custom_scenario"
        
        # Initialize scenario-specific parameters
        self.custom_param = kwargs.get("custom_param", "default_value")
        
    def execute(self):
        # Implement scenario execution logic
        self.logger.info(f"Executing {self.name} against {self.target}")
        
        # Perform custom attack simulation
        results = self._run_custom_logic()
        
        # Format and return results
        return self._format_results(results)
        
    def _run_custom_logic(self):
        # Implement custom attack logic
        findings = []
        
        # Simulate finding a vulnerability
        findings.append({
            "id": self._generate_id(),
            "title": "Custom Vulnerability",
            "severity": "medium",
            "description": "A custom vulnerability was found.",
            "remediation": "Apply custom remediation."
        })
        
        return {
            "success": True,
            "findings": findings
        }
```

### Registering Custom Scenarios

Register your custom scenario with the Scenario Builder:

```python
from backend.red_team.automation_engine import ScenarioBuilder

# Register custom scenario
ScenarioBuilder.register_scenario_class("custom_scenario", CustomScenario)

# Create scenario from template
scenario = ScenarioBuilder.build_from_template({
    "name": "Custom Scenario",
    "type": "custom_scenario",
    "target": "custom_target",
    "custom_param": "custom_value"
}, config)

# Execute scenario
results = scenario.execute()
```

### Best Practices for Custom Scenarios

1. **Follow the Base Class Interface**: Implement all required methods from the base class
2. **Proper Error Handling**: Handle exceptions and errors gracefully
3. **Comprehensive Logging**: Log all significant actions and results
4. **MITRE ATT&CK Mapping**: Map your scenario to relevant MITRE ATT&CK techniques
5. **Parameterization**: Make your scenario configurable through parameters
6. **Result Formatting**: Format results consistently with other scenarios
7. **Documentation**: Document your scenario's parameters, execution flow, and expected results
"""
        
        # Write to file
        output_file = os.path.join(self.output_dir, "scenario_documentation.md")
        with open(output_file, 'w') as f:
            f.write(scenario_doc)
        
        return output_file


def generate_documentation(output_dir: str = "docs") -> None:
    """Generate all documentation for the Red Team Automation Platform"""
    generator = DocumentationGenerator(output_dir)
    generator.generate_all_documentation()
    print(f"Documentation generated in {output_dir}")


if __name__ == "__main__":
    import sys
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "docs"
    generate_documentation(output_dir)