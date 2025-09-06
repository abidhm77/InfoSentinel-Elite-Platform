#!/usr/bin/env python3
"""
Ticketing System Integration Module for InfoSentinel Enterprise.
Provides integration with Jira, ServiceNow, and other ticketing systems.
"""
import json
import logging
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import base64
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class TicketingSystem(Enum):
    """Supported ticketing systems."""
    JIRA = "jira"
    SERVICENOW = "servicenow"
    REMEDY = "remedy"
    FRESHSERVICE = "freshservice"
    ZENDESK = "zendesk"
    GITHUB_ISSUES = "github_issues"
    GITLAB_ISSUES = "gitlab_issues"
    CUSTOM = "custom"

class TicketPriority(Enum):
    """Ticket priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class TicketStatus(Enum):
    """Ticket status types."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"
    CANCELLED = "cancelled"

class TicketType(Enum):
    """Ticket types."""
    VULNERABILITY = "vulnerability"
    INCIDENT = "incident"
    CHANGE_REQUEST = "change_request"
    PROBLEM = "problem"
    SERVICE_REQUEST = "service_request"
    TASK = "task"

@dataclass
class TicketData:
    """Ticket data structure."""
    title: str
    description: str
    ticket_type: TicketType
    priority: TicketPriority
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    project_key: Optional[str] = None
    labels: Optional[List[str]] = None
    custom_fields: Optional[Dict] = None
    due_date: Optional[datetime] = None
    vulnerability_id: Optional[str] = None
    scan_id: Optional[str] = None
    asset_id: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_ids: Optional[List[str]] = None

@dataclass
class TicketingConfig:
    """Ticketing system configuration."""
    system_type: TicketingSystem
    name: str
    base_url: str
    username: str
    password: Optional[str] = None
    api_token: Optional[str] = None
    project_key: Optional[str] = None
    default_assignee: Optional[str] = None
    ssl_verify: bool = True
    timeout: int = 30
    custom_headers: Optional[Dict] = None
    field_mappings: Optional[Dict] = None

@dataclass
class TicketResponse:
    """Ticket creation/update response."""
    success: bool
    ticket_id: Optional[str] = None
    ticket_key: Optional[str] = None
    ticket_url: Optional[str] = None
    error_message: Optional[str] = None
    raw_response: Optional[Dict] = None

class BaseTicketingIntegration(ABC):
    """Base class for ticketing system integrations."""
    
    def __init__(self, config: TicketingConfig):
        self.config = config
        self.session = None
    
    @abstractmethod
    async def create_ticket(self, ticket_data: TicketData) -> TicketResponse:
        """Create a new ticket."""
        pass
    
    @abstractmethod
    async def update_ticket(self, ticket_id: str, updates: Dict) -> TicketResponse:
        """Update an existing ticket."""
        pass
    
    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> Optional[Dict]:
        """Get ticket details."""
        pass
    
    @abstractmethod
    async def add_comment(self, ticket_id: str, comment: str, is_internal: bool = False) -> bool:
        """Add comment to ticket."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Dict:
        """Test connection to ticketing system."""
        pass
    
    def _get_auth_headers(self) -> Dict:
        """Get authentication headers."""
        headers = {'Content-Type': 'application/json'}
        
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
        
        if self.config.api_token:
            if self.config.system_type == TicketingSystem.JIRA:
                # Jira uses email:token for basic auth with API tokens
                auth_string = f"{self.config.username}:{self.config.api_token}"
                encoded_auth = base64.b64encode(auth_string.encode()).decode()
                headers['Authorization'] = f'Basic {encoded_auth}'
            elif self.config.system_type == TicketingSystem.SERVICENOW:
                headers['Authorization'] = f'Bearer {self.config.api_token}'
            else:
                headers['Authorization'] = f'Bearer {self.config.api_token}'
        elif self.config.username and self.config.password:
            auth_string = f"{self.config.username}:{self.config.password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            headers['Authorization'] = f'Basic {encoded_auth}'
        
        return headers

class JiraIntegration(BaseTicketingIntegration):
    """Jira ticketing system integration."""
    
    def __init__(self, config: TicketingConfig):
        super().__init__(config)
        self.api_base = urljoin(config.base_url, '/rest/api/2/')
    
    async def create_ticket(self, ticket_data: TicketData) -> TicketResponse:
        """Create a new Jira issue."""
        try:
            # Map ticket type to Jira issue type
            issue_type_mapping = {
                TicketType.VULNERABILITY: 'Bug',
                TicketType.INCIDENT: 'Bug',
                TicketType.CHANGE_REQUEST: 'Story',
                TicketType.PROBLEM: 'Bug',
                TicketType.SERVICE_REQUEST: 'Task',
                TicketType.TASK: 'Task'
            }
            
            # Map priority
            priority_mapping = {
                TicketPriority.CRITICAL: 'Highest',
                TicketPriority.HIGH: 'High',
                TicketPriority.MEDIUM: 'Medium',
                TicketPriority.LOW: 'Low'
            }
            
            # Build Jira issue payload
            issue_payload = {
                'fields': {
                    'project': {
                        'key': ticket_data.project_key or self.config.project_key
                    },
                    'summary': ticket_data.title,
                    'description': ticket_data.description,
                    'issuetype': {
                        'name': issue_type_mapping.get(ticket_data.ticket_type, 'Task')
                    },
                    'priority': {
                        'name': priority_mapping.get(ticket_data.priority, 'Medium')
                    }
                }
            }
            
            # Add assignee if specified
            if ticket_data.assignee:
                issue_payload['fields']['assignee'] = {'name': ticket_data.assignee}
            elif self.config.default_assignee:
                issue_payload['fields']['assignee'] = {'name': self.config.default_assignee}
            
            # Add reporter if specified
            if ticket_data.reporter:
                issue_payload['fields']['reporter'] = {'name': ticket_data.reporter}
            
            # Add labels
            if ticket_data.labels:
                issue_payload['fields']['labels'] = ticket_data.labels
            
            # Add due date
            if ticket_data.due_date:
                issue_payload['fields']['duedate'] = ticket_data.due_date.strftime('%Y-%m-%d')
            
            # Add custom fields
            if ticket_data.custom_fields:
                for field_key, field_value in ticket_data.custom_fields.items():
                    issue_payload['fields'][field_key] = field_value
            
            # Add vulnerability-specific fields
            if ticket_data.vulnerability_id:
                if 'labels' not in issue_payload['fields']:
                    issue_payload['fields']['labels'] = []
                issue_payload['fields']['labels'].append(f'vulnerability-{ticket_data.vulnerability_id}')
            
            if ticket_data.cve_ids:
                if 'labels' not in issue_payload['fields']:
                    issue_payload['fields']['labels'] = []
                issue_payload['fields']['labels'].extend([f'cve-{cve}' for cve in ticket_data.cve_ids])
            
            # Create the issue
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    urljoin(self.api_base, 'issue'),
                    json=issue_payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        ticket_key = result.get('key')
                        ticket_url = urljoin(self.config.base_url, f'/browse/{ticket_key}')
                        
                        logger.info(f"Created Jira issue: {ticket_key}")
                        
                        return TicketResponse(
                            success=True,
                            ticket_id=result.get('id'),
                            ticket_key=ticket_key,
                            ticket_url=ticket_url,
                            raw_response=result
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to create Jira issue: {response.status} - {error_text}")
                        
                        return TicketResponse(
                            success=False,
                            error_message=f"HTTP {response.status}: {error_text}"
                        )
        
        except Exception as e:
            logger.error(f"Error creating Jira issue: {str(e)}")
            return TicketResponse(
                success=False,
                error_message=str(e)
            )
    
    async def update_ticket(self, ticket_id: str, updates: Dict) -> TicketResponse:
        """Update a Jira issue."""
        try:
            # Build update payload
            update_payload = {'fields': {}}
            
            # Map common updates
            if 'status' in updates:
                # Status updates require transitions in Jira
                return await self._transition_issue(ticket_id, updates['status'])
            
            if 'assignee' in updates:
                update_payload['fields']['assignee'] = {'name': updates['assignee']}
            
            if 'priority' in updates:
                priority_mapping = {
                    'critical': 'Highest',
                    'high': 'High',
                    'medium': 'Medium',
                    'low': 'Low'
                }
                update_payload['fields']['priority'] = {
                    'name': priority_mapping.get(updates['priority'], 'Medium')
                }
            
            if 'description' in updates:
                update_payload['fields']['description'] = updates['description']
            
            if 'summary' in updates:
                update_payload['fields']['summary'] = updates['summary']
            
            # Update the issue
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    urljoin(self.api_base, f'issue/{ticket_id}'),
                    json=update_payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 204:
                        logger.info(f"Updated Jira issue: {ticket_id}")
                        
                        return TicketResponse(
                            success=True,
                            ticket_id=ticket_id
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to update Jira issue: {response.status} - {error_text}")
                        
                        return TicketResponse(
                            success=False,
                            error_message=f"HTTP {response.status}: {error_text}"
                        )
        
        except Exception as e:
            logger.error(f"Error updating Jira issue: {str(e)}")
            return TicketResponse(
                success=False,
                error_message=str(e)
            )
    
    async def _transition_issue(self, ticket_id: str, new_status: str) -> TicketResponse:
        """Transition Jira issue to new status."""
        try:
            # Get available transitions
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    urljoin(self.api_base, f'issue/{ticket_id}/transitions'),
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        transitions_data = await response.json()
                        transitions = transitions_data.get('transitions', [])
                        
                        # Find matching transition
                        target_transition = None
                        status_mapping = {
                            'open': ['To Do', 'Open', 'New'],
                            'in_progress': ['In Progress', 'In Development'],
                            'resolved': ['Done', 'Resolved', 'Closed'],
                            'closed': ['Done', 'Resolved', 'Closed']
                        }
                        
                        target_statuses = status_mapping.get(new_status, [new_status])
                        
                        for transition in transitions:
                            to_status = transition.get('to', {}).get('name', '')
                            if to_status in target_statuses:
                                target_transition = transition
                                break
                        
                        if target_transition:
                            # Execute transition
                            transition_payload = {
                                'transition': {
                                    'id': target_transition['id']
                                }
                            }
                            
                            async with session.post(
                                urljoin(self.api_base, f'issue/{ticket_id}/transitions'),
                                json=transition_payload,
                                headers=headers,
                                ssl=self.config.ssl_verify,
                                timeout=self.config.timeout
                            ) as transition_response:
                                if transition_response.status == 204:
                                    return TicketResponse(
                                        success=True,
                                        ticket_id=ticket_id
                                    )
                                else:
                                    error_text = await transition_response.text()
                                    return TicketResponse(
                                        success=False,
                                        error_message=f"Transition failed: {error_text}"
                                    )
                        else:
                            return TicketResponse(
                                success=False,
                                error_message=f"No valid transition found for status: {new_status}"
                            )
        
        except Exception as e:
            return TicketResponse(
                success=False,
                error_message=str(e)
            )
    
    async def get_ticket(self, ticket_id: str) -> Optional[Dict]:
        """Get Jira issue details."""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    urljoin(self.api_base, f'issue/{ticket_id}'),
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Failed to get Jira issue {ticket_id}: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Error getting Jira issue: {str(e)}")
            return None
    
    async def add_comment(self, ticket_id: str, comment: str, is_internal: bool = False) -> bool:
        """Add comment to Jira issue."""
        try:
            comment_payload = {
                'body': comment
            }
            
            # Add visibility restriction for internal comments
            if is_internal:
                comment_payload['visibility'] = {
                    'type': 'role',
                    'value': 'Developers'  # Adjust role as needed
                }
            
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    urljoin(self.api_base, f'issue/{ticket_id}/comment'),
                    json=comment_payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 201:
                        logger.info(f"Added comment to Jira issue: {ticket_id}")
                        return True
                    else:
                        logger.error(f"Failed to add comment to Jira issue: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Error adding comment to Jira issue: {str(e)}")
            return False
    
    async def test_connection(self) -> Dict:
        """Test Jira connection."""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    urljoin(self.api_base, 'myself'),
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        user_info = await response.json()
                        return {
                            'success': True,
                            'message': 'Successfully connected to Jira',
                            'user': user_info.get('displayName'),
                            'email': user_info.get('emailAddress')
                        }
                    else:
                        return {
                            'success': False,
                            'message': f'Failed to connect to Jira: HTTP {response.status}'
                        }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Connection test failed: {str(e)}'
            }

class ServiceNowIntegration(BaseTicketingIntegration):
    """ServiceNow ticketing system integration."""
    
    def __init__(self, config: TicketingConfig):
        super().__init__(config)
        self.api_base = urljoin(config.base_url, '/api/now/table/')
    
    async def create_ticket(self, ticket_data: TicketData) -> TicketResponse:
        """Create a new ServiceNow incident/task."""
        try:
            # Determine table based on ticket type
            table_mapping = {
                TicketType.VULNERABILITY: 'incident',
                TicketType.INCIDENT: 'incident',
                TicketType.CHANGE_REQUEST: 'change_request',
                TicketType.PROBLEM: 'problem',
                TicketType.SERVICE_REQUEST: 'sc_request',
                TicketType.TASK: 'sc_task'
            }
            
            table_name = table_mapping.get(ticket_data.ticket_type, 'incident')
            
            # Map priority
            priority_mapping = {
                TicketPriority.CRITICAL: '1',
                TicketPriority.HIGH: '2',
                TicketPriority.MEDIUM: '3',
                TicketPriority.LOW: '4'
            }
            
            # Build ServiceNow payload
            payload = {
                'short_description': ticket_data.title,
                'description': ticket_data.description,
                'priority': priority_mapping.get(ticket_data.priority, '3'),
                'state': '1'  # New
            }
            
            # Add assignee if specified
            if ticket_data.assignee:
                payload['assigned_to'] = ticket_data.assignee
            elif self.config.default_assignee:
                payload['assigned_to'] = self.config.default_assignee
            
            # Add caller/reporter
            if ticket_data.reporter:
                payload['caller_id'] = ticket_data.reporter
            
            # Add custom fields
            if ticket_data.custom_fields:
                payload.update(ticket_data.custom_fields)
            
            # Add vulnerability-specific fields
            if ticket_data.vulnerability_id:
                payload['u_vulnerability_id'] = ticket_data.vulnerability_id
            
            if ticket_data.cvss_score:
                payload['u_cvss_score'] = str(ticket_data.cvss_score)
            
            if ticket_data.cve_ids:
                payload['u_cve_ids'] = ', '.join(ticket_data.cve_ids)
            
            # Create the record
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    urljoin(self.api_base, table_name),
                    json=payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        record = result.get('result', {})
                        ticket_id = record.get('sys_id')
                        ticket_number = record.get('number')
                        ticket_url = urljoin(self.config.base_url, f'/{table_name}.do?sys_id={ticket_id}')
                        
                        logger.info(f"Created ServiceNow {table_name}: {ticket_number}")
                        
                        return TicketResponse(
                            success=True,
                            ticket_id=ticket_id,
                            ticket_key=ticket_number,
                            ticket_url=ticket_url,
                            raw_response=result
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to create ServiceNow {table_name}: {response.status} - {error_text}")
                        
                        return TicketResponse(
                            success=False,
                            error_message=f"HTTP {response.status}: {error_text}"
                        )
        
        except Exception as e:
            logger.error(f"Error creating ServiceNow ticket: {str(e)}")
            return TicketResponse(
                success=False,
                error_message=str(e)
            )
    
    async def update_ticket(self, ticket_id: str, updates: Dict) -> TicketResponse:
        """Update a ServiceNow record."""
        try:
            # Build update payload
            payload = {}
            
            # Map common updates
            if 'status' in updates:
                status_mapping = {
                    'open': '1',
                    'in_progress': '2',
                    'pending': '3',
                    'resolved': '6',
                    'closed': '7'
                }
                payload['state'] = status_mapping.get(updates['status'], '1')
            
            if 'assignee' in updates:
                payload['assigned_to'] = updates['assignee']
            
            if 'priority' in updates:
                priority_mapping = {
                    'critical': '1',
                    'high': '2',
                    'medium': '3',
                    'low': '4'
                }
                payload['priority'] = priority_mapping.get(updates['priority'], '3')
            
            if 'description' in updates:
                payload['description'] = updates['description']
            
            if 'summary' in updates:
                payload['short_description'] = updates['summary']
            
            # Update the record
            headers = self._get_auth_headers()
            
            # Assume incident table for updates (could be made configurable)
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    urljoin(self.api_base, f'incident/{ticket_id}'),
                    json=payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        logger.info(f"Updated ServiceNow record: {ticket_id}")
                        
                        return TicketResponse(
                            success=True,
                            ticket_id=ticket_id
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to update ServiceNow record: {response.status} - {error_text}")
                        
                        return TicketResponse(
                            success=False,
                            error_message=f"HTTP {response.status}: {error_text}"
                        )
        
        except Exception as e:
            logger.error(f"Error updating ServiceNow record: {str(e)}")
            return TicketResponse(
                success=False,
                error_message=str(e)
            )
    
    async def get_ticket(self, ticket_id: str) -> Optional[Dict]:
        """Get ServiceNow record details."""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    urljoin(self.api_base, f'incident/{ticket_id}'),
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('result', {})
                    else:
                        logger.error(f"Failed to get ServiceNow record {ticket_id}: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Error getting ServiceNow record: {str(e)}")
            return None
    
    async def add_comment(self, ticket_id: str, comment: str, is_internal: bool = False) -> bool:
        """Add comment to ServiceNow record."""
        try:
            # ServiceNow uses work notes for internal comments and comments for external
            field_name = 'work_notes' if is_internal else 'comments'
            
            payload = {
                field_name: comment
            }
            
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    urljoin(self.api_base, f'incident/{ticket_id}'),
                    json=payload,
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        logger.info(f"Added comment to ServiceNow record: {ticket_id}")
                        return True
                    else:
                        logger.error(f"Failed to add comment to ServiceNow record: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Error adding comment to ServiceNow record: {str(e)}")
            return False
    
    async def test_connection(self) -> Dict:
        """Test ServiceNow connection."""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    urljoin(self.api_base, 'sys_user?sysparm_limit=1'),
                    headers=headers,
                    ssl=self.config.ssl_verify,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        return {
                            'success': True,
                            'message': 'Successfully connected to ServiceNow'
                        }
                    else:
                        return {
                            'success': False,
                            'message': f'Failed to connect to ServiceNow: HTTP {response.status}'
                        }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Connection test failed: {str(e)}'
            }

class TicketingIntegrationManager:
    """Manager for ticketing system integrations."""
    
    def __init__(self):
        self.integrations = {}
        self.default_integration = None
    
    def register_integration(self, name: str, integration: BaseTicketingIntegration, is_default: bool = False):
        """Register a ticketing integration."""
        self.integrations[name] = integration
        
        if is_default or not self.default_integration:
            self.default_integration = name
        
        logger.info(f"Registered ticketing integration: {name}")
    
    def create_integration(self, config: TicketingConfig) -> BaseTicketingIntegration:
        """Create ticketing integration based on type."""
        if config.system_type == TicketingSystem.JIRA:
            return JiraIntegration(config)
        elif config.system_type == TicketingSystem.SERVICENOW:
            return ServiceNowIntegration(config)
        else:
            raise ValueError(f"Unsupported ticketing system: {config.system_type}")
    
    async def create_vulnerability_ticket(self, vulnerability: Dict, integration_name: str = None) -> TicketResponse:
        """Create ticket for vulnerability."""
        integration = self.integrations.get(integration_name or self.default_integration)
        
        if not integration:
            return TicketResponse(
                success=False,
                error_message="No ticketing integration available"
            )
        
        # Map vulnerability severity to ticket priority
        severity_to_priority = {
            'critical': TicketPriority.CRITICAL,
            'high': TicketPriority.HIGH,
            'medium': TicketPriority.MEDIUM,
            'low': TicketPriority.LOW
        }
        
        priority = severity_to_priority.get(vulnerability.get('severity', 'medium'), TicketPriority.MEDIUM)
        
        # Build ticket description
        description = f"""Vulnerability Details:
        
Title: {vulnerability.get('title', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Host: {vulnerability.get('host', 'Unknown')}
Port: {vulnerability.get('port', 'Unknown')}
Service: {vulnerability.get('service', 'Unknown')}
        
Description:
{vulnerability.get('description', 'No description available')}
        
Recommendation:
{vulnerability.get('recommendation', 'No recommendation available')}
        
Vulnerability ID: {vulnerability.get('_id', 'Unknown')}
Scan ID: {vulnerability.get('scan_id', 'Unknown')}
"""
        
        # Create ticket data
        ticket_data = TicketData(
            title=f"[SECURITY] {vulnerability.get('title', 'Security Vulnerability')} - {vulnerability.get('host', 'Unknown Host')}",
            description=description,
            ticket_type=TicketType.VULNERABILITY,
            priority=priority,
            vulnerability_id=str(vulnerability.get('_id')),
            scan_id=vulnerability.get('scan_id'),
            severity=vulnerability.get('severity'),
            cvss_score=vulnerability.get('cvss_score'),
            cve_ids=vulnerability.get('cve_ids', []),
            labels=['security', 'vulnerability', vulnerability.get('severity', 'medium')]
        )
        
        return await integration.create_ticket(ticket_data)
    
    async def create_scan_completion_ticket(self, scan_data: Dict, integration_name: str = None) -> TicketResponse:
        """Create ticket for scan completion with findings."""
        integration = self.integrations.get(integration_name or self.default_integration)
        
        if not integration:
            return TicketResponse(
                success=False,
                error_message="No ticketing integration available"
            )
        
        vulnerability_count = scan_data.get('vulnerability_count', 0)
        
        # Determine priority based on findings
        if vulnerability_count > 10:
            priority = TicketPriority.HIGH
        elif vulnerability_count > 5:
            priority = TicketPriority.MEDIUM
        else:
            priority = TicketPriority.LOW
        
        # Build description
        description = f"""Security Scan Completed:
        
Target: {scan_data.get('target', 'Unknown')}
Scan Type: {scan_data.get('scan_type', 'Unknown')}
Vulnerabilities Found: {vulnerability_count}
Scan Duration: {scan_data.get('duration', 'Unknown')}
Completed: {scan_data.get('end_time', 'Unknown')}
        
Scan ID: {scan_data.get('_id', 'Unknown')}
        
Please review the scan results and address any critical or high-severity vulnerabilities.
"""
        
        ticket_data = TicketData(
            title=f"[SECURITY SCAN] Scan completed for {scan_data.get('target', 'Unknown Target')} - {vulnerability_count} vulnerabilities found",
            description=description,
            ticket_type=TicketType.TASK,
            priority=priority,
            scan_id=str(scan_data.get('_id')),
            labels=['security', 'scan', 'review']
        )
        
        return await integration.create_ticket(ticket_data)
    
    async def update_ticket_status(self, ticket_id: str, new_status: str, integration_name: str = None) -> TicketResponse:
        """Update ticket status."""
        integration = self.integrations.get(integration_name or self.default_integration)
        
        if not integration:
            return TicketResponse(
                success=False,
                error_message="No ticketing integration available"
            )
        
        return await integration.update_ticket(ticket_id, {'status': new_status})
    
    async def add_ticket_comment(self, ticket_id: str, comment: str, is_internal: bool = False, integration_name: str = None) -> bool:
        """Add comment to ticket."""
        integration = self.integrations.get(integration_name or self.default_integration)
        
        if not integration:
            return False
        
        return await integration.add_comment(ticket_id, comment, is_internal)
    
    async def test_all_integrations(self) -> Dict:
        """Test all registered ticketing integrations."""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                test_result = await integration.test_connection()
                results[name] = test_result
            except Exception as e:
                results[name] = {
                    'success': False,
                    'message': f'Test failed: {str(e)}'
                }
        
        return results
    
    def get_integration_status(self) -> Dict:
        """Get status of all integrations."""
        status = {}
        
        for name, integration in self.integrations.items():
            status[name] = {
                'type': integration.config.system_type.value,
                'base_url': integration.config.base_url,
                'project_key': integration.config.project_key,
                'default_assignee': integration.config.default_assignee
            }
        
        return {
            'integrations': status,
            'default_integration': self.default_integration,
            'total_integrations': len(self.integrations)
        }

# Global ticketing manager instance
ticketing_manager = TicketingIntegrationManager()

# Convenience functions
async def create_vulnerability_ticket(vulnerability: Dict, integration_name: str = None) -> TicketResponse:
    """Create ticket for vulnerability in configured ticketing system."""
    return await ticketing_manager.create_vulnerability_ticket(vulnerability, integration_name)

async def create_scan_completion_ticket(scan_data: Dict, integration_name: str = None) -> TicketResponse:
    """Create ticket for scan completion in configured ticketing system."""
    return await ticketing_manager.create_scan_completion_ticket(scan_data, integration_name)

async def update_ticket_status(ticket_id: str, new_status: str, integration_name: str = None) -> TicketResponse:
    """Update ticket status in configured ticketing system."""
    return await ticketing_manager.update_ticket_status(ticket_id, new_status, integration_name)

async def add_ticket_comment(ticket_id: str, comment: str, is_internal: bool = False, integration_name: str = None) -> bool:
    """Add comment to ticket in configured ticketing system."""
    return await ticketing_manager.add_ticket_comment(ticket_id, comment, is_internal, integration_name)