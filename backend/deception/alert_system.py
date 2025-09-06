#!/usr/bin/env python3
"""
Deception Technology Alert System Module

This module implements a comprehensive alert system for deception technology triggers,
including real-time monitoring, alert correlation, notification management, and
integration with SIEM/SOAR platforms.

Author: InfoSentinel AI
Version: 1.0.0
"""

import asyncio
import json
import logging
import smtplib
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Set
from urllib.parse import urljoin

import aiohttp
import requests
from jinja2 import Template


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of deception alerts"""
    HONEYPOT_INTERACTION = "honeypot_interaction"
    HONEYTOKEN_ACCESS = "honeytoken_access"
    DECOY_ENVIRONMENT_BREACH = "decoy_environment_breach"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class AlertStatus(Enum):
    """Alert status states"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class NotificationChannel(Enum):
    """Notification delivery channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SYSLOG = "syslog"
    SIEM = "siem"
    SOAR = "soar"
    SMS = "sms"


@dataclass
class AlertContext:
    """Context information for an alert"""
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_agent: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_code: Optional[int] = None
    session_id: Optional[str] = None
    geolocation: Dict[str, Any] = field(default_factory=dict)
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "user_agent": self.user_agent,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_code": self.response_code,
            "session_id": self.session_id,
            "geolocation": self.geolocation,
            "threat_intelligence": self.threat_intelligence,
            "mitre_techniques": self.mitre_techniques,
            "custom_attributes": self.custom_attributes
        }


@dataclass
class DeceptionAlert:
    """Represents a deception technology alert"""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    source_component: str  # honeypot, honeytoken, decoy_environment
    source_id: str  # ID of the specific component that triggered the alert
    context: AlertContext
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    related_alerts: List[str] = field(default_factory=list)
    investigation_notes: List[Dict[str, Any]] = field(default_factory=list)
    remediation_actions: List[Dict[str, Any]] = field(default_factory=list)
    false_positive_probability: float = 0.0
    confidence_score: float = 1.0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_component": self.source_component,
            "source_id": self.source_id,
            "context": self.context.to_dict(),
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "tags": self.tags,
            "related_alerts": self.related_alerts,
            "investigation_notes": self.investigation_notes,
            "remediation_actions": self.remediation_actions,
            "false_positive_probability": self.false_positive_probability,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeceptionAlert':
        """Create from dictionary"""
        context_data = data.get("context", {})
        context = AlertContext(
            source_ip=context_data.get("source_ip", ""),
            destination_ip=context_data.get("destination_ip", ""),
            source_port=context_data.get("source_port"),
            destination_port=context_data.get("destination_port"),
            protocol=context_data.get("protocol"),
            user_agent=context_data.get("user_agent"),
            request_method=context_data.get("request_method"),
            request_path=context_data.get("request_path"),
            request_headers=context_data.get("request_headers", {}),
            request_body=context_data.get("request_body"),
            response_code=context_data.get("response_code"),
            session_id=context_data.get("session_id"),
            geolocation=context_data.get("geolocation", {}),
            threat_intelligence=context_data.get("threat_intelligence", {}),
            mitre_techniques=context_data.get("mitre_techniques", []),
            custom_attributes=context_data.get("custom_attributes", {})
        )
        
        return cls(
            id=data["id"],
            alert_type=AlertType(data["alert_type"]),
            severity=AlertSeverity(data["severity"]),
            title=data["title"],
            description=data["description"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_component=data["source_component"],
            source_id=data["source_id"],
            context=context,
            status=AlertStatus(data.get("status", "new")),
            assigned_to=data.get("assigned_to"),
            tags=data.get("tags", []),
            related_alerts=data.get("related_alerts", []),
            investigation_notes=data.get("investigation_notes", []),
            remediation_actions=data.get("remediation_actions", []),
            false_positive_probability=data.get("false_positive_probability", 0.0),
            confidence_score=data.get("confidence_score", 1.0),
            created_at=datetime.fromisoformat(data.get("created_at", datetime.now().isoformat())),
            updated_at=datetime.fromisoformat(data.get("updated_at", datetime.now().isoformat()))
        )


@dataclass
class NotificationConfig:
    """Configuration for notification channels"""
    channel: NotificationChannel
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    severity_filter: List[AlertSeverity] = field(default_factory=lambda: list(AlertSeverity))
    alert_type_filter: List[AlertType] = field(default_factory=lambda: list(AlertType))
    rate_limit: Optional[int] = None  # Max notifications per hour
    template: Optional[str] = None


@dataclass
class AlertRule:
    """Rule for alert correlation and enrichment"""
    id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: List[Dict[str, Any]]
    enabled: bool = True
    priority: int = 0
    cooldown_period: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    last_triggered: Optional[datetime] = None


class AlertCorrelationEngine:
    """Engine for correlating related alerts"""
    
    def __init__(self):
        self.logger = logging.getLogger("alert_correlation")
        self.correlation_rules = []
        self.time_window = timedelta(minutes=30)
        self.ip_correlation_threshold = 3
        self.session_correlation_enabled = True
    
    def correlate_alerts(self, new_alert: DeceptionAlert, 
                        existing_alerts: List[DeceptionAlert]) -> List[str]:
        """Find related alerts based on correlation rules"""
        related_alert_ids = []
        
        # Time-based correlation window
        window_start = new_alert.timestamp - self.time_window
        window_alerts = [
            alert for alert in existing_alerts 
            if window_start <= alert.timestamp <= new_alert.timestamp
        ]
        
        # IP-based correlation
        ip_related = self._correlate_by_ip(new_alert, window_alerts)
        related_alert_ids.extend(ip_related)
        
        # Session-based correlation
        if self.session_correlation_enabled:
            session_related = self._correlate_by_session(new_alert, window_alerts)
            related_alert_ids.extend(session_related)
        
        # Attack pattern correlation
        pattern_related = self._correlate_by_attack_pattern(new_alert, window_alerts)
        related_alert_ids.extend(pattern_related)
        
        # Remove duplicates
        return list(set(related_alert_ids))
    
    def _correlate_by_ip(self, new_alert: DeceptionAlert, 
                        alerts: List[DeceptionAlert]) -> List[str]:
        """Correlate alerts by source IP address"""
        related = []
        source_ip = new_alert.context.source_ip
        
        for alert in alerts:
            if alert.context.source_ip == source_ip and alert.id != new_alert.id:
                related.append(alert.id)
        
        return related
    
    def _correlate_by_session(self, new_alert: DeceptionAlert, 
                             alerts: List[DeceptionAlert]) -> List[str]:
        """Correlate alerts by session ID"""
        related = []
        session_id = new_alert.context.session_id
        
        if not session_id:
            return related
        
        for alert in alerts:
            if (alert.context.session_id == session_id and 
                alert.id != new_alert.id):
                related.append(alert.id)
        
        return related
    
    def _correlate_by_attack_pattern(self, new_alert: DeceptionAlert, 
                                   alerts: List[DeceptionAlert]) -> List[str]:
        """Correlate alerts by MITRE ATT&CK patterns"""
        related = []
        new_techniques = set(new_alert.context.mitre_techniques)
        
        if not new_techniques:
            return related
        
        for alert in alerts:
            alert_techniques = set(alert.context.mitre_techniques)
            if (alert_techniques.intersection(new_techniques) and 
                alert.id != new_alert.id):
                related.append(alert.id)
        
        return related


class NotificationManager:
    """Manages alert notifications across multiple channels"""
    
    def __init__(self):
        self.logger = logging.getLogger("notification_manager")
        self.notification_configs: Dict[str, NotificationConfig] = {}
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.templates = self._load_default_templates()
    
    def add_notification_config(self, name: str, config: NotificationConfig):
        """Add a notification configuration"""
        self.notification_configs[name] = config
        self.logger.info(f"Added notification config: {name}")
    
    async def send_alert_notification(self, alert: DeceptionAlert) -> Dict[str, bool]:
        """Send alert notification through configured channels"""
        results = {}
        
        for name, config in self.notification_configs.items():
            if not config.enabled:
                continue
            
            # Check severity filter
            if alert.severity not in config.severity_filter:
                continue
            
            # Check alert type filter
            if alert.alert_type not in config.alert_type_filter:
                continue
            
            # Check rate limit
            if not self._check_rate_limit(name, config):
                self.logger.warning(f"Rate limit exceeded for {name}")
                results[name] = False
                continue
            
            try:
                success = await self._send_notification(alert, config)
                results[name] = success
                
                if success:
                    self._update_rate_limit(name)
                    
            except Exception as e:
                self.logger.error(f"Failed to send notification via {name}: {str(e)}")
                results[name] = False
        
        return results
    
    def _check_rate_limit(self, config_name: str, config: NotificationConfig) -> bool:
        """Check if rate limit allows sending notification"""
        if not config.rate_limit:
            return True
        
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        # Clean old entries
        if config_name in self.rate_limits:
            self.rate_limits[config_name] = [
                ts for ts in self.rate_limits[config_name] if ts > hour_ago
            ]
        else:
            self.rate_limits[config_name] = []
        
        return len(self.rate_limits[config_name]) < config.rate_limit
    
    def _update_rate_limit(self, config_name: str):
        """Update rate limit counter"""
        if config_name not in self.rate_limits:
            self.rate_limits[config_name] = []
        
        self.rate_limits[config_name].append(datetime.now())
    
    async def _send_notification(self, alert: DeceptionAlert, 
                               config: NotificationConfig) -> bool:
        """Send notification through specific channel"""
        if config.channel == NotificationChannel.EMAIL:
            return await self._send_email_notification(alert, config)
        elif config.channel == NotificationChannel.SLACK:
            return await self._send_slack_notification(alert, config)
        elif config.channel == NotificationChannel.TEAMS:
            return await self._send_teams_notification(alert, config)
        elif config.channel == NotificationChannel.WEBHOOK:
            return await self._send_webhook_notification(alert, config)
        elif config.channel == NotificationChannel.SIEM:
            return await self._send_siem_notification(alert, config)
        else:
            self.logger.warning(f"Unsupported notification channel: {config.channel}")
            return False
    
    async def _send_email_notification(self, alert: DeceptionAlert, 
                                     config: NotificationConfig) -> bool:
        """Send email notification"""
        try:
            smtp_server = config.config.get("smtp_server", "localhost")
            smtp_port = config.config.get("smtp_port", 587)
            username = config.config.get("username")
            password = config.config.get("password")
            from_email = config.config.get("from_email")
            to_emails = config.config.get("to_emails", [])
            
            if not to_emails:
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ", ".join(to_emails)
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            # Generate email body
            template = self.templates.get("email", self.templates["default"])
            body = template.render(alert=alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")
            return False
    
    async def _send_slack_notification(self, alert: DeceptionAlert, 
                                     config: NotificationConfig) -> bool:
        """Send Slack notification"""
        try:
            webhook_url = config.config.get("webhook_url")
            if not webhook_url:
                return False
            
            # Create Slack message
            color_map = {
                AlertSeverity.LOW: "good",
                AlertSeverity.MEDIUM: "warning", 
                AlertSeverity.HIGH: "danger",
                AlertSeverity.CRITICAL: "danger"
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(alert.severity, "warning"),
                    "title": alert.title,
                    "text": alert.description,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "Source IP", "value": alert.context.source_ip, "short": True},
                        {"title": "Component", "value": alert.source_component, "short": True},
                        {"title": "Timestamp", "value": alert.timestamp.isoformat(), "short": True}
                    ],
                    "footer": "InfoSentinel Deception Technology",
                    "ts": int(alert.timestamp.timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {str(e)}")
            return False
    
    async def _send_teams_notification(self, alert: DeceptionAlert, 
                                     config: NotificationConfig) -> bool:
        """Send Microsoft Teams notification"""
        try:
            webhook_url = config.config.get("webhook_url")
            if not webhook_url:
                return False
            
            # Create Teams message
            color_map = {
                AlertSeverity.LOW: "00FF00",
                AlertSeverity.MEDIUM: "FFFF00", 
                AlertSeverity.HIGH: "FF8000",
                AlertSeverity.CRITICAL: "FF0000"
            }
            
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color_map.get(alert.severity, "FFFF00"),
                "summary": alert.title,
                "sections": [{
                    "activityTitle": alert.title,
                    "activitySubtitle": f"Severity: {alert.severity.value.upper()}",
                    "text": alert.description,
                    "facts": [
                        {"name": "Source IP", "value": alert.context.source_ip},
                        {"name": "Component", "value": alert.source_component},
                        {"name": "Timestamp", "value": alert.timestamp.isoformat()}
                    ]
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Failed to send Teams notification: {str(e)}")
            return False
    
    async def _send_webhook_notification(self, alert: DeceptionAlert, 
                                       config: NotificationConfig) -> bool:
        """Send webhook notification"""
        try:
            webhook_url = config.config.get("url")
            headers = config.config.get("headers", {})
            
            if not webhook_url:
                return False
            
            payload = alert.to_dict()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    return 200 <= response.status < 300
                    
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {str(e)}")
            return False
    
    async def _send_siem_notification(self, alert: DeceptionAlert, 
                                    config: NotificationConfig) -> bool:
        """Send SIEM notification"""
        try:
            siem_url = config.config.get("url")
            api_key = config.config.get("api_key")
            
            if not siem_url or not api_key:
                return False
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Format for SIEM ingestion
            siem_payload = {
                "timestamp": alert.timestamp.isoformat(),
                "event_type": "deception_alert",
                "severity": alert.severity.value,
                "alert_type": alert.alert_type.value,
                "source_ip": alert.context.source_ip,
                "destination_ip": alert.context.destination_ip,
                "description": alert.description,
                "mitre_techniques": alert.context.mitre_techniques,
                "raw_alert": alert.to_dict()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(siem_url, json=siem_payload, headers=headers) as response:
                    return 200 <= response.status < 300
                    
        except Exception as e:
            self.logger.error(f"Failed to send SIEM notification: {str(e)}")
            return False
    
    def _load_default_templates(self) -> Dict[str, Template]:
        """Load default notification templates"""
        templates = {}
        
        # Default template
        default_template = Template("""
        <h2>Deception Technology Alert</h2>
        <p><strong>Title:</strong> {{ alert.title }}</p>
        <p><strong>Severity:</strong> {{ alert.severity.value.upper() }}</p>
        <p><strong>Description:</strong> {{ alert.description }}</p>
        <p><strong>Source IP:</strong> {{ alert.context.source_ip }}</p>
        <p><strong>Timestamp:</strong> {{ alert.timestamp.isoformat() }}</p>
        """)
        templates["default"] = default_template
        templates["email"] = default_template
        
        return templates


class DeceptionAlertSystem:
    """Main deception technology alert system"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger("deception_alert_system")
        self.config_path = config_path
        
        # Core components
        self.alerts: Dict[str, DeceptionAlert] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.correlation_engine = AlertCorrelationEngine()
        self.notification_manager = NotificationManager()
        
        # Event handlers
        self.alert_handlers: List[Callable[[DeceptionAlert], None]] = []
        
        # Load state if available
        if config_path:
            self.load_state()
    
    def create_alert(self, alert_type: AlertType, severity: AlertSeverity,
                    title: str, description: str, source_component: str,
                    source_id: str, context: AlertContext) -> str:
        """Create a new deception alert"""
        alert_id = str(uuid.uuid4())
        
        alert = DeceptionAlert(
            id=alert_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now(),
            source_component=source_component,
            source_id=source_id,
            context=context
        )
        
        # Correlate with existing alerts
        related_alerts = self.correlation_engine.correlate_alerts(
            alert, list(self.alerts.values())
        )
        alert.related_alerts = related_alerts
        
        # Update related alerts
        for related_id in related_alerts:
            if related_id in self.alerts:
                self.alerts[related_id].related_alerts.append(alert_id)
        
        # Store alert
        self.alerts[alert_id] = alert
        
        # Process alert rules
        self._process_alert_rules(alert)
        
        # Send notifications
        asyncio.create_task(self.notification_manager.send_alert_notification(alert))
        
        # Call event handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Error in alert handler: {str(e)}")
        
        self.logger.info(f"Created alert {alert_id}: {title}")
        self.save_state()
        
        return alert_id
    
    def get_alert(self, alert_id: str) -> Optional[DeceptionAlert]:
        """Get an alert by ID"""
        return self.alerts.get(alert_id)
    
    def update_alert_status(self, alert_id: str, status: AlertStatus,
                           assigned_to: Optional[str] = None,
                           notes: Optional[str] = None) -> bool:
        """Update alert status"""
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.status = status
        alert.updated_at = datetime.now()
        
        if assigned_to is not None:
            alert.assigned_to = assigned_to
        
        if notes:
            alert.investigation_notes.append({
                "timestamp": datetime.now().isoformat(),
                "note": notes,
                "author": assigned_to or "system"
            })
        
        self.logger.info(f"Updated alert {alert_id} status to {status.value}")
        self.save_state()
        
        return True
    
    def add_remediation_action(self, alert_id: str, action: Dict[str, Any]) -> bool:
        """Add remediation action to alert"""
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        action["timestamp"] = datetime.now().isoformat()
        alert.remediation_actions.append(action)
        alert.updated_at = datetime.now()
        
        self.logger.info(f"Added remediation action to alert {alert_id}")
        self.save_state()
        
        return True
    
    def list_alerts(self, status: Optional[AlertStatus] = None,
                   severity: Optional[AlertSeverity] = None,
                   alert_type: Optional[AlertType] = None,
                   limit: int = 100) -> List[DeceptionAlert]:
        """List alerts with optional filtering"""
        alerts = list(self.alerts.values())
        
        # Apply filters
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        return alerts[:limit]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        total_alerts = len(self.alerts)
        
        if total_alerts == 0:
            return {"total_alerts": 0}
        
        # Count by status
        status_counts = {}
        for status in AlertStatus:
            status_counts[status.value] = len([
                a for a in self.alerts.values() if a.status == status
            ])
        
        # Count by severity
        severity_counts = {}
        for severity in AlertSeverity:
            severity_counts[severity.value] = len([
                a for a in self.alerts.values() if a.severity == severity
            ])
        
        # Count by type
        type_counts = {}
        for alert_type in AlertType:
            type_counts[alert_type.value] = len([
                a for a in self.alerts.values() if a.alert_type == alert_type
            ])
        
        # Recent activity (last 24 hours)
        day_ago = datetime.now() - timedelta(days=1)
        recent_alerts = len([
            a for a in self.alerts.values() if a.timestamp > day_ago
        ])
        
        return {
            "total_alerts": total_alerts,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "recent_alerts_24h": recent_alerts
        }
    
    def add_alert_handler(self, handler: Callable[[DeceptionAlert], None]):
        """Add an alert event handler"""
        self.alert_handlers.append(handler)
    
    def _process_alert_rules(self, alert: DeceptionAlert):
        """Process alert rules for automatic actions"""
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue
            
            # Check cooldown
            if (rule.last_triggered and 
                datetime.now() - rule.last_triggered < rule.cooldown_period):
                continue
            
            # Check conditions
            if self._evaluate_rule_conditions(alert, rule.conditions):
                self._execute_rule_actions(alert, rule.actions)
                rule.last_triggered = datetime.now()
    
    def _evaluate_rule_conditions(self, alert: DeceptionAlert, 
                                 conditions: Dict[str, Any]) -> bool:
        """Evaluate rule conditions against alert"""
        # Simple condition evaluation - can be extended
        for key, value in conditions.items():
            if key == "severity" and alert.severity.value != value:
                return False
            elif key == "alert_type" and alert.alert_type.value != value:
                return False
            elif key == "source_ip" and alert.context.source_ip != value:
                return False
        
        return True
    
    def _execute_rule_actions(self, alert: DeceptionAlert, 
                             actions: List[Dict[str, Any]]):
        """Execute rule actions"""
        for action in actions:
            action_type = action.get("type")
            
            if action_type == "escalate":
                alert.status = AlertStatus.ESCALATED
            elif action_type == "assign":
                alert.assigned_to = action.get("assignee")
            elif action_type == "add_tag":
                tag = action.get("tag")
                if tag and tag not in alert.tags:
                    alert.tags.append(tag)
    
    def save_state(self) -> bool:
        """Save alert system state"""
        if not self.config_path:
            return False
        
        try:
            data = {
                "alerts": {id: alert.to_dict() for id, alert in self.alerts.items()},
                "alert_rules": {id: {
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "conditions": rule.conditions,
                    "actions": rule.actions,
                    "enabled": rule.enabled,
                    "priority": rule.priority,
                    "cooldown_period": rule.cooldown_period.total_seconds(),
                    "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None
                } for id, rule in self.alert_rules.items()}
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save state: {str(e)}")
            return False
    
    def load_state(self) -> bool:
        """Load alert system state"""
        if not self.config_path or not os.path.exists(self.config_path):
            return False
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            
            # Load alerts
            self.alerts = {}
            for id, alert_data in data.get("alerts", {}).items():
                self.alerts[id] = DeceptionAlert.from_dict(alert_data)
            
            # Load alert rules
            self.alert_rules = {}
            for id, rule_data in data.get("alert_rules", {}).items():
                rule = AlertRule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    conditions=rule_data["conditions"],
                    actions=rule_data["actions"],
                    enabled=rule_data["enabled"],
                    priority=rule_data["priority"],
                    cooldown_period=timedelta(seconds=rule_data["cooldown_period"]),
                    last_triggered=datetime.fromisoformat(rule_data["last_triggered"]) if rule_data["last_triggered"] else None
                )
                self.alert_rules[id] = rule
            
            self.logger.info(f"Loaded {len(self.alerts)} alerts and {len(self.alert_rules)} rules")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load state: {str(e)}")
            return False


# Convenience functions for creating common alert types
def create_honeypot_interaction_alert(honeypot_id: str, source_ip: str,
                                    destination_ip: str, interaction_details: Dict[str, Any]) -> AlertContext:
    """Create context for honeypot interaction alert"""
    return AlertContext(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=interaction_details.get("source_port"),
        destination_port=interaction_details.get("destination_port"),
        protocol=interaction_details.get("protocol"),
        user_agent=interaction_details.get("user_agent"),
        request_method=interaction_details.get("request_method"),
        request_path=interaction_details.get("request_path"),
        custom_attributes={"honeypot_id": honeypot_id, **interaction_details}
    )


def create_honeytoken_access_alert(token_id: str, source_ip: str,
                                 access_details: Dict[str, Any]) -> AlertContext:
    """Create context for honeytoken access alert"""
    return AlertContext(
        source_ip=source_ip,
        destination_ip=access_details.get("destination_ip", ""),
        custom_attributes={"token_id": token_id, **access_details}
    )


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create alert system
    alert_system = DeceptionAlertSystem()
    
    # Configure email notifications
    email_config = NotificationConfig(
        channel=NotificationChannel.EMAIL,
        config={
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "alerts@company.com",
            "password": "app_password",
            "from_email": "alerts@company.com",
            "to_emails": ["security@company.com"]
        },
        severity_filter=[AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    )
    alert_system.notification_manager.add_notification_config("email", email_config)
    
    # Create sample alert
    context = create_honeypot_interaction_alert(
        honeypot_id="honeypot-001",
        source_ip="192.168.1.100",
        destination_ip="10.0.1.50",
        interaction_details={
            "destination_port": 22,
            "protocol": "tcp",
            "request_method": "SSH",
            "attempted_credentials": "admin:password123"
        }
    )
    
    alert_id = alert_system.create_alert(
        alert_type=AlertType.HONEYPOT_INTERACTION,
        severity=AlertSeverity.HIGH,
        title="SSH Brute Force Attempt on Honeypot",
        description="Multiple failed SSH login attempts detected on honeypot",
        source_component="honeypot",
        source_id="honeypot-001",
        context=context
    )
    
    print(f"Created alert: {alert_id}")
    print(f"Alert statistics: {alert_system.get_alert_statistics()}")