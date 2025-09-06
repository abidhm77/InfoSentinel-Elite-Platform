#!/usr/bin/env python3
"""
Red-Blue Team Feedback Loop System

Comprehensive feedback system that connects red team findings with blue team responses,
enabling continuous improvement of defensive capabilities through automated analysis,
prioritized remediation recommendations, and real-time defensive adaptation.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import threading
from collections import defaultdict, deque
import yaml

# Import existing components
from continuous_red_team_engine import AttackResult, RedTeamMetrics, TargetProfile
from adaptive_attack_simulator import DefenseFingerprint, SimulationContext


class AlertSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class RemediationPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    IMMEDIATE = 5


class ResponseAction(Enum):
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    UPDATE_SIGNATURES = "update_signatures"
    PATCH_VULNERABILITY = "patch_vulnerability"
    ENHANCE_MONITORING = "enhance_monitoring"
    ISOLATE_NETWORK = "isolate_network"
    RESET_CREDENTIALS = "reset_credentials"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    UPDATE_POLICIES = "update_policies"


class FeedbackStatus(Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    RECOMMENDED = "recommended"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass
class RedTeamFinding:
    """Represents a finding from red team operations"""
    finding_id: str
    attack_result: AttackResult
    severity: AlertSeverity
    attack_vector: str
    vulnerability_type: str
    affected_systems: List[str]
    impact_description: str
    evidence: Dict[str, Any]
    exploitation_complexity: float
    detection_difficulty: float
    business_impact: float
    created_at: datetime
    updated_at: datetime


@dataclass
class BlueTeamResponse:
    """Represents a blue team response to red team findings"""
    response_id: str
    finding_id: str
    response_type: ResponseAction
    priority: RemediationPriority
    description: str
    implementation_steps: List[str]
    estimated_time: int  # minutes
    required_resources: List[str]
    success_criteria: List[str]
    rollback_plan: str
    status: FeedbackStatus
    implemented_at: Optional[datetime]
    verified_at: Optional[datetime]
    effectiveness_score: float


@dataclass
class FeedbackMetrics:
    """Metrics for tracking feedback loop effectiveness"""
    total_findings: int
    responded_findings: int
    implemented_responses: int
    verified_responses: int
    avg_response_time: float
    avg_implementation_time: float
    effectiveness_score: float
    false_positive_rate: float
    recurrence_rate: float
    improvement_velocity: float


@dataclass
class DefenseImprovement:
    """Represents a specific defensive improvement"""
    improvement_id: str
    finding_id: str
    improvement_type: str
    description: str
    implementation_details: Dict[str, Any]
    effectiveness_metrics: Dict[str, float]
    lessons_learned: List[str]
    recommendations: List[str]
    created_at: datetime


class AlertPrioritizationEngine:
    """Prioritize red team findings based on risk and impact"""
    
    def __init__(self):
        self.logger = logging.getLogger("alert_prioritization")
        self.risk_matrix = self._load_risk_matrix()
        self.impact_scoring = ImpactScoringEngine()
    
    def _load_risk_matrix(self) -> Dict[str, Dict[str, int]]:
        """Load risk assessment matrix"""
        
        return {
            "critical": {"critical": 5, "high": 4, "medium": 3, "low": 2},
            "high": {"critical": 4, "high": 4, "medium": 3, "low": 2},
            "medium": {"critical": 3, "high": 3, "medium": 2, "low": 1},
            "low": {"critical": 2, "high": 2, "medium": 1, "low": 1}
        }
    
    def prioritize_finding(self, finding: RedTeamFinding) -> Tuple[AlertSeverity, RemediationPriority]:
        """Calculate severity and priority for a finding"""
        
        # Calculate risk score
        likelihood = self._calculate_likelihood(finding)
        impact = self._calculate_impact(finding)
        
        # Map to severity and priority
        severity = self._map_to_severity(likelihood, impact)
        priority = self._map_to_priority(severity, finding.business_impact)
        
        return severity, priority
    
    def _calculate_likelihood(self, finding: RedTeamFinding) -> str:
        """Calculate attack likelihood based on complexity and detection difficulty"""
        
        # Lower complexity and detection difficulty = higher likelihood
        complexity_factor = 1 - finding.exploitation_complexity
        detection_factor = 1 - finding.detection_difficulty
        
        likelihood_score = (complexity_factor + detection_factor) / 2
        
        if likelihood_score > 0.8:
            return "critical"
        elif likelihood_score > 0.6:
            return "high"
        elif likelihood_score > 0.4:
            return "medium"
        else:
            return "low"
    
    def _calculate_impact(self, finding: RedTeamFinding) -> str:
        """Calculate impact based on affected systems and business impact"""
        
        # Consider number of affected systems and business impact
        system_count = len(finding.affected_systems)
        business_factor = finding.business_impact
        
        impact_score = min(system_count / 10 + business_factor, 1.0)
        
        if impact_score > 0.8:
            return "critical"
        elif impact_score > 0.6:
            return "high"
        elif impact_score > 0.4:
            return "medium"
        else:
            return "low"
    
    def _map_to_severity(self, likelihood: str, impact: str) -> AlertSeverity:
        """Map likelihood and impact to severity"""
        
        risk_level = self.risk_matrix[likelihood][impact]
        
        severity_map = {
            5: AlertSeverity.CRITICAL,
            4: AlertSeverity.HIGH,
            3: AlertSeverity.MEDIUM,
            2: AlertSeverity.LOW,
            1: AlertSeverity.LOW
        }
        
        return severity_map[risk_level]
    
    def _map_to_priority(self, severity: AlertSeverity, business_impact: float) -> RemediationPriority:
        """Map severity and business impact to remediation priority"""
        
        # Higher business impact increases priority
        if severity == AlertSeverity.CRITICAL:
            return RemediationPriority.IMMEDIATE
        elif severity == AlertSeverity.HIGH and business_impact > 0.7:
            return RemediationPriority.CRITICAL
        elif severity == AlertSeverity.HIGH:
            return RemediationPriority.HIGH
        elif severity == AlertSeverity.MEDIUM:
            return RemediationPriority.MEDIUM
        else:
            return RemediationPriority.LOW


class ImpactScoringEngine:
    """Calculate business impact scores for findings"""
    
    def __init__(self):
        self.logger = logging.getLogger("impact_scoring")
        self.impact_weights = {
            "confidentiality": 0.3,
            "integrity": 0.3,
            "availability": 0.2,
            "compliance": 0.2
        }
    
    def calculate_business_impact(self, finding: RedTeamFinding) -> float:
        """Calculate comprehensive business impact score"""
        
        # Calculate individual impact components
        confidentiality_impact = self._calculate_confidentiality_impact(finding)
        integrity_impact = self._calculate_integrity_impact(finding)
        availability_impact = self._calculate_availability_impact(finding)
        compliance_impact = self._calculate_compliance_impact(finding)
        
        # Weighted sum
        total_impact = (
            confidentiality_impact * self.impact_weights["confidentiality"] +
            integrity_impact * self.impact_weights["integrity"] +
            availability_impact * self.impact_weights["availability"] +
            compliance_impact * self.impact_weights["compliance"]
        )
        
        return min(total_impact, 1.0)
    
    def _calculate_confidentiality_impact(self, finding: RedTeamFinding) -> float:
        """Calculate confidentiality impact"""
        
        # Check if sensitive data was accessed
        if "data_access" in finding.impact_description.lower():
            return 0.9
        elif "information_disclosure" in finding.impact_description.lower():
            return 0.7
        else:
            return 0.3
    
    def _calculate_integrity_impact(self, finding: RedTeamFinding) -> float:
        """Calculate integrity impact"""
        
        # Check if data was modified
        if "data_modification" in finding.impact_description.lower():
            return 0.9
        elif "system_compromise" in finding.impact_description.lower():
            return 0.8
        else:
            return 0.2
    
    def _calculate_availability_impact(self, finding: RedTeamFinding) -> float:
        """Calculate availability impact"""
        
        # Check if services were disrupted
        if "service_disruption" in finding.impact_description.lower():
            return 0.8
        elif "system_downtime" in finding.impact_description.lower():
            return 0.9
        else:
            return 0.1
    
    def _calculate_compliance_impact(self, finding: RedTeamFinding) -> float:
        """Calculate compliance impact"""
        
        # Check for regulatory violations
        if "pci_dss" in finding.impact_description.lower() or \
           "gdpr" in finding.impact_description.lower():
            return 0.9
        elif "sox" in finding.impact_description.lower():
            return 0.7
        else:
            return 0.2


class ResponseRecommendationEngine:
    """Generate automated response recommendations"""
    
    def __init__(self):
        self.logger = logging.getLogger("response_recommendation")
        self.response_templates = self._load_response_templates()
        self.resource_estimator = ResourceEstimationEngine()
    
    def _load_response_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load response templates for different finding types"""
        
        return {
            "buffer_overflow": {
                "response_type": ResponseAction.PATCH_VULNERABILITY,
                "implementation_steps": [
                    "Identify vulnerable software",
                    "Apply security patches",
                    "Enable stack protection",
                    "Deploy ASLR",
                    "Test applications"
                ],
                "required_resources": ["security_team", "development_team"],
                "estimated_time": 240,  # 4 hours
                "success_criteria": ["vulnerability_patched", "exploitation_blocked"]
            },
            "sql_injection": {
                "response_type": ResponseAction.UPDATE_POLICIES,
                "implementation_steps": [
                    "Review input validation",
                    "Implement parameterized queries",
                    "Deploy WAF rules",
                    "Update coding standards",
                    "Conduct code review"
                ],
                "required_resources": ["security_team", "development_team", "qa_team"],
                "estimated_time": 480,  # 8 hours
                "success_criteria": ["sql_injection_blocked", "input_validated"]
            },
            "network_intrusion": {
                "response_type": ResponseAction.ENHANCE_MONITORING,
                "implementation_steps": [
                    "Deploy network sensors",
                    "Update IDS signatures",
                    "Implement network segmentation",
                    "Enhance logging",
                    "Set up alerting"
                ],
                "required_resources": ["network_team", "security_team"],
                "estimated_time": 360,  # 6 hours
                "success_criteria": ["intrusion_detected", "network_monitored"]
            }
        }
    
    def generate_response_recommendations(self, finding: RedTeamFinding) -> List[BlueTeamResponse]:
        """Generate response recommendations for a finding"""
        
        recommendations = []
        
        # Get appropriate response template
        template_key = self._identify_template_key(finding)
        template = self.response_templates.get(template_key, self._get_default_template())
        
        # Create response recommendation
        response = BlueTeamResponse(
            response_id=str(uuid.uuid4()),
            finding_id=finding.finding_id,
            response_type=template["response_type"],
            priority=RemediationPriority.HIGH,  # Will be calculated by prioritization engine
            description=f"Automated response for {finding.vulnerability_type}",
            implementation_steps=template["implementation_steps"],
            estimated_time=template["estimated_time"],
            required_resources=template["required_resources"],
            success_criteria=template["success_criteria"],
            rollback_plan="Revert changes and restore previous configuration",
            status=FeedbackStatus.PENDING,
            implemented_at=None,
            verified_at=None,
            effectiveness_score=0.0
        )
        
        recommendations.append(response)
        
        return recommendations
    
    def _identify_template_key(self, finding: RedTeamFinding) -> str:
        """Identify the appropriate template key for a finding"""
        
        vulnerability_type = finding.vulnerability_type.lower()
        
        if "buffer" in vulnerability_type or "overflow" in vulnerability_type:
            return "buffer_overflow"
        elif "sql" in vulnerability_type or "injection" in vulnerability_type:
            return "sql_injection"
        elif "network" in vulnerability_type or "intrusion" in vulnerability_type:
            return "network_intrusion"
        else:
            return "generic"
    
    def _get_default_template(self) -> Dict[str, Any]:
        """Get default response template"""
        
        return {
            "response_type": ResponseAction.ENHANCE_MONITORING,
            "implementation_steps": [
                "Analyze the finding",
                "Implement appropriate countermeasures",
                "Monitor for effectiveness",
                "Document lessons learned"
            ],
            "required_resources": ["security_team"],
            "estimated_time": 120,
            "success_criteria": ["finding_addressed", "security_improved"]
        }


class ResourceEstimationEngine:
    """Estimate resources required for response implementation"""
    
    def __init__(self):
        self.logger = logging.getLogger("resource_estimation")
        self.resource_costs = {
            "security_team": {"hourly_rate": 150, "availability": 0.8},
            "development_team": {"hourly_rate": 120, "availability": 0.7},
            "network_team": {"hourly_rate": 130, "availability": 0.9},
            "qa_team": {"hourly_rate": 100, "availability": 0.6},
            "system_admin": {"hourly_rate": 110, "availability": 0.85}
        }
    
    def estimate_resources(self, response: BlueTeamResponse) -> Dict[str, Any]:
        """Estimate resources and costs for response implementation"""
        
        total_cost = 0
        resource_breakdown = {}
        
        for resource in response.required_resources:
            if resource in self.resource_costs:
                cost = (response.estimated_time / 60) * self.resource_costs[resource]["hourly_rate"]
                total_cost += cost
                resource_breakdown[resource] = {
                    "hours": response.estimated_time / 60,
                    "cost": cost,
                    "availability": self.resource_costs[resource]["availability"]
                }
        
        return {
            "total_cost": total_cost,
            "resource_breakdown": resource_breakdown,
            "estimated_completion_time": response.estimated_time
        }


class NotificationSystem:
    """Handle notifications for red team findings and responses"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("notification_system")
        
    async def send_alert(self, finding: RedTeamFinding, response: BlueTeamResponse):
        """Send alert notification for critical findings"""
        
        subject = f"Critical Security Finding: {finding.vulnerability_type}"
        body = self._create_alert_body(finding, response)
        
        # Send email notification
        await self._send_email(subject, body)
        
        # Send Slack notification (if configured)
        if self.config.get("slack_webhook_url"):
            await self._send_slack_notification(finding, response)
    
    def _create_alert_body(self, finding: RedTeamFinding, response: BlueTeamResponse) -> str:
        """Create detailed alert body"""
        
        return f"""
        CRITICAL SECURITY FINDING DETECTED
        
        Finding ID: {finding.finding_id}
        Vulnerability Type: {finding.vulnerability_type}
        Severity: {finding.severity.name}
        Priority: {response.priority.name}
        
        Affected Systems: {', '.join(finding.affected_systems)}
        
        Impact Description:
        {finding.impact_description}
        
        Recommended Response:
        {response.description}
        
        Implementation Steps:
        {chr(10).join(f'- {step}' for step in response.implementation_steps)}
        
        Estimated Time: {response.estimated_time} minutes
        Required Resources: {', '.join(response.required_resources)}
        
        Please implement the recommended response immediately.
        """
    
    async def _send_email(self, subject: str, body: str):
        """Send email notification"""
        
        try:
            smtp_server = self.config.get("smtp_server", "localhost")
            smtp_port = self.config.get("smtp_port", 587)
            sender_email = self.config.get("sender_email", "security@company.com")
            recipient_emails = self.config.get("recipient_emails", ["security-team@company.com"])
            
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, self.config.get("smtp_password", ""))
            
            text = msg.as_string()
            server.sendmail(sender_email, recipient_emails, text)
            server.quit()
            
            self.logger.info("Alert email sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
    
    async def _send_slack_notification(self, finding: RedTeamFinding, response: BlueTeamResponse):
        """Send Slack notification"""
        
        # Implementation would use Slack webhook
        pass


class FeedbackLoopDatabase:
    """Database for storing and managing feedback loop data"""
    
    def __init__(self, db_path: str = "/tmp/red_blue_feedback.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("feedback_loop_db")
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                attack_result TEXT,
                severity INTEGER,
                attack_vector TEXT,
                vulnerability_type TEXT,
                affected_systems TEXT,
                impact_description TEXT,
                evidence TEXT,
                exploitation_complexity REAL,
                detection_difficulty REAL,
                business_impact REAL,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Create responses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                response_id TEXT PRIMARY KEY,
                finding_id TEXT,
                response_type TEXT,
                priority INTEGER,
                description TEXT,
                implementation_steps TEXT,
                estimated_time INTEGER,
                required_resources TEXT,
                success_criteria TEXT,
                rollback_plan TEXT,
                status INTEGER,
                implemented_at TEXT,
                verified_at TEXT,
                effectiveness_score REAL,
                FOREIGN KEY (finding_id) REFERENCES findings (finding_id)
            )
        ''')
        
        # Create metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                metric_id TEXT PRIMARY KEY,
                total_findings INTEGER,
                responded_findings INTEGER,
                implemented_responses INTEGER,
                verified_responses INTEGER,
                avg_response_time REAL,
                avg_implementation_time REAL,
                effectiveness_score REAL,
                false_positive_rate REAL,
                recurrence_rate REAL,
                improvement_velocity REAL,
                calculated_at TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_finding(self, finding: RedTeamFinding):
        """Store a red team finding"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.finding_id,
            json.dumps(asdict(finding.attack_result)),
            finding.severity.value,
            finding.attack_vector,
            finding.vulnerability_type,
            json.dumps(finding.affected_systems),
            finding.impact_description,
            json.dumps(finding.evidence),
            finding.exploitation_complexity,
            finding.detection_difficulty,
            finding.business_impact,
            finding.created_at.isoformat(),
            finding.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def store_response(self, response: BlueTeamResponse):
        """Store a blue team response"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            response.response_id,
            response.finding_id,
            response.response_type.value,
            response.priority.value,
            response.description,
            json.dumps(response.implementation_steps),
            response.estimated_time,
            json.dumps(response.required_resources),
            json.dumps(response.success_criteria),
            response.rollback_plan,
            response.status.value,
            response.implemented_at.isoformat() if response.implemented_at else None,
            response.verified_at.isoformat() if response.verified_at else None,
            response.effectiveness_score
        ))
        
        conn.commit()
        conn.close()
    
    def get_findings_by_severity(self, severity: AlertSeverity) -> List[RedTeamFinding]:
        """Get findings by severity"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM findings WHERE severity = ?', (severity.value,))
        rows = cursor.fetchall()
        
        findings = []
        for row in rows:
            finding = RedTeamFinding(
                finding_id=row[0],
                attack_result=json.loads(row[1]),
                severity=AlertSeverity(row[2]),
                attack_vector=row[3],
                vulnerability_type=row[4],
                affected_systems=json.loads(row[5]),
                impact_description=row[6],
                evidence=json.loads(row[7]),
                exploitation_complexity=row[8],
                detection_difficulty=row[9],
                business_impact=row[10],
                created_at=datetime.fromisoformat(row[11]),
                updated_at=datetime.fromisoformat(row[12])
            )
            findings.append(finding)
        
        conn.close()
        return findings


class RedBlueFeedbackLoop:
    """Main red-blue team feedback loop system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("red_blue_feedback_loop")
        
        # Core engines
        self.prioritization_engine = AlertPrioritizationEngine()
        self.response_engine = ResponseRecommendationEngine()
        self.notification_system = NotificationSystem(config.get("notifications", {}))
        self.database = FeedbackLoopDatabase(config.get("db_path", "/tmp/red_blue_feedback.db"))
        
        # Configuration
        self.auto_response_threshold = config.get("auto_response_threshold", AlertSeverity.HIGH)
        self.feedback_frequency = config.get("feedback_frequency", 300)  # 5 minutes
        self.continuous_monitoring = config.get("continuous_monitoring", True)
        
        # State management
        self.active_findings = {}
        self.pending_responses = {}
        self.improvement_history = []
        self.metrics = FeedbackMetrics(0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        
    async def process_red_team_findings(self, findings: List[RedTeamFinding]):
        """Process red team findings through the feedback loop"""
        
        self.logger.info(f"Processing {len(findings)} red team findings")
        
        for finding in findings:
            await self._process_single_finding(finding)
    
    async def _process_single_finding(self, finding: RedTeamFinding):
        """Process a single red team finding"""
        
        # Calculate impact score
        finding.business_impact = self.prioritization_engine.impact_scoring.calculate_business_impact(finding)
        
        # Determine severity and priority
        severity, priority = self.prioritization_engine.prioritize_finding(finding)
        finding.severity = severity
        
        # Store finding
        self.database.store_finding(finding)
        self.active_findings[finding.finding_id] = finding
        
        # Generate response recommendations
        responses = self.response_engine.generate_response_recommendations(finding)
        
        # Prioritize responses
        for response in responses:
            response.priority = priority
            self.database.store_response(response)
            self.pending_responses[response.response_id] = response
            
            # Send notifications for high priority findings
            if finding.severity.value >= self.auto_response_threshold.value:
                await self.notification_system.send_alert(finding, response)
        
        # Update metrics
        self.metrics.total_findings += 1
        
        self.logger.info(f"Processed finding {finding.finding_id} with severity {severity.name}")
    
    async def implement_blue_team_response(self, response_id: str, 
                                         implementation_details: Dict[str, Any]):
        """Implement a blue team response"""
        
        if response_id not in self.pending_responses:
            self.logger.error(f"Response {response_id} not found")
            return
        
        response = self.pending_responses[response_id]
        response.status = FeedbackStatus.IMPLEMENTING
        response.implemented_at = datetime.now()
        
        # Simulate implementation
        success = await self._simulate_implementation(response, implementation_details)
        
        if success:
            response.status = FeedbackStatus.IMPLEMENTED
            self.metrics.implemented_responses += 1
            
            # Schedule verification
            asyncio.create_task(self._verify_response(response))
        else:
            response.status = FeedbackStatus.FAILED
        
        self.database.store_response(response)
        self.logger.info(f"Response {response_id} implementation completed: {response.status}")
    
    async def _simulate_implementation(self, response: BlueTeamResponse, 
                                     details: Dict[str, Any]) -> bool:
        """Simulate response implementation (replace with real implementation)"""
        
        # Simulate implementation time
        await asyncio.sleep(2)  # 2 seconds for demo
        
        # Calculate effectiveness
        response.effectiveness_score = random.uniform(0.7, 1.0)
        
        return response.effectiveness_score > 0.8
    
    async def _verify_response(self, response: BlueTeamResponse):
        """Verify the effectiveness of a blue team response"""
        
        await asyncio.sleep(5)  # Simulate verification time
        
        # Simulate verification
        if response.effectiveness_score > 0.9:
            response.status = FeedbackStatus.VERIFIED
            response.verified_at = datetime.now()
            self.metrics.verified_responses += 1
        else:
            response.status = FeedbackStatus.FAILED
            
            # Generate improvement recommendation
            improvement = self._generate_improvement_recommendation(response)
            self.improvement_history.append(improvement)
        
        self.database.store_response(response)
        self.logger.info(f"Response {response.response_id} verification completed: {response.status}")
    
    def _generate_improvement_recommendation(self, response: BlueTeamResponse) -> DefenseImprovement:
        """Generate improvement recommendation for failed response"""
        
        return DefenseImprovement(
            improvement_id=str(uuid.uuid4()),
            finding_id=response.finding_id,
            improvement_type="response_enhancement",
            description="Enhance response effectiveness",
            implementation_details={
                "current_effectiveness": response.effectiveness_score,
                "target_effectiveness": 0.95,
                "improvement_areas": ["detection_accuracy", "response_time"]
            },
            effectiveness_metrics={
                "current_score": response.effectiveness_score,
                "improvement_potential": 0.25
            },
            lessons_learned=["Response needs refinement", "Consider alternative approaches"],
            recommendations=["Increase monitoring sensitivity", "Implement additional controls"],
            created_at=datetime.now()
        )
    
    async def generate_feedback_report(self) -> Dict[str, Any]:
        """Generate comprehensive feedback loop report"""
        
        # Calculate metrics
        self._calculate_metrics()
        
        # Get recent findings and responses
        recent_findings = self.database.get_findings_by_severity(AlertSeverity.HIGH)
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat(),
            "metrics": asdict(self.metrics),
            "active_findings": len(self.active_findings),
            "pending_responses": len(self.pending_responses),
            "improvement_history": [asdict(imp) for imp in self.improvement_history[-10:]],
            "recent_findings": [asdict(f) for f in recent_findings[-5:]],
            "recommendations": [
                "Increase monitoring for high-severity findings",
                "Implement automated response for critical vulnerabilities",
                "Regular review of response effectiveness",
                "Continuous improvement of defensive measures"
            ]
        }
        
        return report
    
    def _calculate_metrics(self):
        """Calculate feedback loop metrics"""
        
        # Calculate response times
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        # Average response time
        cursor.execute('''
            SELECT AVG(
                (julianday(implemented_at) - julianday(created_at)) * 24 * 60
            ) FROM responses r 
            JOIN findings f ON r.finding_id = f.finding_id
            WHERE implemented_at IS NOT NULL
        ''')
        
        avg_response_time = cursor.fetchone()[0] or 0
        
        # Average implementation time
        cursor.execute('''
            SELECT AVG(estimated_time) FROM responses
            WHERE status >= ?
        ''', (FeedbackStatus.IMPLEMENTED.value,))
        
        avg_implementation_time = cursor.fetchone()[0] or 0
        
        # Calculate effectiveness
        cursor.execute('''
            SELECT AVG(effectiveness_score) FROM responses
            WHERE effectiveness_score > 0
        ''')
        
        effectiveness_score = cursor.fetchone()[0] or 0
        
        conn.close()
        
        # Update metrics
        self.metrics.avg_response_time = avg_response_time
        self.metrics.avg_implementation_time = avg_implementation_time
        self.metrics.effectiveness_score = effectiveness_score
        
        # Calculate rates
        if self.metrics.total_findings > 0:
            self.metrics.responded_findings = self.metrics.implemented_responses + self.metrics.failed_responses
            self.metrics.false_positive_rate = 0.1  # Placeholder
            self.metrics.recurrence_rate = 0.05  # Placeholder
            self.metrics.improvement_velocity = 0.2  # Placeholder
    
    async def start_continuous_monitoring(self):
        """Start continuous feedback loop monitoring"""
        
        if not self.continuous_monitoring:
            return
        
        self.logger.info("Starting continuous feedback loop monitoring")
        
        while True:
            try:
                # Process any new findings
                await self._check_for_new_findings()
                
                # Update metrics
                self._calculate_metrics()
                
                # Generate periodic reports
                if len(self.active_findings) % 10 == 0:
                    report = await self.generate_feedback_report()
                    self.logger.info(f"Generated feedback report: {report['report_id']}")
                
                await asyncio.sleep(self.feedback_frequency)
                
            except Exception as e:
                self.logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(60)  # 1 minute on error
    
    async def _check_for_new_findings(self):
        """Check for new findings to process"""
        
        # This would typically poll for new findings
        # For demo purposes, we'll just log the check
        self.logger.debug("Checking for new findings")


# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def main():
        # Initialize feedback loop
        config = {
            "auto_response_threshold": "HIGH",
            "feedback_frequency": 300,
            "continuous_monitoring": True,
            "notifications": {
                "smtp_server": "smtp.company.com",
                "smtp_port": 587,
                "sender_email": "security@company.com",
                "recipient_emails": ["security-team@company.com"]
            }
        }
        
        feedback_loop = RedBlueFeedbackLoop(config)
        
        # Create sample findings
        sample_findings = [
            RedTeamFinding(
                finding_id="finding_001",
                attack_result=AttackResult(
                    attack_id="attack_001",
                    scenario_id="scenario_001",
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    status="success",
                    success_rate=0.9,
                    detection_rate=0.3,
                    blocked_techniques=[],
                    successful_techniques=["sql_injection"],
                    artifacts_collected=["database_dump"],
                    defensive_responses=[],
                    adaptation_suggestions=[],
                    evidence={"sql_query": "SELECT * FROM users"},
                    metrics={"execution_time": 30}
                ),
                severity=AlertSeverity.HIGH,
                attack_vector="web_application",
                vulnerability_type="sql_injection",
                affected_systems=["web_server_01", "database_server_01"],
                impact_description="Unauthorized access to customer database",
                evidence={"logs": ["sql_injection_attempts.log"]},
                exploitation_complexity=0.3,
                detection_difficulty=0.7,
                business_impact=0.8,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        # Process findings
        await feedback_loop.process_red_team_findings(sample_findings)
        
        # Generate report
        report = await feedback_loop.generate_feedback_report()
        print(json.dumps(report, indent=2, default=str))
    
    asyncio.run(main())