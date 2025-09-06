#!/usr/bin/env python3
"""
Unified Scan Orchestrator - Core engine for InfoSentinel Pentest AI
Consolidates all scanning tools under a single, policy-aware orchestration layer.
"""

import asyncio
import json
import uuid
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict
import logging
from concurrent.futures import ThreadPoolExecutor

from database.db import get_db, get_postgres_session, ScanQueue, AuditLog
from services.websocket_service import emit_scan_progress, emit_vulnerability_found, emit_scan_complete
from scanners.network_scanner import NetworkScanner
from scanners.owasp_scanner import OWASPScanner
from scanners.sqlmap_integration import sqlmap_scanner
from scanners.metasploit_integration import metasploit_integration
from scanners.hydra_integration import hydra_integration
from scanners.nikto_integration import nikto_integration
from scanners.directory_scanner import directory_scanner
from scanners.burp_integration import burp_integration
from security_tools_integration import SecurityToolsManager
from policy.scope_enforcer import ScopeEnforcer
from ai.vulnerability_analyzer import VulnerabilityAnalyzer
from intelligence.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    ANALYZING = "analyzing"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"  # Policy violation

class ScanType(Enum):
    NETWORK = "network"
    WEB_APP = "web_app"
    COMPREHENSIVE = "comprehensive"
    COMPLIANCE = "compliance"
    EXPLOIT_VALIDATION = "exploit_validation"

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanRequest:
    """Unified scan request structure"""
    target: str
    scan_type: ScanType
    user_id: int
    options: Dict[str, Any]
    priority: int = 5
    risk_level: RiskLevel = RiskLevel.MEDIUM
    requires_approval: bool = False
    scope_validation: bool = True
    ai_triage: bool = True
    threat_intel_enrichment: bool = True

@dataclass
class ScanContext:
    """Runtime context for scan execution"""
    scan_id: str
    request: ScanRequest
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    progress: int = 0
    current_phase: str = ""
    findings: List[Dict] = None
    enriched_findings: List[Dict] = None
    policy_violations: List[str] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.enriched_findings is None:
            self.enriched_findings = []
        if self.policy_violations is None:
            self.policy_violations = []

class ScanOrchestrator:
    """Unified orchestrator for all security scanning operations"""
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.active_scans: Dict[str, ScanContext] = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        # Initialize components
        self.security_tools = SecurityToolsManager()
        self.network_scanner = NetworkScanner(socketio)
        self.owasp_scanner = OWASPScanner()
        self.scope_enforcer = ScopeEnforcer()
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.threat_intel = ThreatIntelService()
        
        logger.info("Scan Orchestrator initialized")
    
    async def submit_scan(self, request: ScanRequest) -> str:
        """Submit a new scan request with policy validation"""
        scan_id = str(uuid.uuid4())
        
        try:
            # Create scan context
            context = ScanContext(
                scan_id=scan_id,
                request=request,
                status=ScanStatus.QUEUED,
                start_time=datetime.now()
            )
            
            self.active_scans[scan_id] = context
            
            # Persist to database
            await self._persist_scan_queue(context)
            
            # Start validation and execution pipeline
            self.executor.submit(self._execute_scan_pipeline, scan_id)
            
            logger.info(f"Scan {scan_id} submitted for target {request.target}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to submit scan: {e}")
            if scan_id in self.active_scans:
                self.active_scans[scan_id].status = ScanStatus.FAILED
                self.active_scans[scan_id].error_message = str(e)
            raise
    
    def _execute_scan_pipeline(self, scan_id: str):
        """Execute the complete scan pipeline with all safety checks"""
        context = self.active_scans[scan_id]
        
        try:
            # Phase 1: Scope and Policy Validation
            self._update_scan_progress(scan_id, 5, "Validating scope and policies")
            context.status = ScanStatus.VALIDATING
            
            if context.request.scope_validation:
                violations = self.scope_enforcer.validate_target(
                    context.request.target,
                    context.request.user_id,
                    context.request.scan_type.value
                )
                
                if violations:
                    context.policy_violations = violations
                    context.status = ScanStatus.BLOCKED
                    self._update_scan_progress(scan_id, 0, f"Blocked: {', '.join(violations)}")
                    return
            
            # Phase 2: Risk Assessment and Approval Gate
            if context.request.requires_approval or context.request.risk_level == RiskLevel.CRITICAL:
                self._update_scan_progress(scan_id, 10, "Awaiting operator approval")
                # In a real implementation, this would wait for approval
                # For now, we'll auto-approve non-critical scans
                if context.request.risk_level == RiskLevel.CRITICAL:
                    context.status = ScanStatus.BLOCKED
                    context.error_message = "Critical risk scans require manual approval"
                    return
            
            # Phase 3: Execute Scanning
            self._update_scan_progress(scan_id, 20, "Starting security scan")
            context.status = ScanStatus.RUNNING
            
            findings = self._execute_scanners(context)
            context.findings = findings
            
            # Phase 4: AI-Driven Analysis and Triage
            if context.request.ai_triage and findings:
                self._update_scan_progress(scan_id, 70, "Analyzing findings with AI")
                context.status = ScanStatus.ANALYZING
                
                analyzed_findings = self.vuln_analyzer.analyze_findings(
                    findings, context.request.target
                )
                context.findings = analyzed_findings
            
            # Phase 5: Threat Intelligence Enrichment
            if context.request.threat_intel_enrichment and context.findings:
                self._update_scan_progress(scan_id, 85, "Enriching with threat intelligence")
                context.status = ScanStatus.ENRICHING
                
                enriched_findings = asyncio.run(self.threat_intel.enrich_findings(
                    context.findings
                ))
                context.enriched_findings = enriched_findings
            
            # Phase 6: Finalization
            self._update_scan_progress(scan_id, 95, "Finalizing results")
            asyncio.run(self._finalize_scan(context))
            
            context.status = ScanStatus.COMPLETED
            context.end_time = datetime.now()
            self._update_scan_progress(scan_id, 100, "Scan completed")
            
            # Emit completion event
            if self.socketio:
                emit_scan_complete(self.socketio, scan_id, {
                    "findings_count": len(context.enriched_findings or context.findings),
                    "target": context.request.target,
                    "duration": str(context.end_time - context.start_time)
                })
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            context.status = ScanStatus.FAILED
            context.error_message = str(e)
            context.end_time = datetime.now()
            self._update_scan_progress(scan_id, 0, f"Scan failed: {str(e)}")
    
    def _execute_scanners(self, context: ScanContext) -> List[Dict]:
        """Execute appropriate scanners based on scan type"""
        findings = []
        scan_type = context.request.scan_type
        target = context.request.target
        options = context.request.options
        
        try:
            if scan_type in [ScanType.NETWORK, ScanType.COMPREHENSIVE]:
                # Network scanning with Nmap
                self._update_scan_progress(context.scan_id, 30, "Network reconnaissance")
                network_findings = self._run_network_scan(context.scan_id, target, options)
                findings.extend(network_findings)
            
            if scan_type in [ScanType.WEB_APP, ScanType.COMPREHENSIVE]:
                # Web application scanning
                self._update_scan_progress(context.scan_id, 50, "Web application testing")
                web_findings = self._run_web_scan(context.scan_id, target, options)
                findings.extend(web_findings)
            
            if scan_type == ScanType.EXPLOIT_VALIDATION:
                # Exploit validation (requires approval)
                self._update_scan_progress(context.scan_id, 60, "Exploit validation")
                exploit_findings = self._run_exploit_validation(context.scan_id, target, options)
                findings.extend(exploit_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Scanner execution failed: {e}")
            raise
    
    def _run_network_scan(self, scan_id: str, target: str, options: Dict) -> List[Dict]:
        """Execute network scanning using unified tools"""
        findings = []
        
        # Use the existing network scanner
        # Note: This would be refactored to return findings directly
        # rather than storing in database
        
        # For now, simulate network findings
        findings.append({
            "type": "network",
            "title": "Open Port Detected",
            "description": f"Port 22 (SSH) is open on {target}",
            "severity": "medium",
            "host": target,
            "port": 22,
            "service": "ssh",
            "confidence": 0.95
        })
        
        return findings
    
    def _run_web_scan(self, scan_id: str, target: str, options: Dict) -> List[Dict]:
        """Execute comprehensive web application scanning"""
        findings = []
        
        try:
            # 1. Directory Discovery
            if options.get("directory_scan", True):
                logger.info(f"Starting directory discovery for {target}")
                dir_scan_id = f"{scan_id}_dir"
                directory_scanner.scan_directories(
                    dir_scan_id, target, 
                    wordlist="common",
                    options={"extensions": ["php", "html", "js", "txt"]}
                )
                
                # Wait for completion and collect results
                while directory_scanner.get_scan_status(dir_scan_id).get("status") == "running":
                    time.sleep(2)
                
                dir_results = directory_scanner.get_scan_status(dir_scan_id)
                if dir_results and dir_results.get("results"):
                    for content in dir_results["results"].discovered_content:
                        findings.append({
                            "type": "directory_discovery",
                            "url": content.url,
                            "status_code": content.status_code,
                            "interesting": content.interesting,
                            "description": content.description or "Directory/file discovered"
                        })
            
            # 2. Nikto Web Server Scan
            if options.get("nikto_scan", True):
                logger.info(f"Starting Nikto scan for {target}")
                nikto_scan_id = f"{scan_id}_nikto"
                nikto_integration.scan_website(
                    nikto_scan_id, target,
                    profile="standard"
                )
                
                # Wait for completion and collect results
                while nikto_integration.get_scan_status(nikto_scan_id).get("status") == "running":
                    time.sleep(3)
                
                nikto_results = nikto_integration.get_scan_status(nikto_scan_id)
                if nikto_results and nikto_results.get("results"):
                    for vuln in nikto_results["results"].vulnerabilities:
                        findings.append({
                            "type": "web_server_vulnerability",
                            "url": vuln.url,
                            "vulnerability_type": vuln.vulnerability_type.value,
                            "severity": vuln.severity.value,
                            "description": vuln.description,
                            "method": vuln.method
                        })
            
            # 3. SQLMap SQL Injection Testing
            if options.get("sqlmap_scan", True):
                logger.info(f"Starting SQLMap scan for {target}")
                sqlmap_scan_id = f"{scan_id}_sqlmap"
                sqlmap_scanner.scan_url(
                    sqlmap_scan_id, target,
                    options={"risk_level": 1, "level": 1}
                )
                
                # Wait for completion and collect results
                while sqlmap_scanner.get_scan_status(sqlmap_scan_id).get("status") == "running":
                    time.sleep(5)
                
                sqlmap_results = sqlmap_scanner.get_scan_status(sqlmap_scan_id)
                if sqlmap_results and sqlmap_results.get("results"):
                    for result in sqlmap_results["results"]:
                        if result.vulnerable:
                            findings.append({
                                "type": "sql_injection",
                                "url": result.target_url,
                                "parameter": result.parameter,
                                "injection_type": result.injection_type,
                                "dbms": result.dbms,
                                "severity": "high",
                                "description": f"SQL injection vulnerability in parameter '{result.parameter}'"
                            })
            
            # 4. Burp Suite Professional Scan (if available)
            if options.get("burp_scan", False) and burp_integration:
                logger.info(f"Starting Burp Suite scan for {target}")
                burp_scan_id = f"{scan_id}_burp"
                burp_integration.start_scan(
                    burp_scan_id, target,
                    scan_type="crawl_and_audit"
                )
                
                # Wait for completion and collect results
                while burp_integration.get_scan_status(burp_scan_id).get("status") == "running":
                    time.sleep(10)
                
                burp_results = burp_integration.get_scan_status(burp_scan_id)
                if burp_results and burp_results.get("results"):
                    for vuln in burp_results["results"].vulnerabilities:
                        findings.append({
                            "type": "burp_vulnerability",
                            "url": vuln.url,
                            "issue_name": vuln.issue_name,
                            "issue_type": vuln.issue_type,
                            "severity": vuln.severity.value,
                            "confidence": vuln.confidence.value,
                            "description": vuln.description
                        })
            
        except Exception as e:
            logger.error(f"Error in web application scanning: {e}")
            findings.append({
                "type": "scan_error",
                "description": f"Web scan error: {str(e)}",
                "severity": "info"
            })
        
        return findings
    
    def _run_exploit_validation(self, scan_id: str, target: str, options: Dict) -> List[Dict]:
        """Execute exploit validation with Metasploit integration"""
        findings = []
        
        try:
            # Only run safe auxiliary modules without approval
            safe_modules = [
                "auxiliary/scanner/http/http_version",
                "auxiliary/scanner/ssh/ssh_version",
                "auxiliary/scanner/http/dir_scanner"
            ]
            
            for module in safe_modules:
                try:
                    # Request exploit validation (auto-approved for safe modules)
                    request_id = metasploit_integration.request_exploit_validation(
                        scan_id, target, module,
                        justification="Automated safe reconnaissance",
                        requested_by="system"
                    )
                    
                    # Execute validation
                    result = metasploit_integration.execute_exploit_validation(request_id)
                    
                    if result.vulnerability_confirmed:
                        findings.append({
                            "type": "exploit_validation",
                            "target": result.target,
                            "exploit_module": result.exploit_module,
                            "vulnerability_confirmed": result.vulnerability_confirmed,
                            "risk_assessment": result.risk_assessment,
                            "remediation": result.remediation,
                            "severity": "medium",
                            "description": f"Vulnerability confirmed using {result.exploit_module}"
                        })
                    
                except Exception as e:
                    logger.warning(f"Exploit validation failed for {module}: {e}")
                    continue
            
            # Add authentication testing with Hydra
            if options.get("auth_testing", False):
                logger.info(f"Starting authentication testing for {target}")
                
                # Test common services
                auth_targets = [
                    {"protocol": "ssh", "port": 22},
                    {"protocol": "ftp", "port": 21},
                    {"protocol": "http-post-form", "port": 80}
                ]
                
                for auth_target in auth_targets:
                    try:
                        from scanners.hydra_integration import AuthTarget, AuthProtocol
                        
                        target_obj = AuthTarget(
                            host=target.split('://')[1].split('/')[0] if '://' in target else target,
                            port=auth_target["port"],
                            protocol=AuthProtocol(auth_target["protocol"])
                        )
                        
                        hydra_scan_id = f"{scan_id}_hydra_{auth_target['protocol']}"
                        hydra_integration.scan_authentication(
                            hydra_scan_id, target_obj,
                            options={"timeout": 10, "threads": 2}
                        )
                        
                        # Wait for completion
                        while hydra_integration.get_scan_status(hydra_scan_id).get("status") == "running":
                            time.sleep(2)
                        
                        hydra_results = hydra_integration.get_scan_status(hydra_scan_id)
                        if hydra_results and hydra_results.get("results"):
                            for login in hydra_results["results"].successful_logins:
                                findings.append({
                                    "type": "weak_authentication",
                                    "target": login.target,
                                    "protocol": login.protocol,
                                    "username": login.username,
                                    "password": "[REDACTED]",  # Don't log actual passwords
                                    "severity": "high",
                                    "description": f"Weak credentials found for {login.protocol} service"
                                })
                    
                    except Exception as e:
                        logger.warning(f"Authentication testing failed for {auth_target['protocol']}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in exploit validation: {e}")
            findings.append({
                "type": "validation_error",
                "description": f"Exploit validation error: {str(e)}",
                "severity": "info"
            })
        
        return findings
    
    def _update_scan_progress(self, scan_id: str, progress: int, phase: str):
        """Update scan progress and emit to clients"""
        if scan_id in self.active_scans:
            context = self.active_scans[scan_id]
            context.progress = progress
            context.current_phase = phase
            
            # Emit to WebSocket clients
            if self.socketio:
                emit_scan_progress(self.socketio, scan_id, {
                    "progress": progress,
                    "phase": phase,
                    "timestamp": datetime.now().isoformat()
                })
    
    async def _persist_scan_queue(self, context: ScanContext):
        """Persist scan to database queue"""
        try:
            db = get_db()
            scan_doc = {
                "_id": context.scan_id,
                "target": context.request.target,
                "scan_type": context.request.scan_type.value,
                "user_id": context.request.user_id,
                "status": context.status.value,
                "priority": context.request.priority,
                "options": context.request.options,
                "start_time": context.start_time,
                "progress": context.progress
            }
            
            # Use upsert to avoid duplicate key errors
            db.scans.update_one(
                {"_id": context.scan_id},
                {"$set": scan_doc},
                upsert=True
            )
            
        except Exception as e:
            logger.error(f"Failed to persist scan queue: {e}")
            raise
    
    async def _finalize_scan(self, context: ScanContext):
        """Finalize scan results and store findings"""
        try:
            db = get_db()
            
            # Update scan status
            db.scans.update_one(
                {"_id": context.scan_id},
                {
                    "$set": {
                        "status": context.status.value,
                        "end_time": context.end_time or datetime.now(),
                        "progress": context.progress,
                        "findings_count": len(context.enriched_findings or context.findings)
                    }
                }
            )
            
            # Store findings
            final_findings = context.enriched_findings or context.findings
            for finding in final_findings:
                finding["scan_id"] = context.scan_id
                finding["created_at"] = datetime.now()
                
            if final_findings:
                db.vulnerabilities.insert_many(final_findings)
            
        except Exception as e:
            logger.error(f"Failed to finalize scan: {e}")
            raise
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get current scan status"""
        if scan_id not in self.active_scans:
            # Check database for completed scans
            try:
                db = get_db()
                scan_doc = db.scans.find_one({"_id": scan_id})
                if scan_doc:
                    created = scan_doc.get("start_time") or scan_doc.get("created_at")
                    return {
                        "scan_id": scan_id,
                        "status": scan_doc["status"],
                        "progress": scan_doc.get("progress", 0),
                        "target": scan_doc["target"],
                        "created_at": created.isoformat() if created else None
                    }
            except Exception as e:
                logger.error(f"Failed to get scan status from DB: {e}")
            
            return None
        
        context = self.active_scans[scan_id]
        return {
            "scan_id": scan_id,
            "status": context.status.value,
            "progress": context.progress,
            "current_phase": context.current_phase,
            "target": context.request.target,
            "start_time": context.start_time.isoformat(),
            "findings_count": len(context.enriched_findings or context.findings),
            "policy_violations": context.policy_violations,
            "error_message": context.error_message
        }
    
    def cancel_scan(self, scan_id: str, user_id: int) -> bool:
        """Cancel an active scan"""
        if scan_id not in self.active_scans:
            return False
        
        context = self.active_scans[scan_id]
        
        # Check if user has permission to cancel
        if context.request.user_id != user_id:
            # Add role-based permission check here
            pass
        
        context.status = ScanStatus.CANCELLED
        context.end_time = datetime.now()
        
        # Update database
        try:
            db = get_db()
            db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "status": "cancelled",
                        "end_time": context.end_time
                    }
                }
            )
        except Exception as e:
            logger.error(f"Failed to update cancelled scan: {e}")
        
        logger.info(f"Scan {scan_id} cancelled by user {user_id}")
        return True
    
    def get_active_scans(self) -> List[Dict]:
        """Get all active scans"""
        active = []
        for scan_id, context in self.active_scans.items():
            if context.status not in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                active.append({
                    "scan_id": scan_id,
                    "target": context.request.target,
                    "status": context.status.value,
                    "progress": context.progress,
                    "start_time": context.start_time.isoformat()
                })
        
        return active

# Global orchestrator instance
orchestrator = None

def get_orchestrator(socketio=None) -> ScanOrchestrator:
    """Get the global orchestrator instance"""
    global orchestrator
    if orchestrator is None:
        orchestrator = ScanOrchestrator(socketio)
    return orchestrator