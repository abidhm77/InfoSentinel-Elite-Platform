#!/usr/bin/env python3
"""
Metasploit Integration Module
Provides exploit validation capabilities with strict approval gates
"""

import subprocess
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import tempfile
import os

logger = logging.getLogger(__name__)

class ExploitRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

@dataclass
class ExploitModule:
    """Represents a Metasploit exploit module"""
    name: str
    description: str
    risk_level: ExploitRisk
    targets: List[str]
    requires_approval: bool = True
    payload_options: Dict = None
    
    def __post_init__(self):
        if self.payload_options is None:
            self.payload_options = {}

@dataclass
class ExploitRequest:
    """Represents an exploit validation request"""
    request_id: str
    scan_id: str
    target: str
    exploit_module: str
    risk_level: ExploitRisk
    justification: str
    requested_by: str
    requested_at: datetime
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

@dataclass
class ExploitResult:
    """Represents exploit validation results"""
    target: str
    exploit_module: str
    success: bool
    vulnerability_confirmed: bool
    payload_executed: bool = False
    evidence: Dict = None
    risk_assessment: str = ""
    remediation: str = ""
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}

class MetasploitIntegration:
    """Metasploit integration with security controls"""
    
    def __init__(self):
        self.msfconsole_path = self._find_metasploit_path()
        self.temp_dir = tempfile.mkdtemp(prefix="msf_")
        self.active_exploits = {}
        self.pending_approvals = {}
        self.approved_exploits = {}
        
        # Safe exploit modules (low risk, verification only)
        self.safe_modules = {
            "auxiliary/scanner/http/dir_scanner": ExploitModule(
                name="Directory Scanner",
                description="Safe directory enumeration",
                risk_level=ExploitRisk.LOW,
                targets=["http", "https"],
                requires_approval=False
            ),
            "auxiliary/scanner/http/http_version": ExploitModule(
                name="HTTP Version Scanner",
                description="Identify web server version",
                risk_level=ExploitRisk.LOW,
                targets=["http", "https"],
                requires_approval=False
            ),
            "auxiliary/scanner/ssh/ssh_version": ExploitModule(
                name="SSH Version Scanner",
                description="Identify SSH service version",
                risk_level=ExploitRisk.LOW,
                targets=["ssh"],
                requires_approval=False
            )
        }
        
        # High-risk modules requiring approval
        self.restricted_modules = {
            "exploit/multi/http/struts2_content_type_ognl": ExploitModule(
                name="Apache Struts2 OGNL Injection",
                description="Exploits CVE-2017-5638 in Apache Struts2",
                risk_level=ExploitRisk.CRITICAL,
                targets=["http", "https"],
                requires_approval=True
            ),
            "exploit/windows/smb/ms17_010_eternalblue": ExploitModule(
                name="EternalBlue SMB Exploit",
                description="Exploits MS17-010 vulnerability",
                risk_level=ExploitRisk.CRITICAL,
                targets=["smb"],
                requires_approval=True
            )
        }
    
    def _find_metasploit_path(self) -> str:
        """Find Metasploit console path"""
        possible_paths = [
            "/usr/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
            "msfconsole"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "-v"], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=10)
                if result.returncode == 0:
                    logger.info(f"Found Metasploit at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        raise RuntimeError("Metasploit not found. Please install Metasploit Framework.")
    
    def request_exploit_validation(self, scan_id: str, target: str, 
                                 exploit_module: str, justification: str, 
                                 requested_by: str) -> str:
        """Request approval for exploit validation"""
        request_id = f"exploit_{scan_id}_{int(time.time())}"
        
        # Check if module exists and get risk level
        module_info = self._get_module_info(exploit_module)
        if not module_info:
            raise ValueError(f"Unknown exploit module: {exploit_module}")
        
        # Create approval request
        request = ExploitRequest(
            request_id=request_id,
            scan_id=scan_id,
            target=target,
            exploit_module=exploit_module,
            risk_level=module_info.risk_level,
            justification=justification,
            requested_by=requested_by,
            requested_at=datetime.now()
        )
        
        # Auto-approve safe modules
        if not module_info.requires_approval:
            request.approval_status = ApprovalStatus.APPROVED
            request.approved_by = "system"
            request.approved_at = datetime.now()
            self.approved_exploits[request_id] = request
        else:
            self.pending_approvals[request_id] = request
            logger.info(f"Exploit validation request {request_id} pending approval")
        
        return request_id
    
    def approve_exploit_request(self, request_id: str, approved_by: str, 
                              expires_hours: int = 24) -> bool:
        """Approve an exploit validation request"""
        if request_id not in self.pending_approvals:
            return False
        
        request = self.pending_approvals.pop(request_id)
        request.approval_status = ApprovalStatus.APPROVED
        request.approved_by = approved_by
        request.approved_at = datetime.now()
        request.expires_at = datetime.now().replace(
            hour=datetime.now().hour + expires_hours
        )
        
        self.approved_exploits[request_id] = request
        logger.info(f"Exploit request {request_id} approved by {approved_by}")
        return True
    
    def deny_exploit_request(self, request_id: str, denied_by: str) -> bool:
        """Deny an exploit validation request"""
        if request_id not in self.pending_approvals:
            return False
        
        request = self.pending_approvals.pop(request_id)
        request.approval_status = ApprovalStatus.DENIED
        logger.info(f"Exploit request {request_id} denied by {denied_by}")
        return True
    
    def execute_exploit_validation(self, request_id: str) -> ExploitResult:
        """Execute approved exploit validation"""
        if request_id not in self.approved_exploits:
            raise ValueError("Exploit request not approved or not found")
        
        request = self.approved_exploits[request_id]
        
        # Check if approval has expired
        if request.expires_at and datetime.now() > request.expires_at:
            request.approval_status = ApprovalStatus.EXPIRED
            raise ValueError("Exploit approval has expired")
        
        # Get module information
        module_info = self._get_module_info(request.exploit_module)
        
        try:
            # Execute in sandboxed environment
            result = self._execute_metasploit_module(
                request.exploit_module,
                request.target,
                module_info
            )
            
            logger.info(f"Exploit validation completed for {request.target}")
            return result
            
        except Exception as e:
            logger.error(f"Exploit validation failed: {e}")
            return ExploitResult(
                target=request.target,
                exploit_module=request.exploit_module,
                success=False,
                vulnerability_confirmed=False,
                evidence={"error": str(e)}
            )
    
    def _get_module_info(self, module_name: str) -> Optional[ExploitModule]:
        """Get information about an exploit module"""
        # Check safe modules first
        if module_name in self.safe_modules:
            return self.safe_modules[module_name]
        
        # Check restricted modules
        if module_name in self.restricted_modules:
            return self.restricted_modules[module_name]
        
        return None
    
    def _execute_metasploit_module(self, module_name: str, target: str, 
                                 module_info: ExploitModule) -> ExploitResult:
        """Execute Metasploit module safely"""
        
        # Create resource script for automated execution
        resource_script = self._create_resource_script(module_name, target, module_info)
        
        try:
            # Execute Metasploit with resource script
            cmd = [
                self.msfconsole_path,
                "-q",  # Quiet mode
                "-r", resource_script,  # Resource script
                "-o", os.path.join(self.temp_dir, "output.log")  # Output log
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=self.temp_dir
            )
            
            # Parse results
            return self._parse_metasploit_output(
                process.stdout, 
                process.stderr, 
                target, 
                module_name
            )
            
        except subprocess.TimeoutExpired:
            logger.error("Metasploit execution timed out")
            return ExploitResult(
                target=target,
                exploit_module=module_name,
                success=False,
                vulnerability_confirmed=False,
                evidence={"error": "Execution timed out"}
            )
        
        finally:
            # Clean up resource script
            try:
                os.remove(resource_script)
            except:
                pass
    
    def _create_resource_script(self, module_name: str, target: str, 
                              module_info: ExploitModule) -> str:
        """Create Metasploit resource script"""
        script_path = os.path.join(self.temp_dir, f"exploit_{int(time.time())}.rc")
        
        script_content = f"""
use {module_name}
set RHOSTS {target}
set VERBOSE true
"""
        
        # Add safe payload for verification only
        if module_info.risk_level in [ExploitRisk.HIGH, ExploitRisk.CRITICAL]:
            script_content += """
set PAYLOAD generic/shell_reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
set ExitOnSession true
"""
        
        # For auxiliary modules, just run check
        if "auxiliary" in module_name:
            script_content += "run\nexit\n"
        else:
            # For exploits, only check if vulnerable (don't execute payload)
            script_content += "check\nexit\n"
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        return script_path
    
    def _parse_metasploit_output(self, stdout: str, stderr: str, 
                               target: str, module_name: str) -> ExploitResult:
        """Parse Metasploit execution output"""
        
        # Check for vulnerability indicators
        vulnerability_confirmed = any([
            "appears to be vulnerable" in stdout.lower(),
            "vulnerable" in stdout.lower() and "not vulnerable" not in stdout.lower(),
            "exploit completed" in stdout.lower(),
            "session" in stdout.lower() and "opened" in stdout.lower()
        ])
        
        # Check for successful execution
        success = "error" not in stderr.lower() and len(stderr.strip()) == 0
        
        # Extract evidence
        evidence = {
            "stdout": stdout[:1000],  # Limit output size
            "module_used": module_name,
            "timestamp": datetime.now().isoformat()
        }
        
        # Determine risk assessment
        if vulnerability_confirmed:
            risk_assessment = "HIGH: Target appears vulnerable to this exploit"
            remediation = "Immediate patching required. Review security configurations."
        else:
            risk_assessment = "LOW: No vulnerability detected"
            remediation = "Continue monitoring. Ensure systems are up to date."
        
        return ExploitResult(
            target=target,
            exploit_module=module_name,
            success=success,
            vulnerability_confirmed=vulnerability_confirmed,
            payload_executed=False,  # We only check, never execute payloads
            evidence=evidence,
            risk_assessment=risk_assessment,
            remediation=remediation
        )
    
    def get_pending_approvals(self) -> List[ExploitRequest]:
        """Get list of pending approval requests"""
        return list(self.pending_approvals.values())
    
    def get_approved_exploits(self) -> List[ExploitRequest]:
        """Get list of approved exploit requests"""
        return list(self.approved_exploits.values())
    
    def get_safe_modules(self) -> List[ExploitModule]:
        """Get list of safe modules that don't require approval"""
        return list(self.safe_modules.values())
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to cleanup Metasploit temp directory: {e}")

# Global instance
metasploit_integration = MetasploitIntegration()