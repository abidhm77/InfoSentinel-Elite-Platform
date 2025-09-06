#!/usr/bin/env python3
"""
Hydra Integration Module
Provides authentication testing and password attack capabilities
"""

import subprocess
import logging
import threading
import time
import os
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class AuthProtocol(Enum):
    SSH = "ssh"
    FTP = "ftp"
    HTTP_GET = "http-get"
    HTTP_POST = "http-post-form"
    TELNET = "telnet"
    SMB = "smb"
    RDP = "rdp"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"

class AttackType(Enum):
    DICTIONARY = "dictionary"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"

@dataclass
class AuthTarget:
    """Represents an authentication target"""
    host: str
    port: int
    protocol: AuthProtocol
    service_path: str = "/"
    username_list: List[str] = None
    password_list: List[str] = None
    
    def __post_init__(self):
        if self.username_list is None:
            self.username_list = []
        if self.password_list is None:
            self.password_list = []

@dataclass
class AuthResult:
    """Represents authentication test results"""
    target: str
    protocol: str
    username: str
    password: str
    success: bool
    response_time: float = 0.0
    error_message: str = ""
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class HydraScanResult:
    """Represents complete Hydra scan results"""
    target: str
    protocol: str
    total_attempts: int
    successful_logins: List[AuthResult]
    failed_attempts: int
    scan_duration: float
    status: str
    error_message: str = ""

class HydraIntegration:
    """Hydra integration for authentication testing"""
    
    def __init__(self):
        self.hydra_path = self._find_hydra_path()
        self.temp_dir = tempfile.mkdtemp(prefix="hydra_")
        self.active_scans = {}
        
        # Default wordlists
        self.default_usernames = [
            "admin", "administrator", "root", "user", "test", "guest",
            "oracle", "postgres", "mysql", "sa", "operator", "manager",
            "service", "support", "demo", "web", "www", "ftp", "mail"
        ]
        
        self.default_passwords = [
            "password", "123456", "admin", "root", "test", "guest",
            "password123", "admin123", "letmein", "welcome", "qwerty",
            "123456789", "password1", "abc123", "Password1", "changeme",
            "", "pass", "secret", "default", "login", "user"
        ]
    
    def _find_hydra_path(self) -> str:
        """Find Hydra executable path"""
        possible_paths = [
            "/usr/bin/hydra",
            "/usr/local/bin/hydra",
            "/opt/hydra/hydra",
            "hydra"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "-h"], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=10)
                if result.returncode == 0 or "Hydra" in result.stderr:
                    logger.info(f"Found Hydra at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        raise RuntimeError("Hydra not found. Please install Hydra.")
    
    def scan_authentication(self, scan_id: str, target: AuthTarget, 
                          attack_type: AttackType = AttackType.DICTIONARY,
                          options: Dict = None) -> str:
        """Start authentication testing scan"""
        options = options or {}
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_hydra_scan,
            args=(scan_id, target, attack_type, options)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_hydra_scan(self, scan_id: str, target: AuthTarget, 
                       attack_type: AttackType, options: Dict):
        """Execute Hydra authentication scan"""
        try:
            self.active_scans[scan_id] = {
                "status": "running",
                "start_time": datetime.now(),
                "target": f"{target.host}:{target.port}",
                "protocol": target.protocol.value,
                "progress": 0
            }
            
            # Prepare wordlists
            username_file, password_file = self._prepare_wordlists(target, options)
            
            # Build Hydra command
            cmd = self._build_hydra_command(target, username_file, password_file, options)
            
            logger.info(f"Starting Hydra scan: {' '.join(cmd)}")
            
            start_time = time.time()
            
            # Execute Hydra
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.temp_dir
            )
            
            # Monitor progress
            stdout_lines = []
            while process.poll() is None:
                line = process.stdout.readline()
                if line:
                    stdout_lines.append(line.strip())
                    # Update progress based on output
                    if "attempt" in line.lower():
                        self.active_scans[scan_id]["progress"] += 1
                time.sleep(0.1)
            
            # Get remaining output
            remaining_stdout, stderr = process.communicate()
            stdout_lines.extend(remaining_stdout.split('\n'))
            
            scan_duration = time.time() - start_time
            
            # Parse results
            if process.returncode == 0 or "login:" in '\n'.join(stdout_lines):
                results = self._parse_hydra_output(stdout_lines, target)
                self.active_scans[scan_id].update({
                    "status": "completed",
                    "progress": 100,
                    "results": results,
                    "duration": scan_duration,
                    "end_time": datetime.now()
                })
            else:
                logger.error(f"Hydra scan failed: {stderr}")
                self.active_scans[scan_id].update({
                    "status": "failed",
                    "error": stderr,
                    "duration": scan_duration,
                    "end_time": datetime.now()
                })
                
        except Exception as e:
            logger.error(f"Hydra scan error: {e}")
            self.active_scans[scan_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
        
        finally:
            # Clean up wordlist files
            self._cleanup_wordlists(username_file, password_file)
    
    def _prepare_wordlists(self, target: AuthTarget, options: Dict) -> Tuple[str, str]:
        """Prepare username and password wordlists"""
        
        # Prepare usernames
        usernames = target.username_list or options.get("usernames", self.default_usernames)
        username_file = os.path.join(self.temp_dir, f"usernames_{int(time.time())}.txt")
        
        with open(username_file, 'w') as f:
            for username in usernames:
                f.write(f"{username}\n")
        
        # Prepare passwords
        passwords = target.password_list or options.get("passwords", self.default_passwords)
        password_file = os.path.join(self.temp_dir, f"passwords_{int(time.time())}.txt")
        
        with open(password_file, 'w') as f:
            for password in passwords:
                f.write(f"{password}\n")
        
        return username_file, password_file
    
    def _build_hydra_command(self, target: AuthTarget, username_file: str, 
                           password_file: str, options: Dict) -> List[str]:
        """Build Hydra command with options"""
        cmd = [self.hydra_path]
        
        # Username and password lists
        cmd.extend(["-L", username_file, "-P", password_file])
        
        # Target specification
        if target.port != self._get_default_port(target.protocol):
            cmd.extend(["-s", str(target.port)])
        
        # Protocol-specific options
        if target.protocol == AuthProtocol.HTTP_POST:
            # HTTP POST form authentication
            form_path = options.get("form_path", "/login")
            form_data = options.get("form_data", "username=^USER^&password=^PASS^")
            failure_string = options.get("failure_string", "Invalid")
            cmd.extend([target.host, "http-post-form", 
                       f"{form_path}:{form_data}:{failure_string}"])
        
        elif target.protocol == AuthProtocol.HTTP_GET:
            # HTTP GET authentication
            cmd.extend([target.host, "http-get", target.service_path])
        
        else:
            # Standard protocols
            cmd.extend([target.host, target.protocol.value])
        
        # Performance options
        threads = options.get("threads", 4)
        cmd.extend(["-t", str(threads)])
        
        # Timeout settings
        timeout = options.get("timeout", 30)
        cmd.extend(["-w", str(timeout)])
        
        # Stop after first success (optional)
        if options.get("stop_on_success", True):
            cmd.append("-f")
        
        # Verbose output
        cmd.append("-V")
        
        # Exit after first valid pair found
        cmd.append("-F")
        
        return cmd
    
    def _get_default_port(self, protocol: AuthProtocol) -> int:
        """Get default port for protocol"""
        port_map = {
            AuthProtocol.SSH: 22,
            AuthProtocol.FTP: 21,
            AuthProtocol.HTTP_GET: 80,
            AuthProtocol.HTTP_POST: 80,
            AuthProtocol.TELNET: 23,
            AuthProtocol.SMB: 445,
            AuthProtocol.RDP: 3389,
            AuthProtocol.MYSQL: 3306,
            AuthProtocol.POSTGRES: 5432,
            AuthProtocol.MSSQL: 1433
        }
        return port_map.get(protocol, 80)
    
    def _parse_hydra_output(self, output_lines: List[str], target: AuthTarget) -> HydraScanResult:
        """Parse Hydra output and extract results"""
        successful_logins = []
        total_attempts = 0
        failed_attempts = 0
        
        for line in output_lines:
            line = line.strip()
            
            # Count attempts
            if "attempt" in line.lower():
                total_attempts += 1
            
            # Look for successful logins
            if "login:" in line and "password:" in line:
                try:
                    # Parse successful login line
                    # Format: [port][protocol] host: login: username   password: password
                    parts = line.split()
                    username_idx = parts.index("login:") + 1
                    password_idx = parts.index("password:") + 1
                    
                    if username_idx < len(parts) and password_idx < len(parts):
                        username = parts[username_idx]
                        password = parts[password_idx]
                        
                        successful_logins.append(AuthResult(
                            target=f"{target.host}:{target.port}",
                            protocol=target.protocol.value,
                            username=username,
                            password=password,
                            success=True
                        ))
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse login line: {line} - {e}")
            
            # Count failed attempts
            elif "invalid" in line.lower() or "failed" in line.lower():
                failed_attempts += 1
        
        return HydraScanResult(
            target=f"{target.host}:{target.port}",
            protocol=target.protocol.value,
            total_attempts=total_attempts,
            successful_logins=successful_logins,
            failed_attempts=failed_attempts,
            scan_duration=0.0,  # Will be set by caller
            status="completed" if successful_logins else "no_credentials_found"
        )
    
    def _cleanup_wordlists(self, username_file: str, password_file: str):
        """Clean up temporary wordlist files"""
        try:
            if os.path.exists(username_file):
                os.remove(username_file)
            if os.path.exists(password_file):
                os.remove(password_file)
        except Exception as e:
            logger.error(f"Failed to cleanup wordlist files: {e}")
    
    def test_single_credential(self, target: AuthTarget, username: str, 
                             password: str) -> AuthResult:
        """Test a single username/password combination"""
        try:
            cmd = [self.hydra_path, "-l", username, "-p", password]
            
            if target.port != self._get_default_port(target.protocol):
                cmd.extend(["-s", str(target.port)])
            
            cmd.extend([target.host, target.protocol.value])
            cmd.append("-f")  # Stop after first success
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            response_time = time.time() - start_time
            
            success = "login:" in result.stdout and "password:" in result.stdout
            
            return AuthResult(
                target=f"{target.host}:{target.port}",
                protocol=target.protocol.value,
                username=username,
                password=password,
                success=success,
                response_time=response_time,
                error_message=result.stderr if result.stderr else ""
            )
            
        except subprocess.TimeoutExpired:
            return AuthResult(
                target=f"{target.host}:{target.port}",
                protocol=target.protocol.value,
                username=username,
                password=password,
                success=False,
                error_message="Timeout"
            )
        except Exception as e:
            return AuthResult(
                target=f"{target.host}:{target.port}",
                protocol=target.protocol.value,
                username=username,
                password=password,
                success=False,
                error_message=str(e)
            )
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a running scan"""
        return self.active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "cancelled"
            return True
        return False
    
    def get_common_credentials(self, service_type: str) -> Dict[str, List[str]]:
        """Get common credentials for specific services"""
        service_credentials = {
            "ssh": {
                "usernames": ["root", "admin", "user", "ubuntu", "centos", "ec2-user"],
                "passwords": ["password", "123456", "root", "admin", "toor", "pass"]
            },
            "ftp": {
                "usernames": ["ftp", "anonymous", "admin", "user", "test"],
                "passwords": ["ftp", "anonymous", "password", "123456", ""]
            },
            "mysql": {
                "usernames": ["root", "mysql", "admin", "user", "test"],
                "passwords": ["password", "123456", "root", "mysql", "", "admin"]
            },
            "postgres": {
                "usernames": ["postgres", "admin", "user", "test"],
                "passwords": ["password", "123456", "postgres", "admin", ""]
            }
        }
        
        return service_credentials.get(service_type, {
            "usernames": self.default_usernames,
            "passwords": self.default_passwords
        })
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to cleanup Hydra temp directory: {e}")

# Global instance
hydra_integration = HydraIntegration()