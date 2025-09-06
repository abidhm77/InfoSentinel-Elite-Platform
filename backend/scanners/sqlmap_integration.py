#!/usr/bin/env python3
"""
SQLMap Integration Module
Provides automated SQL injection testing capabilities using SQLMap
"""

import subprocess
import json
import os
import tempfile
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import threading
import time

logger = logging.getLogger(__name__)

@dataclass
class SQLMapResult:
    """Represents SQLMap scan results"""
    target_url: str
    vulnerable: bool
    injection_type: str = ""
    dbms: str = ""
    payload: str = ""
    parameter: str = ""
    technique: str = ""
    risk_level: str = "medium"
    confidence: int = 0
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}

class SQLMapScanner:
    """SQLMap integration for automated SQL injection testing"""
    
    def __init__(self):
        self.sqlmap_path = self._find_sqlmap_path()
        self.temp_dir = tempfile.mkdtemp(prefix="sqlmap_")
        self.active_scans = {}
        
    def _find_sqlmap_path(self) -> str:
        """Find SQLMap executable path"""
        possible_paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
            "sqlmap"
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=10)
                if result.returncode == 0:
                    logger.info(f"Found SQLMap at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        raise RuntimeError("SQLMap not found. Please install SQLMap.")
    
    def scan_url(self, scan_id: str, target_url: str, options: Dict = None) -> str:
        """Start SQLMap scan for a target URL"""
        options = options or {}
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_sqlmap_scan,
            args=(scan_id, target_url, options)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_sqlmap_scan(self, scan_id: str, target_url: str, options: Dict):
        """Execute SQLMap scan"""
        try:
            self.active_scans[scan_id] = {
                "status": "running",
                "start_time": datetime.now(),
                "target": target_url,
                "progress": 0
            }
            
            # Build SQLMap command
            cmd = self._build_sqlmap_command(target_url, options)
            
            logger.info(f"Starting SQLMap scan: {' '.join(cmd)}")
            
            # Execute SQLMap
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.temp_dir
            )
            
            # Monitor progress
            results = []
            while process.poll() is None:
                time.sleep(2)
                self.active_scans[scan_id]["progress"] += 5
                if self.active_scans[scan_id]["progress"] > 90:
                    self.active_scans[scan_id]["progress"] = 90
            
            stdout, stderr = process.communicate()
            
            # Parse results
            if process.returncode == 0:
                results = self._parse_sqlmap_output(stdout, target_url)
                self.active_scans[scan_id].update({
                    "status": "completed",
                    "progress": 100,
                    "results": results,
                    "end_time": datetime.now()
                })
            else:
                logger.error(f"SQLMap scan failed: {stderr}")
                self.active_scans[scan_id].update({
                    "status": "failed",
                    "error": stderr,
                    "end_time": datetime.now()
                })
                
        except Exception as e:
            logger.error(f"SQLMap scan error: {e}")
            self.active_scans[scan_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
    
    def _build_sqlmap_command(self, target_url: str, options: Dict) -> List[str]:
        """Build SQLMap command with options"""
        cmd = [self.sqlmap_path]
        
        # Target URL
        cmd.extend(["--url", target_url])
        
        # Basic options
        cmd.extend([
            "--batch",  # Non-interactive mode
            "--random-agent",  # Use random User-Agent
            "--output-dir", self.temp_dir,
            "--format", "json"
        ])
        
        # Risk and level settings
        risk_level = options.get("risk_level", 1)
        level = options.get("level", 1)
        cmd.extend(["--risk", str(risk_level), "--level", str(level)])
        
        # Technique options
        if options.get("techniques"):
            cmd.extend(["--technique", options["techniques"]])
        
        # Database enumeration
        if options.get("enumerate_dbs", False):
            cmd.append("--dbs")
        
        if options.get("enumerate_tables", False):
            cmd.append("--tables")
        
        # Custom headers
        if options.get("headers"):
            for header, value in options["headers"].items():
                cmd.extend(["--header", f"{header}: {value}"])
        
        # POST data
        if options.get("data"):
            cmd.extend(["--data", options["data"]])
        
        # Cookies
        if options.get("cookies"):
            cmd.extend(["--cookie", options["cookies"]])
        
        # Timeout settings
        timeout = options.get("timeout", 30)
        cmd.extend(["--timeout", str(timeout)])
        
        # Threads
        threads = options.get("threads", 1)
        cmd.extend(["--threads", str(threads)])
        
        return cmd
    
    def _parse_sqlmap_output(self, output: str, target_url: str) -> List[SQLMapResult]:
        """Parse SQLMap output and extract vulnerabilities"""
        results = []
        
        try:
            # Look for injection indicators in output
            lines = output.split('\n')
            current_result = None
            
            for line in lines:
                line = line.strip()
                
                # Check for vulnerability indicators
                if "Parameter:" in line:
                    if current_result:
                        results.append(current_result)
                    
                    current_result = SQLMapResult(
                        target_url=target_url,
                        vulnerable=True,
                        parameter=line.split("Parameter:")[1].strip()
                    )
                
                elif current_result and "Type:" in line:
                    current_result.injection_type = line.split("Type:")[1].strip()
                
                elif current_result and "Title:" in line:
                    current_result.technique = line.split("Title:")[1].strip()
                
                elif current_result and "Payload:" in line:
                    current_result.payload = line.split("Payload:")[1].strip()
                
                elif "back-end DBMS:" in line:
                    if current_result:
                        current_result.dbms = line.split("back-end DBMS:")[1].strip()
            
            # Add the last result
            if current_result:
                results.append(current_result)
            
            # If no vulnerabilities found, create a clean result
            if not results and "no injection point(s)" not in output.lower():
                results.append(SQLMapResult(
                    target_url=target_url,
                    vulnerable=False,
                    details={"message": "No SQL injection vulnerabilities detected"}
                ))
                
        except Exception as e:
            logger.error(f"Error parsing SQLMap output: {e}")
            results.append(SQLMapResult(
                target_url=target_url,
                vulnerable=False,
                details={"error": f"Failed to parse results: {str(e)}"}
            ))
        
        return results
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a running scan"""
        return self.active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "cancelled"
            return True
        return False
    
    def scan_forms(self, scan_id: str, target_url: str, forms_data: List[Dict]) -> List[SQLMapResult]:
        """Scan multiple forms for SQL injection"""
        all_results = []
        
        for i, form_data in enumerate(forms_data):
            form_scan_id = f"{scan_id}_form_{i}"
            
            # Prepare form-specific options
            options = {
                "data": form_data.get("data", ""),
                "headers": form_data.get("headers", {}),
                "risk_level": 2,  # Higher risk for form testing
                "level": 3
            }
            
            # Run scan for this form
            self._run_sqlmap_scan(form_scan_id, target_url, options)
            
            # Wait for completion (simplified for demo)
            while self.active_scans.get(form_scan_id, {}).get("status") == "running":
                time.sleep(1)
            
            # Collect results
            scan_result = self.active_scans.get(form_scan_id, {})
            if scan_result.get("results"):
                all_results.extend(scan_result["results"])
        
        return all_results
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to cleanup SQLMap temp directory: {e}")

# Global instance
sqlmap_scanner = SQLMapScanner()