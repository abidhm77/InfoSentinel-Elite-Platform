#!/usr/bin/env python3
"""
Directory Scanner Integration Module
Provides directory and content discovery using Gobuster and Dirb
"""

import subprocess
import json
import logging
import threading
import time
import os
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import requests
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class ScanTool(Enum):
    GOBUSTER = "gobuster"
    DIRB = "dirb"
    CUSTOM = "custom"

class ContentType(Enum):
    DIRECTORY = "directory"
    FILE = "file"
    UNKNOWN = "unknown"

@dataclass
class DiscoveredContent:
    """Represents discovered content (file or directory)"""
    url: str
    path: str
    status_code: int
    content_length: int
    content_type: ContentType
    response_time: float = 0.0
    server_header: str = ""
    interesting: bool = False
    description: str = ""
    
@dataclass
class DirectoryScanResult:
    """Represents complete directory scan results"""
    target_url: str
    scan_start: datetime
    scan_end: datetime
    tool_used: ScanTool
    wordlist_used: str
    total_requests: int
    discovered_content: List[DiscoveredContent]
    scan_statistics: Dict
    status: str
    error_message: str = ""

class DirectoryScanner:
    """Directory and content discovery scanner"""
    
    def __init__(self):
        self.gobuster_path = self._find_tool_path("gobuster")
        self.dirb_path = self._find_tool_path("dirb")
        self.temp_dir = tempfile.mkdtemp(prefix="dirscan_")
        self.active_scans = {}
        
        # Built-in wordlists
        self.wordlists = {
            "common": [
                "admin", "administrator", "login", "test", "backup", "config",
                "uploads", "images", "css", "js", "api", "v1", "v2", "docs",
                "documentation", "help", "support", "contact", "about",
                "index", "home", "dashboard", "panel", "control", "manage",
                "files", "download", "upload", "tmp", "temp", "cache",
                "logs", "log", "debug", "error", "errors", "status"
            ],
            "files": [
                "robots.txt", "sitemap.xml", ".htaccess", "web.config",
                "crossdomain.xml", "clientaccesspolicy.xml", "favicon.ico",
                "readme.txt", "README.md", "CHANGELOG.md", "LICENSE",
                "config.php", "config.xml", "config.json", "settings.xml",
                "backup.sql", "database.sql", "dump.sql", "phpinfo.php",
                "test.php", "info.php", "version.txt", "VERSION"
            ],
            "admin": [
                "admin", "administrator", "administration", "manage", "manager",
                "control", "controlpanel", "cp", "dashboard", "panel",
                "login", "signin", "auth", "authentication", "user",
                "users", "account", "accounts", "profile", "settings"
            ],
            "api": [
                "api", "v1", "v2", "v3", "rest", "restapi", "graphql",
                "endpoints", "services", "webservice", "ws", "json",
                "xml", "soap", "rpc", "jsonrpc", "xmlrpc"
            ]
        }
        
        # File extensions to discover
        self.extensions = [
            "php", "asp", "aspx", "jsp", "html", "htm", "js", "css",
            "txt", "xml", "json", "sql", "bak", "old", "orig", "tmp",
            "log", "conf", "config", "ini", "yaml", "yml"
        ]
    
    def _find_tool_path(self, tool_name: str) -> Optional[str]:
        """Find tool executable path"""
        possible_paths = {
            "gobuster": [
                "/usr/bin/gobuster",
                "/usr/local/bin/gobuster",
                "gobuster"
            ],
            "dirb": [
                "/usr/bin/dirb",
                "/usr/local/bin/dirb",
                "dirb"
            ]
        }
        
        for path in possible_paths.get(tool_name, []):
            try:
                result = subprocess.run([path, "--help"], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=10)
                if result.returncode == 0 or tool_name.lower() in result.stderr.lower():
                    logger.info(f"Found {tool_name} at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning(f"{tool_name} not found")
        return None
    
    def scan_directories(self, scan_id: str, target_url: str, 
                        tool: ScanTool = ScanTool.GOBUSTER,
                        wordlist: str = "common", options: Dict = None) -> str:
        """Start directory discovery scan"""
        options = options or {}
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_directory_scan,
            args=(scan_id, target_url, tool, wordlist, options)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_directory_scan(self, scan_id: str, target_url: str,
                           tool: ScanTool, wordlist: str, options: Dict):
        """Execute directory discovery scan"""
        try:
            self.active_scans[scan_id] = {
                "status": "running",
                "start_time": datetime.now(),
                "target": target_url,
                "tool": tool.value,
                "wordlist": wordlist,
                "progress": 0
            }
            
            start_time = datetime.now()
            
            # Choose scanning method
            if tool == ScanTool.GOBUSTER and self.gobuster_path:
                results = self._run_gobuster_scan(scan_id, target_url, wordlist, options)
            elif tool == ScanTool.DIRB and self.dirb_path:
                results = self._run_dirb_scan(scan_id, target_url, wordlist, options)
            else:
                # Fallback to custom implementation
                results = self._run_custom_scan(scan_id, target_url, wordlist, options)
            
            end_time = datetime.now()
            
            # Update scan status
            self.active_scans[scan_id].update({
                "status": "completed",
                "progress": 100,
                "results": results,
                "end_time": end_time
            })
            
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
            self.active_scans[scan_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
    
    def _run_gobuster_scan(self, scan_id: str, target_url: str,
                          wordlist: str, options: Dict) -> DirectoryScanResult:
        """Run Gobuster directory scan"""
        # Prepare wordlist file
        wordlist_file = self._create_wordlist_file(wordlist, options)
        
        try:
            # Build Gobuster command
            cmd = self._build_gobuster_command(target_url, wordlist_file, options)
            
            logger.info(f"Starting Gobuster scan: {' '.join(cmd)}")
            
            # Execute Gobuster
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress and collect output
            output_lines = []
            while process.poll() is None:
                line = process.stdout.readline()
                if line:
                    output_lines.append(line.strip())
                    self.active_scans[scan_id]["progress"] += 1
                time.sleep(0.1)
            
            # Get remaining output
            remaining_stdout, stderr = process.communicate()
            output_lines.extend(remaining_stdout.split('\n'))
            
            # Parse results
            discovered_content = self._parse_gobuster_output(output_lines, target_url)
            
            return DirectoryScanResult(
                target_url=target_url,
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                tool_used=ScanTool.GOBUSTER,
                wordlist_used=wordlist,
                total_requests=len(discovered_content),
                discovered_content=discovered_content,
                scan_statistics={"found_items": len(discovered_content)},
                status="completed"
            )
            
        finally:
            # Clean up wordlist file
            try:
                os.remove(wordlist_file)
            except:
                pass
    
    def _run_dirb_scan(self, scan_id: str, target_url: str,
                      wordlist: str, options: Dict) -> DirectoryScanResult:
        """Run Dirb directory scan"""
        # Prepare wordlist file
        wordlist_file = self._create_wordlist_file(wordlist, options)
        
        try:
            # Build Dirb command
            cmd = self._build_dirb_command(target_url, wordlist_file, options)
            
            logger.info(f"Starting Dirb scan: {' '.join(cmd)}")
            
            # Execute Dirb
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get("timeout", 600)
            )
            
            # Parse results
            discovered_content = self._parse_dirb_output(process.stdout, target_url)
            
            return DirectoryScanResult(
                target_url=target_url,
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                tool_used=ScanTool.DIRB,
                wordlist_used=wordlist,
                total_requests=len(discovered_content),
                discovered_content=discovered_content,
                scan_statistics={"found_items": len(discovered_content)},
                status="completed"
            )
            
        finally:
            # Clean up wordlist file
            try:
                os.remove(wordlist_file)
            except:
                pass
    
    def _run_custom_scan(self, scan_id: str, target_url: str,
                        wordlist: str, options: Dict) -> DirectoryScanResult:
        """Run custom directory scan implementation"""
        discovered_content = []
        
        # Get wordlist
        words = self._get_wordlist(wordlist, options)
        
        # Add extensions if specified
        if options.get("extensions"):
            extended_words = []
            for word in words:
                extended_words.append(word)
                for ext in options["extensions"]:
                    extended_words.append(f"{word}.{ext}")
            words = extended_words
        
        total_words = len(words)
        
        # Test each word
        for i, word in enumerate(words):
            try:
                # Update progress
                progress = int((i / total_words) * 100)
                self.active_scans[scan_id]["progress"] = progress
                
                # Test URL
                test_url = urljoin(target_url.rstrip('/') + '/', word)
                
                start_time = time.time()
                response = requests.get(
                    test_url,
                    timeout=options.get("timeout", 10),
                    allow_redirects=False,
                    verify=False
                )
                response_time = time.time() - start_time
                
                # Check if content was found
                if self._is_valid_response(response, options):
                    content_type = self._determine_content_type(test_url, response)
                    
                    discovered_content.append(DiscoveredContent(
                        url=test_url,
                        path=word,
                        status_code=response.status_code,
                        content_length=len(response.content),
                        content_type=content_type,
                        response_time=response_time,
                        server_header=response.headers.get('Server', ''),
                        interesting=self._is_interesting_content(word, response),
                        description=self._get_content_description(word, response)
                    ))
                
            except requests.RequestException:
                # Skip failed requests
                continue
            except Exception as e:
                logger.warning(f"Error testing {word}: {e}")
                continue
        
        return DirectoryScanResult(
            target_url=target_url,
            scan_start=datetime.now(),
            scan_end=datetime.now(),
            tool_used=ScanTool.CUSTOM,
            wordlist_used=wordlist,
            total_requests=total_words,
            discovered_content=discovered_content,
            scan_statistics={"found_items": len(discovered_content)},
            status="completed"
        )
    
    def _create_wordlist_file(self, wordlist: str, options: Dict) -> str:
        """Create temporary wordlist file"""
        words = self._get_wordlist(wordlist, options)
        
        # Add extensions if specified
        if options.get("extensions"):
            extended_words = []
            for word in words:
                extended_words.append(word)
                for ext in options["extensions"]:
                    extended_words.append(f"{word}.{ext}")
            words = extended_words
        
        wordlist_file = os.path.join(self.temp_dir, f"wordlist_{int(time.time())}.txt")
        
        with open(wordlist_file, 'w') as f:
            for word in words:
                f.write(f"{word}\n")
        
        return wordlist_file
    
    def _get_wordlist(self, wordlist: str, options: Dict) -> List[str]:
        """Get wordlist based on name or custom list"""
        if wordlist in self.wordlists:
            return self.wordlists[wordlist]
        elif options.get("custom_wordlist"):
            return options["custom_wordlist"]
        else:
            # Default to common wordlist
            return self.wordlists["common"]
    
    def _build_gobuster_command(self, target_url: str, wordlist_file: str,
                               options: Dict) -> List[str]:
        """Build Gobuster command"""
        cmd = [self.gobuster_path, "dir"]
        
        # Target URL
        cmd.extend(["-u", target_url])
        
        # Wordlist
        cmd.extend(["-w", wordlist_file])
        
        # Status codes to include
        status_codes = options.get("status_codes", "200,204,301,302,307,401,403")
        cmd.extend(["-s", status_codes])
        
        # Threads
        threads = options.get("threads", 10)
        cmd.extend(["-t", str(threads)])
        
        # Timeout
        timeout = options.get("timeout", 10)
        cmd.extend(["--timeout", f"{timeout}s"])
        
        # User agent
        if options.get("user_agent"):
            cmd.extend(["-a", options["user_agent"]])
        
        # Cookies
        if options.get("cookies"):
            cmd.extend(["-c", options["cookies"]])
        
        # Headers
        if options.get("headers"):
            for header, value in options["headers"].items():
                cmd.extend(["-H", f"{header}: {value}"])
        
        # Follow redirects
        if options.get("follow_redirects", False):
            cmd.append("-r")
        
        # Quiet mode
        cmd.append("-q")
        
        return cmd
    
    def _build_dirb_command(self, target_url: str, wordlist_file: str,
                           options: Dict) -> List[str]:
        """Build Dirb command"""
        cmd = [self.dirb_path, target_url, wordlist_file]
        
        # Silent mode
        cmd.append("-S")
        
        # Don't search recursively
        cmd.append("-r")
        
        # Extensions
        if options.get("extensions"):
            ext_string = ",".join(options["extensions"])
            cmd.extend(["-X", ext_string])
        
        return cmd
    
    def _parse_gobuster_output(self, output_lines: List[str], target_url: str) -> List[DiscoveredContent]:
        """Parse Gobuster output"""
        discovered_content = []
        
        for line in output_lines:
            line = line.strip()
            if line.startswith('/') and '(Status:' in line:
                try:
                    # Parse line format: /path (Status: 200) [Size: 1234]
                    path = line.split(' ')[0]
                    status_match = line.split('Status: ')[1].split(')')[0]
                    status_code = int(status_match)
                    
                    size_match = line.split('[Size: ')[1].split(']')[0] if '[Size:' in line else '0'
                    content_length = int(size_match)
                    
                    full_url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
                    content_type = ContentType.DIRECTORY if path.endswith('/') else ContentType.FILE
                    
                    discovered_content.append(DiscoveredContent(
                        url=full_url,
                        path=path,
                        status_code=status_code,
                        content_length=content_length,
                        content_type=content_type,
                        interesting=self._is_interesting_path(path)
                    ))
                    
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse Gobuster line: {line} - {e}")
        
        return discovered_content
    
    def _parse_dirb_output(self, output: str, target_url: str) -> List[DiscoveredContent]:
        """Parse Dirb output"""
        discovered_content = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('+ ') and '(CODE:' in line:
                try:
                    # Parse line format: + http://target/path (CODE:200|SIZE:1234)
                    url = line.split(' ')[1]
                    code_part = line.split('(CODE:')[1].split('|')[0]
                    status_code = int(code_part)
                    
                    size_part = line.split('SIZE:')[1].split(')')[0] if 'SIZE:' in line else '0'
                    content_length = int(size_part)
                    
                    path = url.replace(target_url.rstrip('/'), '')
                    content_type = ContentType.DIRECTORY if path.endswith('/') else ContentType.FILE
                    
                    discovered_content.append(DiscoveredContent(
                        url=url,
                        path=path,
                        status_code=status_code,
                        content_length=content_length,
                        content_type=content_type,
                        interesting=self._is_interesting_path(path)
                    ))
                    
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse Dirb line: {line} - {e}")
        
        return discovered_content
    
    def _is_valid_response(self, response: requests.Response, options: Dict) -> bool:
        """Check if response indicates found content"""
        valid_codes = options.get("status_codes", [200, 204, 301, 302, 307, 401, 403])
        if isinstance(valid_codes, str):
            valid_codes = [int(code.strip()) for code in valid_codes.split(',')]
        
        return response.status_code in valid_codes
    
    def _determine_content_type(self, url: str, response: requests.Response) -> ContentType:
        """Determine if content is file or directory"""
        if url.endswith('/'):
            return ContentType.DIRECTORY
        elif '.' in os.path.basename(url):
            return ContentType.FILE
        else:
            # Check Content-Type header
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type:
                return ContentType.DIRECTORY
            else:
                return ContentType.FILE
    
    def _is_interesting_content(self, path: str, response: requests.Response) -> bool:
        """Check if content is particularly interesting"""
        return self._is_interesting_path(path)
    
    def _is_interesting_path(self, path: str) -> bool:
        """Check if path is particularly interesting"""
        interesting_keywords = [
            'admin', 'login', 'config', 'backup', 'database', 'sql',
            'password', 'secret', 'private', 'internal', 'debug',
            'test', 'dev', 'staging', 'api', 'upload', 'download'
        ]
        
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in interesting_keywords)
    
    def _get_content_description(self, path: str, response: requests.Response) -> str:
        """Get description for discovered content"""
        if self._is_interesting_path(path):
            return "Potentially sensitive content discovered"
        elif response.status_code == 403:
            return "Access forbidden - may contain sensitive information"
        elif response.status_code in [301, 302, 307]:
            return "Redirect found - check destination"
        else:
            return "Content discovered"
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a running scan"""
        return self.active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "cancelled"
            return True
        return False
    
    def get_available_wordlists(self) -> Dict[str, List[str]]:
        """Get available built-in wordlists"""
        return {name: wordlist[:10] for name, wordlist in self.wordlists.items()}  # Preview only
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to cleanup directory scanner temp directory: {e}")

# Global instance
directory_scanner = DirectoryScanner()