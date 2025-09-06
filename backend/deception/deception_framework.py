#!/usr/bin/env python3
"""
Advanced Deception Technology Framework
Comprehensive honeypot deployment, canary tokens, and decoy environments
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import hashlib
import uuid
import http.server
import socketserver
import random
import string

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deception_framework")

@dataclass
class HoneypotConfig:
    """Configuration for individual honeypots"""
    honeypot_id: str
    network_segment: str
    service_type: str  # ssh, http, ftp, smb, etc.
    port: int
    decoy_data: Dict[str, Any]
    interaction_logging: bool = True
    alert_threshold: int = 1
    auto_isolation: bool = False

@dataclass
class CanaryToken:
    """Canary token configuration"""
    token_id: str
    token_type: str  # file, email, url, dns, web, database
    trigger_action: str
    target_system: str
    placement_path: str
    creation_time: datetime
    metadata: Dict[str, Any]
    is_triggered: bool = False
    trigger_count: int = 0

@dataclass
class DecoyEnvironment:
    """Decoy environment configuration"""
    environment_id: str
    environment_type: str  # production, development, staging
    services: List[str]
    fake_credentials: List[Dict[str, str]]
    network_topology: Dict[str, Any]
    bait_files: List[str]
    interaction_logs: List[Dict[str, Any]]
    is_active: bool = True

@dataclass
class DeceptionAlert:
    """Alert structure for deception events"""
    alert_id: str
    source_type: str  # honeypot, canary, decoy
    source_id: str
    attacker_ip: str
    timestamp: datetime
    attack_details: Dict[str, Any]
    severity: str  # low, medium, high, critical
    response_actions: List[str]

class DistributedHoneypotManager:
    """Manages distributed honeypots across network segments"""
    
    def __init__(self, config_dir: str = "/tmp/honeypots"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.active_honeypots: Dict[str, HoneypotConfig] = {}
        self.honeypot_servers: Dict[str, Any] = {}
        self.alert_callbacks: List[callable] = []
        
    def deploy_honeypot(self, config: HoneypotConfig) -> bool:
        """Deploy a new honeypot in specified network segment"""
        try:
            honeypot_path = self.config_dir / config.honeypot_id
            honeypot_path.mkdir(exist_ok=True)
            
            # Save configuration
            config_file = honeypot_path / "config.json"
            with open(config_file, 'w') as f:
                json.dump(asdict(config), f, indent=2, default=str)
            
            # Deploy based on service type
            if config.service_type == "http":
                self._deploy_http_honeypot(config)
            elif config.service_type == "ssh":
                self._deploy_ssh_honeypot(config)
            elif config.service_type == "ftp":
                self._deploy_ftp_honeypot(config)
            elif config.service_type == "smb":
                self._deploy_smb_honeypot(config)
            
            self.active_honeypots[config.honeypot_id] = config
            logger.info(f"Deployed honeypot {config.honeypot_id} in {config.network_segment}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deploy honeypot {config.honeypot_id}: {e}")
            return False
    
    def _deploy_http_honeypot(self, config: HoneypotConfig):
        """Deploy HTTP honeypot"""
        class HTTPHoneypotHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.honeypot_config = config
                super().__init__(*args, directory=str(self.config_dir / config.honeypot_id), **kwargs)
            
            def log_message(self, format, *args):
                client_ip = self.client_address[0]
                logger.warning(f"HTTP honeypot {config.honeypot_id} accessed from {client_ip}")
                
                # Generate alert
                alert = DeceptionAlert(
                    alert_id=str(uuid.uuid4()),
                    source_type="honeypot",
                    source_id=config.honeypot_id,
                    attacker_ip=client_ip,
                    timestamp=datetime.now(),
                    attack_details={
                        "method": self.command,
                        "path": self.path,
                        "user_agent": self.headers.get('User-Agent', 'Unknown')
                    },
                    severity="medium",
                    response_actions=["log", "alert"]
                )
                
                for callback in self.server.deception_manager.alert_callbacks:
                    callback(alert)
        
        # Create HTTP server
        handler = HTTPHoneypotHandler
        server = socketserver.TCPServer(("0.0.0.0", config.port), handler)
        server.deception_manager = self
        
        # Start server in background thread
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        
        self.honeypot_servers[config.honeypot_id] = server
    
    def _deploy_ssh_honeypot(self, config: HoneypotConfig):
        """Deploy SSH honeypot using paramiko"""
        try:
            import paramiko
            
            class SSHHoneypotServer(paramiko.ServerInterface):
                def __init__(self, config, deception_manager):
                    self.config = config
                    self.deception_manager = deception_manager
                    self.event = threading.Event()
                
                def check_channel_request(self, kind, chanid):
                    if kind == 'session':
                        return paramiko.OPEN_SUCCEEDED
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                
                def check_auth_password(self, username, password):
                    client_ip = self.transport.getpeername()[0]
                    
                    # Generate alert for any login attempt
                    alert = DeceptionAlert(
                        alert_id=str(uuid.uuid4()),
                        source_type="honeypot",
                        source_id=self.config.honeypot_id,
                        attacker_ip=client_ip,
                        timestamp=datetime.now(),
                        attack_details={
                            "username": username,
                            "password": password,
                            "service": "ssh"
                        },
                        severity="high",
                        response_actions=["log", "alert"]
                    )
                    
                    for callback in self.deception_manager.alert_callbacks:
                        callback(alert)
                    
                    return paramiko.AUTH_FAILED
            
            # SSH server setup would go here
            logger.info(f"SSH honeypot {config.honeypot_id} configured (simulation mode)")
            
        except ImportError:
            logger.warning("Paramiko not available, SSH honeypot in simulation mode")
    
    def _deploy_ftp_honeypot(self, config: HoneypotConfig):
        """Deploy FTP honeypot"""
        logger.info(f"FTP honeypot {config.honeypot_id} configured (simulation mode)")
    
    def _deploy_smb_honeypot(self, config: HoneypotConfig):
        """Deploy SMB honeypot"""
        logger.info(f"SMB honeypot {config.honeypot_id} configured (simulation mode)")
    
    def register_alert_callback(self, callback: callable):
        """Register callback for deception alerts"""
        self.alert_callbacks.append(callback)
    
    def get_active_honeypots(self) -> List[HoneypotConfig]:
        """Get list of active honeypots"""
        return list(self.active_honeypots.values())
    
    def remove_honeypot(self, honeypot_id: str) -> bool:
        """Remove a honeypot"""
        if honeypot_id in self.honeypot_servers:
            server = self.honeypot_servers[honeypot_id]
            server.shutdown()
            del self.honeypot_servers[honeypot_id]
        
        if honeypot_id in self.active_honeypots:
            del self.active_honeypots[honeypot_id]
            logger.info(f"Removed honeypot {honeypot_id}")
            return True
        
        return False

class CanaryTokenManager:
    """Manages canary tokens across systems"""
    
    def __init__(self, token_dir: str = "/tmp/canary_tokens"):
        self.token_dir = Path(token_dir)
        self.token_dir.mkdir(exist_ok=True)
        self.active_tokens: Dict[str, CanaryToken] = {}
        self.alert_callbacks: List[callable] = []
    
    def create_file_token(self, filename: str, target_path: str, 
                         trigger_action: str = "alert") -> Optional[CanaryToken]:
        """Create file-based canary token"""
        try:
            token_id = str(uuid.uuid4())
            token = CanaryToken(
                token_id=token_id,
                token_type="file",
                trigger_action=trigger_action,
                target_system=socket.gethostname(),
                placement_path=target_path,
                creation_time=datetime.now(),
                metadata={"filename": filename, "size": 1024}
            )
            
            # Create decoy file
            full_path = Path(target_path) / filename
            decoy_content = self._generate_decoy_file_content(token_id)
            
            with open(full_path, 'w') as f:
                f.write(decoy_content)
            
            # Set up file monitoring
            self._setup_file_monitoring(full_path, token)
            
            self.active_tokens[token_id] = token
            logger.info(f"Created file canary token: {filename} at {target_path}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to create file canary token: {e}")
            return None
    
    def create_dns_token(self, domain: str, subdomain: str) -> Optional[CanaryToken]:
        """Create DNS-based canary token"""
        try:
            token_id = str(uuid.uuid4())
            token = CanaryToken(
                token_id=token_id,
                token_type="dns",
                trigger_action="alert",
                target_system=socket.gethostname(),
                placement_path=f"{subdomain}.{domain}",
                creation_time=datetime.now(),
                metadata={"domain": domain, "subdomain": subdomain}
            )
            
            self.active_tokens[token_id] = token
            logger.info(f"Created DNS canary token: {subdomain}.{domain}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to create DNS canary token: {e}")
            return None
    
    def create_web_token(self, url: str, target_system: str) -> Optional[CanaryToken]:
        """Create web-based canary token"""
        try:
            token_id = str(uuid.uuid4())
            token = CanaryToken(
                token_id=token_id,
                token_type="web",
                trigger_action="alert",
                target_system=target_system,
                placement_path=url,
                creation_time=datetime.now(),
                metadata={"url": url, "method": "GET"}
            )
            
            self.active_tokens[token_id] = token
            logger.info(f"Created web canary token: {url}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to create web canary token: {e}")
            return None
    
    def _generate_decoy_file_content(self, token_id: str) -> str:
        """Generate believable decoy file content"""
        fake_data = {
            "database": {
                "host": "prod-db-01.internal",
                "port": 5432,
                "username": "admin",
                "password": "SuperSecret2024!",
                "database": "customer_records"
            },
            "api": {
                "endpoint": "https://api.company.com/v1",
                "key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
                "webhook": "https://webhook.company.com/notifications"
            },
            "s3": {
                "bucket": "company-backups",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }
        
        return json.dumps(fake_data, indent=2)
    
    def _setup_file_monitoring(self, file_path: Path, token: CanaryToken):
        """Set up file access monitoring"""
        # This would use inotify or similar for real monitoring
        # For now, we'll create a simple trigger mechanism
        pass
    
    def trigger_token(self, token_id: str, details: Dict[str, Any]):
        """Trigger a canary token"""
        if token_id in self.active_tokens:
            token = self.active_tokens[token_id]
            token.is_triggered = True
            token.trigger_count += 1
            
            alert = DeceptionAlert(
                alert_id=str(uuid.uuid4()),
                source_type="canary",
                source_id=token_id,
                attacker_ip=details.get("source_ip", "unknown"),
                timestamp=datetime.now(),
                attack_details=details,
                severity="high",
                response_actions=["alert", "log", "isolate"]
            )
            
            for callback in self.alert_callbacks:
                callback(alert)
            
            logger.warning(f"Canary token triggered: {token_id}")
    
    def register_alert_callback(self, callback: callable):
        """Register callback for canary alerts"""
        self.alert_callbacks.append(callback)
    
    def get_active_tokens(self) -> List[CanaryToken]:
        """Get list of active canary tokens"""
        return list(self.active_tokens.values())

class DecoyEnvironmentManager:
    """Manages believable decoy environments"""
    
    def __init__(self, env_dir: str = "/tmp/decoy_envs"):
        self.env_dir = Path(env_dir)
        self.env_dir.mkdir(exist_ok=True)
        self.active_environments: Dict[str, DecoyEnvironment] = {}
        self.alert_callbacks: List[callable] = []
    
    def create_production_decoy(self, env_id: str) -> bool:
        """Create a production-like decoy environment"""
        try:
            env = DecoyEnvironment(
                environment_id=env_id,
                environment_type="production",
                services=["nginx", "mysql", "redis", "elasticsearch"],
                fake_credentials=[
                    {"username": "admin", "password": "ProdAdmin2024!", "role": "admin"},
                    {"username": "deploy", "password": "DeployKey2024!", "role": "deploy"},
                    {"username": "monitor", "password": "MonPass2024!", "role": "monitor"}
                ],
                network_topology={
                    "subnets": ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"],
                    "gateways": ["10.0.1.1", "10.0.2.1", "10.0.3.1"],
                    "vlans": [100, 200, 300]
                },
                bait_files=[
                    "/opt/app/secrets.env",
                    "/var/backups/database.sql",
                    "/home/admin/.ssh/id_rsa",
                    "/etc/nginx/sites-available/api.conf"
                ],
                interaction_logs=[]
            )
            
            return self._setup_environment(env)
            
        except Exception as e:
            logger.error(f"Failed to create production decoy: {e}")
            return False
    
    def create_development_decoy(self, env_id: str) -> bool:
        """Create a development-like decoy environment"""
        try:
            env = DecoyEnvironment(
                environment_id=env_id,
                environment_type="development",
                services=["nodejs", "mongodb", "redis", "jenkins"],
                fake_credentials=[
                    {"username": "dev", "password": "DevPass2024!", "role": "developer"},
                    {"username": "test", "password": "TestKey2024!", "role": "test"},
                    {"username": "build", "password": "Build2024!", "role": "ci"}
                ],
                network_topology={
                    "subnets": ["192.168.1.0/24"],
                    "gateways": ["192.168.1.1"],
                    "vlans": [10]
                },
                bait_files=[
                    "/workspace/.env.local",
                    "/workspace/package.json",
                    "/workspace/docker-compose.yml",
                    "/home/dev/.npmrc"
                ],
                interaction_logs=[]
            )
            
            return self._setup_environment(env)
            
        except Exception as e:
            logger.error(f"Failed to create development decoy: {e}")
            return False
    
    def _setup_environment(self, env: DecoyEnvironment) -> bool:
        """Set up the decoy environment"""
        try:
            env_path = self.env_dir / env.environment_id
            env_path.mkdir(exist_ok=True)
            
            # Create bait files
            for file_path in env.bait_files:
                full_path = env_path / file_path.lstrip('/')
                full_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Generate fake content
                content = self._generate_bait_file_content(env.environment_type, file_path)
                with open(full_path, 'w') as f:
                    f.write(content)
            
            # Save environment configuration
            config_file = env_path / "environment.json"
            with open(config_file, 'w') as f:
                json.dump(asdict(env), f, indent=2, default=str)
            
            self.active_environments[env.environment_id] = env
            logger.info(f"Created decoy environment: {env.environment_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup environment {env.environment_id}: {e}")
            return False
    
    def _generate_bait_file_content(self, env_type: str, file_path: str) -> str:
        """Generate realistic bait file content"""
        if ".env" in file_path:
            return self._generate_env_file(env_type)
        elif "package.json" in file_path:
            return self._generate_package_json()
        elif "docker-compose" in file_path:
            return self._generate_docker_compose()
        elif ".ssh/id_rsa" in file_path:
            return self._generate_fake_ssh_key()
        elif ".npmrc" in file_path:
            return self._generate_npmrc()
        else:
            return "# Decoy file content"
    
    def _generate_env_file(self, env_type: str) -> str:
        """Generate realistic environment file"""
        if env_type == "production":
            return """# Production Environment Variables
NODE_ENV=production
DB_HOST=prod-db-01.internal
DB_PORT=5432
DB_NAME=customer_db
DB_USER=app_user
DB_PASSWORD=ProdSecure2024!
REDIS_URL=redis://prod-redis-01:6379
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
API_KEY=sk_prod_4eC39HqLyjWDarjtT1zdp7dc
WEBHOOK_SECRET=whsec_test_secret
"""
        else:
            return """# Development Environment Variables
NODE_ENV=development
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dev_db
DB_USER=dev_user
DB_PASSWORD=DevPass2024!
REDIS_URL=redis://localhost:6379
JWT_SECRET=dev_secret_key
API_KEY=sk_dev_test_key
WEBHOOK_SECRET=dev_webhook_secret
"""
    
    def _generate_package_json(self) -> str:
        """Generate realistic package.json"""
        return json.dumps({
            "name": "company-api",
            "version": "2.1.0",
            "description": "Internal company API service",
            "main": "index.js",
            "scripts": {
                "start": "node index.js",
                "dev": "nodemon index.js",
                "test": "jest",
                "build": "webpack --mode production"
            },
            "dependencies": {
                "express": "^4.18.2",
                "mongoose": "^7.5.0",
                "redis": "^4.6.7",
                "jsonwebtoken": "^9.0.2",
                "bcryptjs": "^2.4.3"
            },
            "devDependencies": {
                "nodemon": "^3.0.1",
                "jest": "^29.6.2",
                "webpack": "^5.88.2"
            }
        }, indent=2)
    
    def _generate_docker_compose(self) -> str:
        """Generate realistic docker-compose.yml"""
        return """version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - db
      - redis
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: customer_db
      POSTGRES_USER: app_user
      POSTGRES_PASSWORD: ProdSecure2024!
    volumes:
      - postgres_data:/var/lib/postgresql/data
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
"""
    
    def _generate_fake_ssh_key(self) -> str:
        """Generate fake SSH private key"""
        return """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDkKx3+K4mK3mY9z6v5h8t2q9K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7