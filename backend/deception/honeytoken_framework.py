#!/usr/bin/env python3
"""
Honeytoken Framework Module

Provides a comprehensive framework for creating, deploying, and monitoring
canary tokens and decoy credentials across enterprise environments.
"""

import os
import json
import uuid
import hashlib
import logging
import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, field


class TokenType(Enum):
    """Types of honeytokens supported by the framework"""
    # File-based tokens
    DOCUMENT = "document"  # Word, Excel, PDF documents
    DATABASE = "database"  # Database entries (fake records)
    FILESYSTEM = "filesystem"  # Files/directories with special monitoring
    
    # Credential-based tokens
    API_KEY = "api_key"  # Fake API keys
    PASSWORD = "password"  # Fake user credentials
    SSH_KEY = "ssh_key"  # SSH keys
    CERTIFICATE = "certificate"  # TLS/SSL certificates
    
    # Web-based tokens
    WEB_BUG = "web_bug"  # Web bugs/tracking pixels
    URL = "url"  # Special URLs that trigger alerts
    DNS = "dns"  # DNS-based canaries
    
    # Cloud-based tokens
    S3_BUCKET = "s3_bucket"  # S3 bucket with monitoring
    CLOUD_RESOURCE = "cloud_resource"  # Monitored cloud resources
    
    # Network-based tokens
    BEACON = "beacon"  # Network beacons
    PORT_KNOCKING = "port_knocking"  # Special port sequences
    
    # Custom tokens
    CUSTOM = "custom"  # Custom implementation


class TokenLocation(Enum):
    """Locations where honeytokens can be deployed"""
    FILESYSTEM = "filesystem"  # Local filesystem
    DATABASE = "database"  # Database systems
    SOURCE_CODE = "source_code"  # Source code repositories
    CLOUD_STORAGE = "cloud_storage"  # Cloud storage services
    EMAIL = "email"  # Email messages
    DOCUMENT = "document"  # Within documents
    BROWSER = "browser"  # Browser storage (cookies, localStorage)
    NETWORK_SHARE = "network_share"  # Network file shares
    MEMORY = "memory"  # In-memory only
    API = "api"  # Exposed via APIs
    CUSTOM = "custom"  # Custom location


class AlertSeverity(Enum):
    """Severity levels for honeytoken alerts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TokenConfig:
    """Configuration for a honeytoken"""
    name: str
    token_type: TokenType
    location: TokenLocation
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    expiration: Optional[datetime.datetime] = None
    alert_channels: List[str] = field(default_factory=list)
    custom_properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        result = {
            "name": self.name,
            "token_type": self.token_type.value,
            "location": self.location.value,
            "description": self.description,
            "severity": self.severity.value,
            "alert_channels": self.alert_channels,
            "custom_properties": self.custom_properties,
            "tags": self.tags
        }
        
        if self.expiration:
            result["expiration"] = self.expiration.isoformat()
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenConfig':
        """Create config from dictionary"""
        config = cls(
            name=data["name"],
            token_type=TokenType(data["token_type"]),
            location=TokenLocation(data["location"]),
            description=data.get("description", ""),
            severity=AlertSeverity(data.get("severity", "medium")),
            alert_channels=data.get("alert_channels", []),
            custom_properties=data.get("custom_properties", {}),
            tags=data.get("tags", [])
        )
        
        if "expiration" in data and data["expiration"]:
            config.expiration = datetime.datetime.fromisoformat(data["expiration"])
            
        return config


class TokenStatus(Enum):
    """Status of a honeytoken"""
    CREATED = "created"  # Token created but not deployed
    DEPLOYED = "deployed"  # Token successfully deployed
    TRIGGERED = "triggered"  # Token has been triggered
    EXPIRED = "expired"  # Token has expired
    DISABLED = "disabled"  # Token manually disabled


@dataclass
class HoneytokenInstance:
    """Represents a deployed honeytoken instance"""
    id: str
    config: TokenConfig
    status: TokenStatus
    value: str  # The actual token value
    created_at: datetime.datetime
    updated_at: datetime.datetime
    deployed_at: Optional[datetime.datetime] = None
    last_triggered: Optional[datetime.datetime] = None
    trigger_count: int = 0
    trigger_details: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert instance to dictionary"""
        result = {
            "id": self.id,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "value": self.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "trigger_count": self.trigger_count,
            "trigger_details": self.trigger_details
        }
        
        if self.deployed_at:
            result["deployed_at"] = self.deployed_at.isoformat()
            
        if self.last_triggered:
            result["last_triggered"] = self.last_triggered.isoformat()
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HoneytokenInstance':
        """Create instance from dictionary"""
        instance = cls(
            id=data["id"],
            config=TokenConfig.from_dict(data["config"]),
            status=TokenStatus(data["status"]),
            value=data["value"],
            created_at=datetime.datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.datetime.fromisoformat(data["updated_at"]),
            trigger_count=data.get("trigger_count", 0),
            trigger_details=data.get("trigger_details", [])
        )
        
        if "deployed_at" in data and data["deployed_at"]:
            instance.deployed_at = datetime.datetime.fromisoformat(data["deployed_at"])
            
        if "last_triggered" in data and data["last_triggered"]:
            instance.last_triggered = datetime.datetime.fromisoformat(data["last_triggered"])
            
        return instance


class HoneytokenFramework:
    """Framework for creating, deploying, and monitoring honeytokens"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger("honeytoken_framework")
        self.tokens: Dict[str, HoneytokenInstance] = {}
        self.config_path = config_path
        
        # Register token generators
        self.token_generators = {
            TokenType.DOCUMENT: self._generate_document_token,
            TokenType.DATABASE: self._generate_database_token,
            TokenType.FILESYSTEM: self._generate_filesystem_token,
            TokenType.API_KEY: self._generate_api_key_token,
            TokenType.PASSWORD: self._generate_password_token,
            TokenType.SSH_KEY: self._generate_ssh_key_token,
            TokenType.CERTIFICATE: self._generate_certificate_token,
            TokenType.WEB_BUG: self._generate_web_bug_token,
            TokenType.URL: self._generate_url_token,
            TokenType.DNS: self._generate_dns_token,
            TokenType.S3_BUCKET: self._generate_s3_bucket_token,
            TokenType.CLOUD_RESOURCE: self._generate_cloud_resource_token,
            TokenType.BEACON: self._generate_beacon_token,
            TokenType.PORT_KNOCKING: self._generate_port_knocking_token,
            TokenType.CUSTOM: self._generate_custom_token
        }
        
        # Register token deployers
        self.token_deployers = {
            TokenLocation.FILESYSTEM: self._deploy_to_filesystem,
            TokenLocation.DATABASE: self._deploy_to_database,
            TokenLocation.SOURCE_CODE: self._deploy_to_source_code,
            TokenLocation.CLOUD_STORAGE: self._deploy_to_cloud_storage,
            TokenLocation.EMAIL: self._deploy_to_email,
            TokenLocation.DOCUMENT: self._deploy_to_document,
            TokenLocation.BROWSER: self._deploy_to_browser,
            TokenLocation.NETWORK_SHARE: self._deploy_to_network_share,
            TokenLocation.MEMORY: self._deploy_to_memory,
            TokenLocation.API: self._deploy_to_api,
            TokenLocation.CUSTOM: self._deploy_to_custom
        }
        
        # Load existing tokens if config path exists
        if config_path and os.path.exists(config_path):
            self.load_state()
    
    def create_token(self, config: TokenConfig) -> HoneytokenInstance:
        """Create a new honeytoken instance"""
        # Generate token value based on type
        if config.token_type not in self.token_generators:
            raise ValueError(f"Unsupported token type: {config.token_type}")
            
        token_value = self.token_generators[config.token_type](config)
        
        # Create instance
        now = datetime.datetime.now()
        instance = HoneytokenInstance(
            id=str(uuid.uuid4()),
            config=config,
            status=TokenStatus.CREATED,
            value=token_value,
            created_at=now,
            updated_at=now
        )
        
        self.tokens[instance.id] = instance
        self.logger.info(f"Created honeytoken {instance.id} of type {config.token_type.value}")
        self.save_state()
        return instance
    
    def deploy_token(self, token_id: str) -> bool:
        """Deploy a honeytoken to its configured location"""
        if token_id not in self.tokens:
            self.logger.error(f"Token {token_id} not found")
            return False
        
        instance = self.tokens[token_id]
        location = instance.config.location
        
        if location not in self.token_deployers:
            self.logger.error(f"Unsupported token location: {location}")
            return False
        
        try:
            result = self.token_deployers[location](instance)
            if result:
                instance.status = TokenStatus.DEPLOYED
                instance.deployed_at = datetime.datetime.now()
                instance.updated_at = datetime.datetime.now()
                self.save_state()
            return result
        except Exception as e:
            self.logger.error(f"Failed to deploy token {token_id}: {str(e)}")
            return False
    
    def disable_token(self, token_id: str) -> bool:
        """Disable a honeytoken"""
        if token_id not in self.tokens:
            self.logger.error(f"Token {token_id} not found")
            return False
        
        instance = self.tokens[token_id]
        instance.status = TokenStatus.DISABLED
        instance.updated_at = datetime.datetime.now()
        self.save_state()
        return True
    
    def delete_token(self, token_id: str) -> bool:
        """Delete a honeytoken"""
        if token_id not in self.tokens:
            self.logger.error(f"Token {token_id} not found")
            return False
        
        del self.tokens[token_id]
        self.save_state()
        return True
    
    def get_token(self, token_id: str) -> Optional[HoneytokenInstance]:
        """Get a honeytoken by ID"""
        return self.tokens.get(token_id)
    
    def list_tokens(self, token_type: Optional[TokenType] = None, 
                   status: Optional[TokenStatus] = None) -> List[HoneytokenInstance]:
        """List honeytokens with optional filtering"""
        results = list(self.tokens.values())
        
        if token_type:
            results = [t for t in results if t.config.token_type == token_type]
        
        if status:
            results = [t for t in results if t.status == status]
            
        return results
    
    def record_trigger(self, token_id: str, details: Dict[str, Any]) -> bool:
        """Record a token trigger event"""
        if token_id not in self.tokens:
            self.logger.error(f"Token {token_id} not found")
            return False
        
        instance = self.tokens[token_id]
        now = datetime.datetime.now()
        
        # Add timestamp to details
        details["timestamp"] = now.isoformat()
        
        # Update instance
        instance.status = TokenStatus.TRIGGERED
        instance.last_triggered = now
        instance.trigger_count += 1
        instance.trigger_details.append(details)
        instance.updated_at = now
        
        # Log the trigger
        self.logger.warning(f"Honeytoken {token_id} triggered: {details}")
        
        # Save state
        self.save_state()
        return True
    
    def save_state(self):
        """Save framework state to disk"""
        if not self.config_path:
            return
        
        data = {
            "tokens": {id: token.to_dict() for id, token in self.tokens.items()}
        }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save state: {str(e)}")
    
    def load_state(self):
        """Load framework state from disk"""
        if not self.config_path or not os.path.exists(self.config_path):
            return
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            
            self.tokens = {}
            for id, token_data in data.get("tokens", {}).items():
                self.tokens[id] = HoneytokenInstance.from_dict(token_data)
                
            self.logger.info(f"Loaded {len(self.tokens)} honeytokens")
        except Exception as e:
            self.logger.error(f"Failed to load state: {str(e)}")
    
    # Token generators
    def _generate_document_token(self, config: TokenConfig) -> str:
        """Generate a document-based token"""
        return f"DOC-{uuid.uuid4()}"
    
    def _generate_database_token(self, config: TokenConfig) -> str:
        """Generate a database-based token"""
        return f"DB-{uuid.uuid4()}"
    
    def _generate_filesystem_token(self, config: TokenConfig) -> str:
        """Generate a filesystem-based token"""
        return f"FS-{uuid.uuid4()}"
    
    def _generate_api_key_token(self, config: TokenConfig) -> str:
        """Generate an API key token"""
        prefix = config.custom_properties.get("prefix", "API-KEY")
        key = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
        return f"{prefix}-{key}"
    
    def _generate_password_token(self, config: TokenConfig) -> str:
        """Generate a password token"""
        return f"Password-{uuid.uuid4().hex[:12]}"
    
    def _generate_ssh_key_token(self, config: TokenConfig) -> str:
        """Generate an SSH key token (simplified)"""
        return f"SSH-KEY-{uuid.uuid4()}"
    
    def _generate_certificate_token(self, config: TokenConfig) -> str:
        """Generate a certificate token (simplified)"""
        return f"CERT-{uuid.uuid4()}"
    
    def _generate_web_bug_token(self, config: TokenConfig) -> str:
        """Generate a web bug token"""
        return f"https://tracking.example.com/pixel/{uuid.uuid4()}.gif"
    
    def _generate_url_token(self, config: TokenConfig) -> str:
        """Generate a URL token"""
        base_url = config.custom_properties.get("base_url", "https://canary.example.com")
        path = uuid.uuid4()
        return f"{base_url}/{path}"
    
    def _generate_dns_token(self, config: TokenConfig) -> str:
        """Generate a DNS token"""
        domain = config.custom_properties.get("domain", "canary.example.com")
        subdomain = uuid.uuid4().hex[:8]
        return f"{subdomain}.{domain}"
    
    def _generate_s3_bucket_token(self, config: TokenConfig) -> str:
        """Generate an S3 bucket token"""
        return f"s3-canary-{uuid.uuid4().hex[:8]}"
    
    def _generate_cloud_resource_token(self, config: TokenConfig) -> str:
        """Generate a cloud resource token"""
        resource_type = config.custom_properties.get("resource_type", "instance")
        return f"{resource_type}-canary-{uuid.uuid4().hex[:8]}"
    
    def _generate_beacon_token(self, config: TokenConfig) -> str:
        """Generate a beacon token"""
        return f"BEACON-{uuid.uuid4()}"
    
    def _generate_port_knocking_token(self, config: TokenConfig) -> str:
        """Generate a port knocking sequence"""
        # Generate a sequence of 4 ports between 10000-65000
        import random
        ports = [str(random.randint(10000, 65000)) for _ in range(4)]
        return ",".join(ports)
    
    def _generate_custom_token(self, config: TokenConfig) -> str:
        """Generate a custom token"""
        generator = config.custom_properties.get("generator")
        if callable(generator):
            return generator(config)
        return f"CUSTOM-{uuid.uuid4()}"
    
    # Token deployers
    def _deploy_to_filesystem(self, token: HoneytokenInstance) -> bool:
        """Deploy token to filesystem (placeholder implementation)"""
        self.logger.info(f"Deploying filesystem token {token.id}")
        # Implementation would create files with the token
        return True
    
    def _deploy_to_database(self, token: HoneytokenInstance) -> bool:
        """Deploy token to database (placeholder implementation)"""
        self.logger.info(f"Deploying database token {token.id}")
        # Implementation would insert records with the token
        return True
    
    def _deploy_to_source_code(self, token: HoneytokenInstance) -> bool:
        """Deploy token to source code (placeholder implementation)"""
        self.logger.info(f"Deploying source code token {token.id}")
        # Implementation would insert tokens into source code
        return True
    
    def _deploy_to_cloud_storage(self, token: HoneytokenInstance) -> bool:
        """Deploy token to cloud storage (placeholder implementation)"""
        self.logger.info(f"Deploying cloud storage token {token.id}")
        # Implementation would create cloud storage objects
        return True
    
    def _deploy_to_email(self, token: HoneytokenInstance) -> bool:
        """Deploy token via email (placeholder implementation)"""
        self.logger.info(f"Deploying email token {token.id}")
        # Implementation would send emails containing the token
        return True
    
    def _deploy_to_document(self, token: HoneytokenInstance) -> bool:
        """Deploy token to document (placeholder implementation)"""
        self.logger.info(f"Deploying document token {token.id}")
        # Implementation would create/modify documents with the token
        return True
    
    def _deploy_to_browser(self, token: HoneytokenInstance) -> bool:
        """Deploy token to browser storage (placeholder implementation)"""
        self.logger.info(f"Deploying browser token {token.id}")
        # Implementation would create browser cookies/storage entries
        return True
    
    def _deploy_to_network_share(self, token: HoneytokenInstance) -> bool:
        """Deploy token to network share (placeholder implementation)"""
        self.logger.info(f"Deploying network share token {token.id}")
        # Implementation would create files on network shares
        return True
    
    def _deploy_to_memory(self, token: HoneytokenInstance) -> bool:
        """Deploy token to memory (placeholder implementation)"""
        self.logger.info(f"Deploying memory token {token.id}")
        # Implementation would register token with a monitoring service
        return True
    
    def _deploy_to_api(self, token: HoneytokenInstance) -> bool:
        """Deploy token to API (placeholder implementation)"""
        self.logger.info(f"Deploying API token {token.id}")
        # Implementation would expose token via an API
        return True
    
    def _deploy_to_custom(self, token: HoneytokenInstance) -> bool:
        """Deploy token to custom location (placeholder implementation)"""
        self.logger.info(f"Deploying custom token {token.id}")
        deployer = token.config.custom_properties.get("deployer")
        if callable(deployer):
            return deployer(token)
        return True
    
    # Additional methods for token management
    def check_expired_tokens(self) -> List[str]:
        """Check for and mark expired tokens"""
        now = datetime.datetime.now()
        expired_ids = []
        
        for id, token in self.tokens.items():
            if token.config.expiration and token.config.expiration <= now:
                if token.status != TokenStatus.EXPIRED:
                    token.status = TokenStatus.EXPIRED
                    token.updated_at = now
                    expired_ids.append(id)
        
        if expired_ids:
            self.logger.info(f"Marked {len(expired_ids)} tokens as expired")
            self.save_state()
            
        return expired_ids
    
    def get_token_by_value(self, value: str) -> Optional[HoneytokenInstance]:
        """Find a token by its value"""
        for token in self.tokens.values():
            if token.value == value:
                return token
        return None
    
    def create_credential_token(self, username: str, password: Optional[str] = None, 
                              description: str = "", severity: AlertSeverity = AlertSeverity.HIGH) -> HoneytokenInstance:
        """Convenience method to create a credential-based token"""
        config = TokenConfig(
            name=f"Credential-{username}",
            token_type=TokenType.PASSWORD,
            location=TokenLocation.DATABASE,
            description=description or f"Decoy credentials for username {username}",
            severity=severity,
            custom_properties={"username": username}
        )
        
        instance = self.create_token(config)
        
        # If password is provided, override the generated one
        if password:
            instance.value = password
            self.save_state()
            
        return instance
    
    def create_api_key_token(self, service_name: str, prefix: str = "API", 
                           description: str = "", severity: AlertSeverity = AlertSeverity.HIGH) -> HoneytokenInstance:
        """Convenience method to create an API key token"""
        config = TokenConfig(
            name=f"APIKey-{service_name}",
            token_type=TokenType.API_KEY,
            location=TokenLocation.DATABASE,
            description=description or f"Decoy API key for {service_name}",
            severity=severity,
            custom_properties={"service": service_name, "prefix": prefix}
        )
        
        return self.create_token(config)
    
    def create_document_token(self, document_name: str, location: TokenLocation = TokenLocation.FILESYSTEM,
                            description: str = "", severity: AlertSeverity = AlertSeverity.MEDIUM) -> HoneytokenInstance:
        """Convenience method to create a document-based token"""
        config = TokenConfig(
            name=f"Document-{document_name}",
            token_type=TokenType.DOCUMENT,
            location=location,
            description=description or f"Decoy document {document_name}",
            severity=severity,
            custom_properties={"document_name": document_name}
        )
        
        return self.create_token(config)
    
    def create_web_bug_token(self, target_name: str, base_url: str = "https://tracking.example.com",
                           description: str = "", severity: AlertSeverity = AlertSeverity.MEDIUM) -> HoneytokenInstance:
        """Convenience method to create a web bug token"""
        config = TokenConfig(
            name=f"WebBug-{target_name}",
            token_type=TokenType.WEB_BUG,
            location=TokenLocation.DOCUMENT,
            description=description or f"Web bug for {target_name}",
            severity=severity,
            custom_properties={"target": target_name, "base_url": base_url}
        )
        
        return self.create_token(config)