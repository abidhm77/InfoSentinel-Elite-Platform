#!/usr/bin/env python3
"""
InfoSentinel Database Setup
PostgreSQL database configuration and models for security data
"""

import os
import asyncio
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, Float, Boolean,
    ForeignKey, JSON, Enum as SQLEnum, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB
from enum import Enum
import uuid
import bcrypt
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://infosec_user:secure_password@localhost:5432/infosec_db'
)

# Create engine
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    echo=False  # Set to True for SQL debugging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all models
Base = declarative_base()

# Enums
class UserRole(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanType(Enum):
    NETWORK = "network"
    WEB_APPLICATION = "web_application"
    COMPREHENSIVE = "comprehensive"
    QUICK = "quick"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"

# Database Models
class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # MFA settings
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))
    backup_codes = Column(JSONB)
    
    # Relationships
    scans = relationship("Scan", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def set_password(self, password: str):
        """Hash and set password"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Check if password is correct"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': str(self.id),
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'mfa_enabled': self.mfa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat()
        }

class APIKey(Base):
    """API key model for programmatic access"""
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    permissions = Column(JSONB, default=list)  # List of allowed operations
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True))
    last_used = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'name': self.name,
            'permissions': self.permissions,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat()
        }

class Organization(Base):
    """Organization model for multi-tenant support"""
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True)
    settings = Column(JSONB, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    scans = relationship("Scan", back_populates="organization")

class Scan(Base):
    """Scan model for penetration testing scans"""
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    
    name = Column(String(255), nullable=False)
    target = Column(String(500), nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)
    
    # Scan configuration
    config = Column(JSONB, default=dict)  # Scan parameters, ports, options
    
    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Results summary
    hosts_discovered = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    services_found = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    organization = relationship("Organization", back_populates="scans")
    hosts = relationship("Host", back_populates="scan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_user_status', 'user_id', 'status'),
        Index('idx_scan_created', 'created_at'),
        Index('idx_scan_target', 'target'),
    )
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'name': self.name,
            'target': self.target,
            'scan_type': self.scan_type.value,
            'status': self.status.value,
            'progress': self.progress,
            'hosts_discovered': self.hosts_discovered,
            'vulnerabilities_found': self.vulnerabilities_found,
            'services_found': self.services_found,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat(),
            'error_message': self.error_message
        }

class Host(Base):
    """Host model for discovered network hosts"""
    __tablename__ = "hosts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    hostname = Column(String(255))
    mac_address = Column(String(17))
    
    # Host information
    os_name = Column(String(255))
    os_version = Column(String(255))
    os_accuracy = Column(Float)
    
    # Status
    status = Column(String(20), default="up")  # up, down, unknown
    
    # Additional data
    metadata = Column(JSONB, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    # Relationships
    scan = relationship("Scan", back_populates="hosts")
    services = relationship("Service", back_populates="host")
    vulnerabilities = relationship("Vulnerability", back_populates="host")
    
    # Indexes
    __table_args__ = (
        Index('idx_host_scan_ip', 'scan_id', 'ip_address'),
        Index('idx_host_ip', 'ip_address'),
    )
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'os_accuracy': self.os_accuracy,
            'status': self.status,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat()
        }

class Service(Base):
    """Service model for discovered network services"""
    __tablename__ = "services"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)  # tcp, udp
    service_name = Column(String(100))
    product = Column(String(255))
    version = Column(String(255))
    state = Column(String(20))  # open, closed, filtered
    
    # Additional service information
    banner = Column(Text)
    extra_info = Column(Text)
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    # Relationships
    host = relationship("Host", back_populates="services")
    
    # Indexes
    __table_args__ = (
        Index('idx_service_host_port', 'host_id', 'port', 'protocol'),
        Index('idx_service_name', 'service_name'),
    )
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'port': self.port,
            'protocol': self.protocol,
            'service_name': self.service_name,
            'product': self.product,
            'version': self.version,
            'state': self.state,
            'banner': self.banner,
            'extra_info': self.extra_info,
            'created_at': self.created_at.isoformat()
        }

class Vulnerability(Base):
    """Vulnerability model for discovered security issues"""
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"))
    
    # Vulnerability details
    name = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(String(255))
    
    # External references
    cve_id = Column(String(20))
    cwe_id = Column(String(20))
    
    # Location information
    port = Column(Integer)
    service = Column(String(100))
    url = Column(String(1000))  # For web vulnerabilities
    
    # Remediation
    solution = Column(Text)
    references = Column(JSONB, default=list)
    
    # Status
    status = Column(String(20), default="open")  # open, fixed, false_positive, accepted
    
    # Additional data
    evidence = Column(JSONB, default=dict)
    metadata = Column(JSONB, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    host = relationship("Host", back_populates="vulnerabilities")
    
    # Indexes
    __table_args__ = (
        Index('idx_vuln_scan_severity', 'scan_id', 'severity'),
        Index('idx_vuln_cve', 'cve_id'),
        Index('idx_vuln_severity', 'severity'),
        Index('idx_vuln_status', 'status'),
    )
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'port': self.port,
            'service': self.service,
            'url': self.url,
            'solution': self.solution,
            'references': self.references,
            'status': self.status,
            'evidence': self.evidence,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Report(Base):
    """Report model for generated security reports"""
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # executive, technical, compliance
    format = Column(String(10), nullable=False)  # pdf, html, json
    
    # Report configuration
    config = Column(JSONB, default=dict)
    
    # File information
    file_path = Column(String(500))
    file_size = Column(Integer)
    
    # Status
    status = Column(String(20), default="pending")  # pending, generating, completed, failed
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True))
    
    def to_dict(self) -> Dict:
        return {
            'id': str(self.id),
            'name': self.name,
            'report_type': self.report_type,
            'format': self.format,
            'status': self.status,
            'file_size': self.file_size,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

class AuditLog(Base):
    """Audit log model for tracking user actions"""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    
    # Request information
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    
    # Additional data
    details = Column(JSONB, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_created', 'created_at'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )

class CVEData(Base):
    """CVE database for vulnerability information"""
    __tablename__ = "cve_data"
    
    id = Column(String(20), primary_key=True)  # CVE-YYYY-NNNN
    description = Column(Text)
    cvss_v2_score = Column(Float)
    cvss_v3_score = Column(Float)
    cvss_v2_vector = Column(String(255))
    cvss_v3_vector = Column(String(255))
    
    # Dates
    published_date = Column(DateTime(timezone=True))
    modified_date = Column(DateTime(timezone=True))
    
    # Additional data
    references = Column(JSONB, default=list)
    cwe_ids = Column(JSONB, default=list)
    affected_products = Column(JSONB, default=list)
    
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index('idx_cve_score', 'cvss_v3_score'),
        Index('idx_cve_published', 'published_date'),
    )

# Database utility functions
class DatabaseManager:
    """Database management utilities"""
    
    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def drop_tables(self):
        """Drop all database tables (use with caution!)"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.info("Database tables dropped successfully")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise
    
    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def create_admin_user(self, username: str, email: str, password: str) -> User:
        """Create initial admin user"""
        with self.get_session() as session:
            # Check if admin user already exists
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                logger.warning(f"User with username '{username}' or email '{email}' already exists")
                return existing_user
            
            # Create new admin user
            admin_user = User(
                username=username,
                email=email,
                first_name="Admin",
                last_name="User",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True
            )
            admin_user.set_password(password)
            
            session.add(admin_user)
            session.commit()
            session.refresh(admin_user)
            
            logger.info(f"Admin user '{username}' created successfully")
            return admin_user
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        with self.get_session() as session:
            return session.query(User).filter(User.username == username).first()
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        with self.get_session() as session:
            return session.query(User).filter(User.email == email).first()
    
    def create_organization(self, name: str, domain: str = None) -> Organization:
        """Create new organization"""
        with self.get_session() as session:
            org = Organization(
                name=name,
                domain=domain,
                settings={}
            )
            session.add(org)
            session.commit()
            session.refresh(org)
            
            logger.info(f"Organization '{name}' created successfully")
            return org

# Global database manager instance
db_manager = DatabaseManager()

# Dependency for FastAPI
def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if __name__ == "__main__":
    # Initialize database
    print("Initializing InfoSentinel database...")
    
    # Create tables
    db_manager.create_tables()
    
    # Create default admin user
    admin_user = db_manager.create_admin_user(
        username="admin",
        email="admin@infosec.local",
        password="SecurePassword123!"
    )
    
    # Create default organization
    org = db_manager.create_organization(
        name="InfoSentinel Security",
        domain="infosec.local"
    )
    
    print("Database initialization completed successfully!")
    print(f"Admin user created: {admin_user.username} ({admin_user.email})")
    print(f"Organization created: {org.name}")