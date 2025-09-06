"""Database models for InfoSentinel Enterprise Security Platform."""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

Base = declarative_base()

class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default='user')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    scans = relationship('Scan', back_populates='user')
    
class Scan(Base):
    """Scan model for penetration testing scans."""
    __tablename__ = 'scans'
    
    id = Column(String(50), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    progress = Column(Integer, default=0)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    error_message = Column(Text)
    config = Column(JSON)
    
    # Relationships
    user = relationship('User', back_populates='scans')
    vulnerabilities = relationship('Vulnerability', back_populates='scan')
    
class Vulnerability(Base):
    """Vulnerability model for scan results."""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), ForeignKey('scans.id'), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    cvss_score = Column(Float)
    cve_id = Column(String(20))
    location = Column(String(255))
    remediation = Column(Text)
    tool = Column(String(50))  # nmap, nikto, sqlmap, etc.
    raw_output = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship('Scan', back_populates='vulnerabilities')
    
class ComplianceResult(Base):
    """Compliance assessment results."""
    __tablename__ = 'compliance_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), ForeignKey('scans.id'), nullable=False)
    framework = Column(String(50), nullable=False)  # OWASP, PCI_DSS, etc.
    control_id = Column(String(20), nullable=False)
    control_title = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)  # compliant, non_compliant, not_applicable
    details = Column(Text)
    evidence = Column(JSON)
    tested_at = Column(DateTime, default=datetime.utcnow)
    
class SecurityEvent(Base):
    """Real-time security events."""
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(50), unique=True, nullable=False)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    source = Column(String(255))
    target = Column(String(255))
    description = Column(Text)
    details = Column(JSON)
    threat_score = Column(Float)
    status = Column(String(20), default='new')  # new, acknowledged, resolved
    timestamp = Column(DateTime, default=datetime.utcnow)
    
class Notification(Base):
    """System notifications."""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String(20), default='info')  # info, warning, error, success
    read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
class AuditLog(Base):
    """Audit logging for enterprise compliance."""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(100), nullable=False)
    resource = Column(String(100))
    resource_id = Column(String(50))
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
class ScanQueue(Base):
    """Scan queue for background processing."""
    __tablename__ = 'scan_queue'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), ForeignKey('scans.id'), nullable=False)
    priority = Column(Integer, default=5)  # 1-10, lower is higher priority
    status = Column(String(20), default='queued')  # queued, processing, completed, failed
    worker_id = Column(String(50))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
# Database configuration
class DatabaseConfig:
    """Database configuration and connection management."""
    
    def __init__(self):
        # Use environment variables for production
        self.database_url = os.getenv(
            'DATABASE_URL',
            'postgresql://postgres:password@localhost:5432/infosentinel'
        )
        
        # Fallback to SQLite for development
        if not self.database_url or 'postgresql' not in self.database_url:
            self.database_url = 'sqlite:///infosentinel.db'
        
        self.engine = create_engine(
            self.database_url,
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            pool_recycle=300
        )
        
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
    
    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self):
        """Get database session."""
        return self.SessionLocal()
    
    def close_session(self, session):
        """Close database session."""
        session.close()

# Global database instance
db_config = DatabaseConfig()

def get_db():
    """Dependency to get database session."""
    session = db_config.get_session()
    try:
        yield session
    finally:
        session.close()

def init_database():
    """Initialize database with tables and default data."""
    try:
        db_config.create_tables()
        print("Database tables created successfully")
        
        # Create default admin user if not exists
        session = db_config.get_session()
        try:
            admin_user = session.query(User).filter_by(username='admin').first()
            if not admin_user:
                from werkzeug.security import generate_password_hash
                admin_user = User(
                    username='admin',
                    email='admin@infosentinel.com',
                    password_hash=generate_password_hash('admin123'),
                    role='admin'
                )
                session.add(admin_user)
                session.commit()
                print("Default admin user created: admin/admin123")
        finally:
            session.close()
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Fallback to SQLite if PostgreSQL fails
        if 'postgresql' in db_config.database_url:
            print("Falling back to SQLite database")
            db_config.database_url = 'sqlite:///infosentinel.db'
            db_config.engine = create_engine(db_config.database_url)
            db_config.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=db_config.engine
            )
            db_config.create_tables()

if __name__ == '__main__':
    init_database()