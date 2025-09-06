"""Enhanced database configuration supporting PostgreSQL and MongoDB."""
import os
import logging
from pymongo import MongoClient
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime

logger = logging.getLogger(__name__)

# Global database connections
mongo_db = None
postgres_session = None
Base = declarative_base()

# PostgreSQL Models
class User(Base):
    """User model for PostgreSQL."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default='user')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class ScanQueue(Base):
    """Scan queue model for PostgreSQL."""
    __tablename__ = 'scan_queue'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    priority = Column(Integer, default=5)
    status = Column(String(20), default='queued')
    user_id = Column(Integer, nullable=False)
    options = Column(Text)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    celery_task_id = Column(String(100))

class AuditLog(Base):
    """Audit log model for PostgreSQL."""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class SystemMetrics(Base):
    """System metrics model for PostgreSQL."""
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    metric_type = Column(String(50), nullable=False)
    metric_name = Column(String(100), nullable=False)
    value = Column(Float, nullable=False)
    unit = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)

def initialize_db(app):
    """
    Initialize both PostgreSQL and MongoDB connections.
    
    Args:
        app: Flask application instance
    """
    global mongo_db, postgres_session
    
    try:
        # Initialize PostgreSQL
        postgres_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if postgres_uri:
            engine = create_engine(postgres_uri, echo=app.config.get('DEBUG', False))
            
            # Create tables
            Base.metadata.create_all(engine)
            
            # Create session
            Session = scoped_session(sessionmaker(bind=engine))
            postgres_session = Session
            
            logger.info("Connected to PostgreSQL database")
        
        # Initialize MongoDB
        mongo_uri = app.config.get('MONGO_URI')
        if mongo_uri:
            client = MongoClient(mongo_uri)
            db_name = mongo_uri.split('/')[-1]
            mongo_db = client[db_name]
            
            # Create indexes for better performance
            _create_mongo_indexes()
            
            logger.info(f"Connected to MongoDB: {db_name}")
        
        return {'postgres': postgres_session, 'mongo': mongo_db}
        
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

def _create_mongo_indexes():
    """Create MongoDB indexes for optimal performance."""
    global mongo_db
    
    if mongo_db is None:
        return
    
    try:
        # Scans collection indexes
        mongo_db.scans.create_index([("target", 1), ("start_time", -1)])
        mongo_db.scans.create_index([("status", 1), ("start_time", -1)])
        mongo_db.scans.create_index([("scan_type", 1), ("start_time", -1)])
        mongo_db.scans.create_index([("user_id", 1), ("start_time", -1)])
        
        # Vulnerabilities collection indexes
        mongo_db.vulnerabilities.create_index([("scan_id", 1), ("severity", -1)])
        mongo_db.vulnerabilities.create_index([("severity", 1), ("created_at", -1)])
        mongo_db.vulnerabilities.create_index([("host", 1), ("port", 1)])
        mongo_db.vulnerabilities.create_index([("title", "text"), ("description", "text")])
        
        # Reports collection indexes
        mongo_db.reports.create_index([("scan_id", 1), ("generated_at", -1)])
        mongo_db.reports.create_index([("report_type", 1), ("generated_at", -1)])
        
        # Notifications collection indexes
        mongo_db.notifications.create_index([("type", 1), ("created_at", -1)])
        mongo_db.alerts.create_index([("severity", 1), ("created_at", -1)])
        
        # Statistics collection indexes
        mongo_db.statistics.create_index([("type", 1), ("updated_at", -1)])
        
        logger.info("MongoDB indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error creating MongoDB indexes: {str(e)}")

def get_db():
    """
    Get the MongoDB connection.
    
    Returns:
        MongoDB database instance
    """
    global mongo_db
    if mongo_db is None:
        raise Exception("MongoDB not initialized. Call initialize_db first.")
    return mongo_db

def get_postgres_session():
    """
    Get the PostgreSQL session.
    
    Returns:
        SQLAlchemy session instance
    """
    global postgres_session
    if postgres_session is None:
        raise Exception("PostgreSQL not initialized. Call initialize_db first.")
    return postgres_session()

def close_postgres_session(session):
    """
    Close PostgreSQL session.
    
    Args:
        session: SQLAlchemy session to close
    """
    try:
        session.close()
    except Exception as e:
        logger.error(f"Error closing PostgreSQL session: {str(e)}")

def create_user(username, email, password_hash, role='user'):
    """
    Create a new user in PostgreSQL.
    
    Args:
        username: User's username
        email: User's email
        password_hash: Hashed password
        role: User role (default: 'user')
        
    Returns:
        User object
    """
    session = get_postgres_session()
    try:
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role
        )
        session.add(user)
        session.commit()
        return user
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        raise
    finally:
        close_postgres_session(session)

def get_user_by_username(username):
    """
    Get user by username from PostgreSQL.
    
    Args:
        username: Username to search for
        
    Returns:
        User object or None
    """
    session = get_postgres_session()
    try:
        return session.query(User).filter(User.username == username).first()
    finally:
        close_postgres_session(session)

def log_audit_event(user_id, action, resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None):
    """
    Log an audit event to PostgreSQL.
    
    Args:
        user_id: ID of the user performing the action
        action: Action being performed
        resource_type: Type of resource being acted upon
        resource_id: ID of the resource
        details: Additional details (JSON string)
        ip_address: User's IP address
        user_agent: User's browser/client info
    """
    session = get_postgres_session()
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        session.add(audit_log)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Error logging audit event: {str(e)}")
    finally:
        close_postgres_session(session)

def record_system_metric(metric_type, metric_name, value, unit=None):
    """
    Record a system metric to PostgreSQL.
    
    Args:
        metric_type: Type of metric (cpu, memory, disk, etc.)
        metric_name: Name of the specific metric
        value: Metric value
        unit: Unit of measurement
    """
    session = get_postgres_session()
    try:
        metric = SystemMetrics(
            metric_type=metric_type,
            metric_name=metric_name,
            value=value,
            unit=unit
        )
        session.add(metric)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Error recording system metric: {str(e)}")
    finally:
        close_postgres_session(session)