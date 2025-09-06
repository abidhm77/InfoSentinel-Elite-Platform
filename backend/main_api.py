#!/usr/bin/env python3
"""
InfoSentinel Main API Server
FastAPI application with security controls, rate limiting, and comprehensive endpoints
"""

import os
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI, HTTPException, Depends, Request, Response, 
    WebSocket, BackgroundTasks, UploadFile, File
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
import redis
import uvicorn

# Import our modules
from database_setup import (
    get_db, db_manager, User, Scan, Vulnerability, Host, Service, 
    UserRole, ScanStatus, VulnerabilitySeverity, ScanType
)
from auth_system import (
    auth_manager, mfa_manager, api_key_manager, audit_logger,
    get_current_user, get_current_active_user, get_admin_user,
    require_permission, require_role, Permission
)
from security_tools_integration import security_tools, ScanTarget
from websocket_manager import websocket_manager, websocket_endpoint

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8000').split(',')
UPLOAD_DIR = os.getenv('UPLOAD_DIR', './uploads')
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', '10485760'))  # 10MB

# Create upload directory
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# Pydantic models for API requests/responses
class UserLogin(BaseModel):
    username: str
    password: str
    mfa_token: Optional[str] = None

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role: UserRole = UserRole.VIEWER
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class ScanRequest(BaseModel):
    name: str
    target: str
    scan_type: ScanType
    config: Optional[Dict[str, Any]] = {}

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VulnerabilityUpdate(BaseModel):
    status: str
    notes: Optional[str] = None

class APIKeyRequest(BaseModel):
    name: str
    permissions: List[str]
    expires_days: Optional[int] = None

class APIKeyResponse(BaseModel):
    api_key: str
    key_id: str
    name: str
    expires_at: Optional[str]

class NotificationRequest(BaseModel):
    title: str
    message: str
    level: str = "info"
    user_ids: Optional[List[str]] = None

# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events"""
    # Startup
    logger.info("Starting InfoSentinel API server...")
    
    # Initialize database
    try:
        db_manager.create_tables()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    
    # Initialize security tools
    try:
        security_tools.initialize_zap()
        logger.info("Security tools initialized")
    except Exception as e:
        logger.warning(f"Security tools initialization warning: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down InfoSentinel API server...")

# Create FastAPI app
app = FastAPI(
    title="InfoSentinel Security API",
    description="Enterprise cybersecurity platform with real-time scanning and vulnerability management",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# Initialize tenant service
from tenant_management import TenantService, TenantMiddleware
tenant_service = TenantService()
app.state.tenant_service = tenant_service

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

app.add_middleware(SlowAPIMiddleware)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response

@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Audit logging middleware"""
    start_time = datetime.now(timezone.utc)
    
    # Get user info if available
    user_id = None
    try:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            token_payload = auth_manager.verify_token(token)
            if token_payload:
                user_id = token_payload.user_id
    except Exception:
        pass  # Ignore auth errors in middleware
    
    response = await call_next(request)
    
    # Log the request
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    # Only log API endpoints
    if request.url.path.startswith("/api/"):
        with db_manager.get_session() as db:
            audit_logger.log_action(
                user_id=user_id,
                action=f"{request.method} {request.url.path}",
                resource_type="api_endpoint",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_seconds": duration,
                    "user_agent": request.headers.get("User-Agent"),
                },
                ip_address=get_remote_address(request),
                user_agent=request.headers.get("User-Agent"),
                db=db
            )
    
    return response

# Health check endpoint
@app.get("/health")
@limiter.limit("100/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }

# Authentication endpoints
@app.post("/api/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, user_login: UserLogin, db: Session = Depends(get_db)):
    """User login endpoint"""
    # Authenticate user
    user = auth_manager.authenticate_user(user_login.username, user_login.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check MFA if enabled
    if user.mfa_enabled:
        if not user_login.mfa_token:
            # Return MFA required response
            mfa_token = auth_manager.create_mfa_token(user)
            return JSONResponse(
                status_code=202,
                content={
                    "mfa_required": True,
                    "mfa_token": mfa_token,
                    "message": "MFA token required"
                }
            )
        
        # Verify MFA token
        if not mfa_manager.verify_totp(user.mfa_secret, user_login.mfa_token):
            # Try backup codes
            if not mfa_manager.verify_backup_code(user, user_login.mfa_token, db):
                raise HTTPException(status_code=401, detail="Invalid MFA token")
    
    # Generate tokens
    access_token = auth_manager.create_access_token(user)
    refresh_token = auth_manager.create_refresh_token(user)
    
    # Log successful login
    audit_logger.log_action(
        user_id=str(user.id),
        action="user_login",
        resource_type="authentication",
        ip_address=get_remote_address(request),
        user_agent=request.headers.get("User-Agent"),
        db=db
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,  # 30 minutes
        user=user.to_dict()
    )

@app.post("/api/auth/register")
@limiter.limit("3/minute")
async def register(request: Request, user_data: UserRegister, db: Session = Depends(get_db)):
    """User registration endpoint"""
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role=user_data.role
    )
    new_user.set_password(user_data.password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log registration
    audit_logger.log_action(
        user_id=str(new_user.id),
        action="user_registration",
        resource_type="user",
        resource_id=str(new_user.id),
        ip_address=get_remote_address(request),
        user_agent=request.headers.get("User-Agent"),
        db=db
    )
    
    return {"message": "User registered successfully", "user_id": str(new_user.id)}

@app.post("/api/auth/logout")
async def logout(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """User logout endpoint"""
    # Revoke all user tokens
    auth_manager.revoke_all_user_tokens(str(current_user.id))
    
    # Log logout
    audit_logger.log_action(
        user_id=str(current_user.id),
        action="user_logout",
        resource_type="authentication",
        db=db
    )
    
    return {"message": "Logged out successfully"}

# MFA endpoints
@app.post("/api/auth/mfa/setup")
async def setup_mfa(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Setup MFA for user"""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")
    
    # Generate secret and QR code
    secret = mfa_manager.generate_secret()
    qr_code = mfa_manager.generate_qr_code(current_user, secret)
    backup_codes = mfa_manager.generate_backup_codes()
    
    # Store secret temporarily (user needs to verify before enabling)
    current_user.mfa_secret = secret
    current_user.backup_codes = backup_codes
    db.commit()
    
    return {
        "qr_code": qr_code,
        "secret": secret,
        "backup_codes": backup_codes
    }

@app.post("/api/auth/mfa/verify")
async def verify_mfa_setup(token: str, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Verify and enable MFA"""
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated")
    
    if not mfa_manager.verify_totp(current_user.mfa_secret, token):
        raise HTTPException(status_code=400, detail="Invalid MFA token")
    
    # Enable MFA
    current_user.mfa_enabled = True
    db.commit()
    
    # Log MFA enablement
    audit_logger.log_action(
        user_id=str(current_user.id),
        action="mfa_enabled",
        resource_type="user_security",
        db=db
    )
    
    return {"message": "MFA enabled successfully"}

# Scan endpoints
@app.post("/api/scans", response_model=ScanResponse)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create and start a new security scan"""
    # Check permissions
    if not require_permission(Permission.SCAN_CREATE):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        name=scan_request.name,
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        config=scan_request.config,
        started_at=datetime.now(timezone.utc)
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Start scan in background
    scan_target = ScanTarget(
        target=scan_request.target,
        scan_type=scan_request.scan_type.value,
        scan_options=scan_request.config
    )
    
    if scan_request.scan_type in [ScanType.NETWORK, ScanType.COMPREHENSIVE]:
        scan_id = security_tools.start_nmap_scan(scan_target)
    elif scan_request.scan_type == ScanType.WEB_APPLICATION:
        scan_id = security_tools.start_zap_scan(scan_target)
    else:
        scan_id = security_tools.start_nmap_scan(scan_target)
    
    # Update scan with external scan ID
    scan.config['external_scan_id'] = scan_id
    db.commit()
    
    # Send WebSocket notification
    await websocket_manager.send_scan_started(str(scan.id), scan.to_dict())
    
    # Log scan creation
    audit_logger.log_action(
        user_id=str(current_user.id),
        action="scan_created",
        resource_type="scan",
        resource_id=str(scan.id),
        details={"target": scan_request.target, "scan_type": scan_request.scan_type.value},
        db=db
    )
    
    return ScanResponse(
        scan_id=str(scan.id),
        status="started",
        message="Scan started successfully"
    )

@app.get("/api/scans")
async def get_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's scans"""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.offset(skip).limit(limit).all()
    
    return {
        "scans": [scan.to_dict() for scan in scans],
        "total": query.count()
    }

@app.get("/api/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get specific scan details"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get external scan status if available
    external_scan_id = scan.config.get('external_scan_id')
    if external_scan_id:
        external_status = security_tools.get_scan_status(external_scan_id)
        if external_status:
            scan.progress = external_status['progress']
            scan.status = ScanStatus(external_status['status'])
            db.commit()
    
    return scan.to_dict()

@app.get("/api/scans/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scan results"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get external scan results
    external_scan_id = scan.config.get('external_scan_id')
    if external_scan_id:
        external_results = security_tools.get_scan_results(external_scan_id)
        if external_results:
            return external_results
    
    # Get results from database
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    
    return {
        "scan_id": scan_id,
        "hosts": [host.to_dict() for host in hosts],
        "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities],
        "summary": {
            "hosts_discovered": len(hosts),
            "vulnerabilities_found": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]),
            "high_vulnerabilities": len([v for v in vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])
        }
    }

# Vulnerability endpoints
@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[VulnerabilitySeverity] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get vulnerabilities"""
    # Get user's scans
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id).subquery()
    
    query = db.query(Vulnerability).filter(Vulnerability.scan_id.in_(user_scan_ids))
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    if status:
        query = query.filter(Vulnerability.status == status)
    
    vulnerabilities = query.offset(skip).limit(limit).all()
    
    return {
        "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities],
        "total": query.count()
    }

@app.patch("/api/vulnerabilities/{vuln_id}")
async def update_vulnerability(
    vuln_id: str,
    update_data: VulnerabilityUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update vulnerability status"""
    # Get user's scans
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id).subquery()
    
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id,
        Vulnerability.scan_id.in_(user_scan_ids)
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Update vulnerability
    vulnerability.status = update_data.status
    if update_data.notes:
        if not vulnerability.metadata:
            vulnerability.metadata = {}
        vulnerability.metadata['notes'] = update_data.notes
    
    db.commit()
    
    # Log update
    audit_logger.log_action(
        user_id=str(current_user.id),
        action="vulnerability_updated",
        resource_type="vulnerability",
        resource_id=vuln_id,
        details={"status": update_data.status},
        db=db
    )
    
    return vulnerability.to_dict()

# API Key endpoints
@app.post("/api/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    key_request: APIKeyRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create new API key"""
    expires_at = None
    if key_request.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=key_request.expires_days)
    
    api_key_obj, api_key = api_key_manager.create_api_key(
        current_user,
        key_request.name,
        key_request.permissions,
        expires_at,
        db
    )
    
    return APIKeyResponse(
        api_key=api_key,
        key_id=str(api_key_obj.id),
        name=api_key_obj.name,
        expires_at=expires_at.isoformat() if expires_at else None
    )

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint_handler(websocket: WebSocket, db: Session = Depends(get_db)):
    """WebSocket endpoint for real-time communication"""
    await websocket_endpoint(websocket, db)

# Admin endpoints
@app.get("/api/admin/stats")
async def get_admin_stats(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Get system statistics (admin only)"""
    total_users = db.query(User).count()
    total_scans = db.query(Scan).count()
    total_vulnerabilities = db.query(Vulnerability).count()
    
    # WebSocket stats
    ws_stats = websocket_manager.get_connection_stats()
    
    return {
        "users": {
            "total": total_users,
            "active": db.query(User).filter(User.is_active == True).count()
        },
        "scans": {
            "total": total_scans,
            "running": db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count(),
            "completed": db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
        },
        "vulnerabilities": {
            "total": total_vulnerabilities,
            "critical": db.query(Vulnerability).filter(Vulnerability.severity == VulnerabilitySeverity.CRITICAL).count(),
            "high": db.query(Vulnerability).filter(Vulnerability.severity == VulnerabilitySeverity.HIGH).count()
        },
        "websockets": ws_stats
    }

@app.get("/api/admin/connections")
async def get_active_connections(
    admin_user: User = Depends(get_admin_user)
):
    """Get active WebSocket connections (admin only)"""
    return {
        "connections": websocket_manager.get_active_connections(),
        "stats": websocket_manager.get_connection_stats()
    }

# Notification endpoints
@app.post("/api/notifications/send")
async def send_notification(
    notification: NotificationRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Send notification to users"""
    if notification.user_ids:
        # Send to specific users
        for user_id in notification.user_ids:
            await websocket_manager.send_notification(
                user_id,
                notification.title,
                notification.message,
                notification.level
            )
    else:
        # Send system-wide alert
        await websocket_manager.send_system_alert(
            notification.title,
            notification.message,
            notification.level
        )
    
    return {"message": "Notification sent successfully"}

if __name__ == "__main__":
    # Run the server
    uvicorn.run(
        "main_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )