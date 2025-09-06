#!/usr/bin/env python3
"""
InfoSentinel Authentication & Authorization System
JWT-based authentication with role-based access control and MFA
"""

import os
import jwt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any, Tuple
from functools import wraps
from dataclasses import dataclass
from enum import Enum
import secrets
import hashlib
import logging
from sqlalchemy.orm import Session
from database_setup import User, APIKey, AuditLog, UserRole, get_db
import bcrypt
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import redis
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-super-secret-jwt-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
MFA_ISSUER = 'InfoSentinel Security'
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Redis client for session management
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
except Exception as e:
    logger.warning(f"Redis connection failed: {e}. Session management will be limited.")
    redis_client = None

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    MFA = "mfa"
    RESET = "reset"

class Permission(Enum):
    # Scan permissions
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"
    
    # Vulnerability permissions
    VULN_READ = "vuln:read"
    VULN_UPDATE = "vuln:update"
    VULN_DELETE = "vuln:delete"
    
    # Report permissions
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_DELETE = "report:delete"
    
    # User management permissions
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Admin permissions
    ADMIN_FULL = "admin:full"
    SYSTEM_CONFIG = "system:config"
    AUDIT_READ = "audit:read"

@dataclass
class TokenPayload:
    """JWT token payload structure"""
    user_id: str
    username: str
    role: str
    token_type: TokenType
    permissions: List[str]
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for token revocation

class RolePermissions:
    """Role-based permission mapping"""
    
    ROLE_PERMISSIONS = {
        UserRole.ADMIN: [
            Permission.ADMIN_FULL,
            Permission.SYSTEM_CONFIG,
            Permission.AUDIT_READ,
            Permission.SCAN_CREATE,
            Permission.SCAN_READ,
            Permission.SCAN_UPDATE,
            Permission.SCAN_DELETE,
            Permission.SCAN_EXECUTE,
            Permission.VULN_READ,
            Permission.VULN_UPDATE,
            Permission.VULN_DELETE,
            Permission.REPORT_CREATE,
            Permission.REPORT_READ,
            Permission.REPORT_DELETE,
            Permission.USER_CREATE,
            Permission.USER_READ,
            Permission.USER_UPDATE,
            Permission.USER_DELETE,
        ],
        UserRole.ANALYST: [
            Permission.SCAN_CREATE,
            Permission.SCAN_READ,
            Permission.SCAN_UPDATE,
            Permission.SCAN_EXECUTE,
            Permission.VULN_READ,
            Permission.VULN_UPDATE,
            Permission.REPORT_CREATE,
            Permission.REPORT_READ,
            Permission.USER_READ,
        ],
        UserRole.AUDITOR: [
            Permission.SCAN_READ,
            Permission.VULN_READ,
            Permission.REPORT_CREATE,
            Permission.REPORT_READ,
            Permission.AUDIT_READ,
            Permission.USER_READ,
        ],
        UserRole.VIEWER: [
            Permission.SCAN_READ,
            Permission.VULN_READ,
            Permission.REPORT_READ,
        ],
    }
    
    @classmethod
    def get_permissions(cls, role: UserRole) -> List[str]:
        """Get permissions for a role"""
        permissions = cls.ROLE_PERMISSIONS.get(role, [])
        return [perm.value for perm in permissions]
    
    @classmethod
    def has_permission(cls, role: UserRole, permission: Permission) -> bool:
        """Check if role has specific permission"""
        role_permissions = cls.ROLE_PERMISSIONS.get(role, [])
        return permission in role_permissions or Permission.ADMIN_FULL in role_permissions

class AuthenticationManager:
    """Handles authentication operations"""
    
    def __init__(self):
        self.security = HTTPBearer()
    
    def create_access_token(self, user: User, permissions: List[str] = None) -> str:
        """Create JWT access token"""
        if permissions is None:
            permissions = RolePermissions.get_permissions(user.role)
        
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        jti = secrets.token_urlsafe(32)
        
        payload = {
            'user_id': str(user.id),
            'username': user.username,
            'role': user.role.value,
            'permissions': permissions,
            'token_type': TokenType.ACCESS.value,
            'exp': expire,
            'iat': now,
            'jti': jti
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Store token in Redis for revocation capability
        if redis_client:
            try:
                redis_client.setex(
                    f"token:{jti}",
                    JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    json.dumps({
                        'user_id': str(user.id),
                        'token_type': TokenType.ACCESS.value,
                        'created_at': now.isoformat()
                    })
                )
            except Exception as e:
                logger.warning(f"Failed to store token in Redis: {e}")
        
        return token
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        jti = secrets.token_urlsafe(32)
        
        payload = {
            'user_id': str(user.id),
            'username': user.username,
            'token_type': TokenType.REFRESH.value,
            'exp': expire,
            'iat': now,
            'jti': jti
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Store refresh token in Redis
        if redis_client:
            try:
                redis_client.setex(
                    f"refresh_token:{jti}",
                    JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                    json.dumps({
                        'user_id': str(user.id),
                        'token_type': TokenType.REFRESH.value,
                        'created_at': now.isoformat()
                    })
                )
            except Exception as e:
                logger.warning(f"Failed to store refresh token in Redis: {e}")
        
        return token
    
    def create_mfa_token(self, user: User) -> str:
        """Create temporary MFA token"""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=5)  # Short-lived MFA token
        jti = secrets.token_urlsafe(32)
        
        payload = {
            'user_id': str(user.id),
            'username': user.username,
            'token_type': TokenType.MFA.value,
            'exp': expire,
            'iat': now,
            'jti': jti
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    def verify_token(self, token: str, expected_type: TokenType = TokenType.ACCESS) -> Optional[TokenPayload]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Check token type
            if payload.get('token_type') != expected_type.value:
                return None
            
            # Check if token is revoked (if Redis is available)
            jti = payload.get('jti')
            if redis_client and jti:
                try:
                    token_data = redis_client.get(f"token:{jti}")
                    if not token_data:
                        logger.warning(f"Token {jti} not found in Redis (possibly revoked)")
                        return None
                except Exception as e:
                    logger.warning(f"Failed to check token in Redis: {e}")
            
            return TokenPayload(
                user_id=payload['user_id'],
                username=payload['username'],
                role=payload['role'],
                token_type=TokenType(payload['token_type']),
                permissions=payload.get('permissions', []),
                exp=datetime.fromtimestamp(payload['exp'], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload['iat'], tz=timezone.utc),
                jti=payload.get('jti', '')
            )
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def revoke_token(self, jti: str, token_type: TokenType = TokenType.ACCESS) -> bool:
        """Revoke a token by removing it from Redis"""
        if not redis_client:
            logger.warning("Redis not available, cannot revoke token")
            return False
        
        try:
            key = f"token:{jti}" if token_type == TokenType.ACCESS else f"refresh_token:{jti}"
            result = redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id: str) -> bool:
        """Revoke all tokens for a user"""
        if not redis_client:
            logger.warning("Redis not available, cannot revoke user tokens")
            return False
        
        try:
            # Find all tokens for the user
            pattern = "token:*"
            tokens_to_revoke = []
            
            for key in redis_client.scan_iter(match=pattern):
                token_data = redis_client.get(key)
                if token_data:
                    data = json.loads(token_data)
                    if data.get('user_id') == user_id:
                        tokens_to_revoke.append(key)
            
            # Also check refresh tokens
            pattern = "refresh_token:*"
            for key in redis_client.scan_iter(match=pattern):
                token_data = redis_client.get(key)
                if token_data:
                    data = json.loads(token_data)
                    if data.get('user_id') == user_id:
                        tokens_to_revoke.append(key)
            
            # Revoke all found tokens
            if tokens_to_revoke:
                redis_client.delete(*tokens_to_revoke)
                logger.info(f"Revoked {len(tokens_to_revoke)} tokens for user {user_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke user tokens: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str, db: Session) -> Optional[User]:
        """Authenticate user with username/email and password"""
        # Find user by username or email
        user = db.query(User).filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            logger.warning(f"Authentication failed: user '{username}' not found")
            return None
        
        if not user.is_active:
            logger.warning(f"Authentication failed: user '{username}' is inactive")
            return None
        
        if not user.check_password(password):
            logger.warning(f"Authentication failed: invalid password for user '{username}'")
            return None
        
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        
        logger.info(f"User '{username}' authenticated successfully")
        return user
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()), db: Session = Depends(get_db)) -> User:
        """Get current authenticated user from JWT token"""
        token_payload = self.verify_token(credentials.credentials)
        
        if not token_payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        user = db.query(User).filter(User.id == token_payload.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user

class MFAManager:
    """Handles Multi-Factor Authentication"""
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, user: User, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name=MFA_ISSUER
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_base64}"
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 window tolerance
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for MFA"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8-character hex codes
            codes.append(code)
        return codes
    
    def verify_backup_code(self, user: User, code: str, db: Session) -> bool:
        """Verify and consume a backup code"""
        if not user.backup_codes:
            return False
        
        code = code.upper().strip()
        if code in user.backup_codes:
            # Remove the used backup code
            user.backup_codes.remove(code)
            db.commit()
            logger.info(f"Backup code used for user {user.username}")
            return True
        
        return False

class APIKeyManager:
    """Handles API key authentication"""
    
    def generate_api_key(self) -> Tuple[str, str]:
        """Generate API key and its hash"""
        # Generate a secure random API key
        api_key = f"is_{secrets.token_urlsafe(32)}"
        
        # Hash the API key for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        return api_key, key_hash
    
    def create_api_key(self, user: User, name: str, permissions: List[str], expires_at: Optional[datetime], db: Session) -> Tuple[APIKey, str]:
        """Create a new API key for user"""
        api_key, key_hash = self.generate_api_key()
        
        api_key_obj = APIKey(
            user_id=user.id,
            name=name,
            key_hash=key_hash,
            permissions=permissions,
            expires_at=expires_at
        )
        
        db.add(api_key_obj)
        db.commit()
        db.refresh(api_key_obj)
        
        logger.info(f"API key '{name}' created for user {user.username}")
        return api_key_obj, api_key
    
    def authenticate_api_key(self, api_key: str, db: Session) -> Optional[Tuple[User, APIKey]]:
        """Authenticate using API key"""
        if not api_key.startswith('is_'):
            return None
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_obj = db.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        ).first()
        
        if not api_key_obj:
            return None
        
        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.now(timezone.utc):
            logger.warning(f"API key '{api_key_obj.name}' has expired")
            return None
        
        # Get user
        user = db.query(User).filter(User.id == api_key_obj.user_id).first()
        if not user or not user.is_active:
            return None
        
        # Update last used
        api_key_obj.last_used = datetime.now(timezone.utc)
        db.commit()
        
        return user, api_key_obj

class AuditLogger:
    """Handles audit logging"""
    
    def log_action(self, user_id: Optional[str], action: str, resource_type: str = None, 
                   resource_id: str = None, details: Dict = None, 
                   ip_address: str = None, user_agent: str = None, db: Session = None):
        """Log user action for audit purposes"""
        if not db:
            return
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Audit log: {action} by user {user_id}")

# Authorization decorators
def require_permission(permission: Permission):
    """Decorator to require specific permission"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract current user from kwargs (assumes it's passed as dependency)
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            if not RolePermissions.has_permission(current_user.role, permission):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_role(required_role: UserRole):
    """Decorator to require specific role or higher"""
    role_hierarchy = {
        UserRole.VIEWER: 0,
        UserRole.AUDITOR: 1,
        UserRole.ANALYST: 2,
        UserRole.ADMIN: 3
    }
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            user_level = role_hierarchy.get(current_user.role, 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            if user_level < required_level:
                raise HTTPException(status_code=403, detail="Insufficient role level")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Global instances
auth_manager = AuthenticationManager()
mfa_manager = MFAManager()
api_key_manager = APIKeyManager()
audit_logger = AuditLogger()

# FastAPI dependencies
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()), db: Session = Depends(get_db)) -> User:
    """FastAPI dependency to get current authenticated user"""
    return auth_manager.get_current_user(credentials, db)

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """FastAPI dependency to get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    """FastAPI dependency to require admin user"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

if __name__ == "__main__":
    # Test authentication system
    from database_setup import db_manager
    
    # Create test user
    with db_manager.get_session() as db:
        test_user = db_manager.create_admin_user(
            username="testuser",
            email="test@example.com",
            password="testpassword123"
        )
        
        # Test authentication
        authenticated_user = auth_manager.authenticate_user(
            "testuser", "testpassword123", db
        )
        
        if authenticated_user:
            # Test token creation
            access_token = auth_manager.create_access_token(authenticated_user)
            refresh_token = auth_manager.create_refresh_token(authenticated_user)
            
            print(f"Access token created: {access_token[:50]}...")
            print(f"Refresh token created: {refresh_token[:50]}...")
            
            # Test token verification
            token_payload = auth_manager.verify_token(access_token)
            if token_payload:
                print(f"Token verified for user: {token_payload.username}")
                print(f"Permissions: {token_payload.permissions}")
            
            # Test MFA
            secret = mfa_manager.generate_secret()
            qr_code = mfa_manager.generate_qr_code(authenticated_user, secret)
            backup_codes = mfa_manager.generate_backup_codes()
            
            print(f"MFA secret generated: {secret}")
            print(f"Backup codes: {backup_codes}")
            
            # Test API key
            api_key_obj, api_key = api_key_manager.create_api_key(
                authenticated_user, "Test API Key", 
                RolePermissions.get_permissions(authenticated_user.role),
                None, db
            )
            
            print(f"API key created: {api_key}")
            
            # Test API key authentication
            auth_result = api_key_manager.authenticate_api_key(api_key, db)
            if auth_result:
                user, key_obj = auth_result
                print(f"API key authenticated for user: {user.username}")
        
        print("Authentication system test completed successfully!")