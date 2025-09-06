#!/usr/bin/env python3
"""
Multi-Factor Authentication (MFA) system for InfoSentinel.
Implements TOTP, SMS, and backup codes for enhanced security.
"""
import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
import hmac
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import json
from database.db import get_postgres_session, close_postgres_session
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base

logger = logging.getLogger(__name__)
Base = declarative_base()

class MFAMethod(Enum):
    """MFA method types."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODES = "backup_codes"
    HARDWARE_TOKEN = "hardware_token"

class MFAStatus(Enum):
    """MFA status types."""
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"
    SUSPENDED = "suspended"

@dataclass
class MFAChallenge:
    """MFA challenge data."""
    challenge_id: str
    user_id: int
    method: MFAMethod
    code: str
    expires_at: datetime
    attempts: int
    max_attempts: int

class UserMFA(Base):
    """User MFA configuration model."""
    __tablename__ = 'user_mfa'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    method = Column(String(50), nullable=False)
    status = Column(String(20), default='pending')
    secret_key = Column(Text)  # Encrypted TOTP secret or phone number
    backup_codes = Column(Text)  # JSON array of backup codes
    last_used = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata = Column(Text)  # JSON metadata for method-specific data

class MFAAttempt(Base):
    """MFA attempt logging model."""
    __tablename__ = 'mfa_attempts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    method = Column(String(50), nullable=False)
    success = Column(Boolean, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    failure_reason = Column(String(255))

class MFASystem:
    """
    Comprehensive Multi-Factor Authentication system.
    """
    
    def __init__(self, app_name: str = "InfoSentinel"):
        """
        Initialize the MFA system.
        
        Args:
            app_name: Application name for TOTP labels
        """
        self.app_name = app_name
        self.totp_window = 1  # Allow 1 window before/after current time
        self.backup_code_length = 8
        self.backup_code_count = 10
        self.max_attempts = 3
        self.lockout_duration = timedelta(minutes=15)
        
        # Active challenges (in production, use Redis)
        self.active_challenges = {}
    
    def setup_totp(self, user_id: int, user_email: str) -> Dict:
        """
        Set up TOTP (Time-based One-Time Password) for a user.
        
        Args:
            user_id: User identifier
            user_email: User email for QR code label
            
        Returns:
            Setup information including QR code
        """
        try:
            session = get_postgres_session()
            
            # Check if TOTP is already set up
            existing_totp = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.method == MFAMethod.TOTP.value
            ).first()
            
            if existing_totp and existing_totp.status == MFAStatus.ACTIVE.value:
                return {
                    'error': 'TOTP is already set up for this user',
                    'status': 'already_configured'
                }
            
            # Generate secret key
            secret = pyotp.random_base32()
            
            # Create or update TOTP configuration
            if existing_totp:
                existing_totp.secret_key = self._encrypt_secret(secret)
                existing_totp.status = MFAStatus.PENDING.value
                existing_totp.updated_at = datetime.utcnow()
                totp_config = existing_totp
            else:
                totp_config = UserMFA(
                    user_id=user_id,
                    method=MFAMethod.TOTP.value,
                    status=MFAStatus.PENDING.value,
                    secret_key=self._encrypt_secret(secret)
                )
                session.add(totp_config)
            
            session.commit()
            
            # Generate QR code
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_email,
                issuer_name=self.app_name
            )
            
            qr_code = self._generate_qr_code(totp_uri)
            
            logger.info(f"TOTP setup initiated for user {user_id}")
            
            return {
                'status': 'setup_required',
                'secret': secret,
                'qr_code': qr_code,
                'manual_entry_key': secret,
                'instructions': [
                    "1. Install an authenticator app (Google Authenticator, Authy, etc.)",
                    "2. Scan the QR code or enter the manual key",
                    "3. Enter the 6-digit code from your app to complete setup"
                ]
            }
            
        except Exception as e:
            logger.error(f"Error setting up TOTP for user {user_id}: {str(e)}")
            return {'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def verify_totp_setup(self, user_id: int, verification_code: str) -> Dict:
        """
        Verify TOTP setup with user-provided code.
        
        Args:
            user_id: User identifier
            verification_code: 6-digit TOTP code
            
        Returns:
            Verification result
        """
        try:
            session = get_postgres_session()
            
            # Get pending TOTP configuration
            totp_config = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.method == MFAMethod.TOTP.value,
                UserMFA.status == MFAStatus.PENDING.value
            ).first()
            
            if not totp_config:
                return {
                    'success': False,
                    'error': 'No pending TOTP setup found'
                }
            
            # Decrypt secret and verify code
            secret = self._decrypt_secret(totp_config.secret_key)
            totp = pyotp.TOTP(secret)
            
            if totp.verify(verification_code, valid_window=self.totp_window):
                # Activate TOTP
                totp_config.status = MFAStatus.ACTIVE.value
                totp_config.last_used = datetime.utcnow()
                
                # Generate backup codes
                backup_codes = self._generate_backup_codes()
                backup_config = UserMFA(
                    user_id=user_id,
                    method=MFAMethod.BACKUP_CODES.value,
                    status=MFAStatus.ACTIVE.value,
                    backup_codes=json.dumps([self._hash_backup_code(code) for code in backup_codes])
                )
                session.add(backup_config)
                
                session.commit()
                
                logger.info(f"TOTP setup completed for user {user_id}")
                
                return {
                    'success': True,
                    'status': 'activated',
                    'backup_codes': backup_codes,
                    'message': 'TOTP has been successfully set up. Save your backup codes in a secure location.'
                }
            else:
                self._log_mfa_attempt(user_id, MFAMethod.TOTP, False, "Invalid verification code")
                return {
                    'success': False,
                    'error': 'Invalid verification code'
                }
                
        except Exception as e:
            logger.error(f"Error verifying TOTP setup for user {user_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def setup_sms(self, user_id: int, phone_number: str) -> Dict:
        """
        Set up SMS-based MFA for a user.
        
        Args:
            user_id: User identifier
            phone_number: User's phone number
            
        Returns:
            Setup result
        """
        try:
            session = get_postgres_session()
            
            # Validate phone number format
            if not self._validate_phone_number(phone_number):
                return {
                    'success': False,
                    'error': 'Invalid phone number format'
                }
            
            # Check if SMS MFA is already set up
            existing_sms = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.method == MFAMethod.SMS.value
            ).first()
            
            # Generate verification code
            verification_code = self._generate_sms_code()
            
            # Send SMS (in production, integrate with SMS service)
            sms_sent = self._send_sms(phone_number, verification_code)
            
            if not sms_sent:
                return {
                    'success': False,
                    'error': 'Failed to send SMS verification code'
                }
            
            # Store or update SMS configuration
            if existing_sms:
                existing_sms.secret_key = self._encrypt_secret(phone_number)
                existing_sms.status = MFAStatus.PENDING.value
                existing_sms.updated_at = datetime.utcnow()
            else:
                sms_config = UserMFA(
                    user_id=user_id,
                    method=MFAMethod.SMS.value,
                    status=MFAStatus.PENDING.value,
                    secret_key=self._encrypt_secret(phone_number)
                )
                session.add(sms_config)
            
            session.commit()
            
            # Store challenge
            challenge_id = secrets.token_urlsafe(32)
            self.active_challenges[challenge_id] = MFAChallenge(
                challenge_id=challenge_id,
                user_id=user_id,
                method=MFAMethod.SMS,
                code=verification_code,
                expires_at=datetime.utcnow() + timedelta(minutes=5),
                attempts=0,
                max_attempts=self.max_attempts
            )
            
            logger.info(f"SMS MFA setup initiated for user {user_id}")
            
            return {
                'success': True,
                'status': 'verification_sent',
                'challenge_id': challenge_id,
                'message': f'Verification code sent to {self._mask_phone_number(phone_number)}'
            }
            
        except Exception as e:
            logger.error(f"Error setting up SMS MFA for user {user_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def verify_mfa_code(self, user_id: int, code: str, method: Optional[MFAMethod] = None, challenge_id: Optional[str] = None) -> Dict:
        """
        Verify MFA code for authentication.
        
        Args:
            user_id: User identifier
            code: MFA code to verify
            method: Optional specific method to verify
            challenge_id: Optional challenge ID for SMS/email verification
            
        Returns:
            Verification result
        """
        try:
            session = get_postgres_session()
            
            # Check for account lockout
            if self._is_user_locked_out(user_id):
                return {
                    'success': False,
                    'error': 'Account temporarily locked due to too many failed attempts',
                    'lockout_until': self._get_lockout_expiry(user_id).isoformat()
                }
            
            # Try different MFA methods
            verification_result = None
            
            # 1. Try TOTP if no specific method or TOTP specified
            if not method or method == MFAMethod.TOTP:
                verification_result = self._verify_totp_code(session, user_id, code)
                if verification_result['success']:
                    self._log_mfa_attempt(user_id, MFAMethod.TOTP, True)
                    return verification_result
            
            # 2. Try SMS if challenge_id provided or SMS specified
            if challenge_id or method == MFAMethod.SMS:
                verification_result = self._verify_sms_code(user_id, code, challenge_id)
                if verification_result['success']:
                    self._log_mfa_attempt(user_id, MFAMethod.SMS, True)
                    return verification_result
            
            # 3. Try backup codes if no specific method
            if not method:
                verification_result = self._verify_backup_code(session, user_id, code)
                if verification_result['success']:
                    self._log_mfa_attempt(user_id, MFAMethod.BACKUP_CODES, True)
                    return verification_result
            
            # All methods failed
            self._log_mfa_attempt(user_id, method or MFAMethod.TOTP, False, "Invalid code")
            
            return {
                'success': False,
                'error': 'Invalid MFA code',
                'remaining_attempts': self._get_remaining_attempts(user_id)
            }
            
        except Exception as e:
            logger.error(f"Error verifying MFA code for user {user_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def get_user_mfa_methods(self, user_id: int) -> Dict:
        """
        Get all active MFA methods for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            User's MFA methods
        """
        try:
            session = get_postgres_session()
            
            mfa_methods = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.status == MFAStatus.ACTIVE.value
            ).all()
            
            methods = []
            for method in mfa_methods:
                method_info = {
                    'method': method.method,
                    'status': method.status,
                    'last_used': method.last_used.isoformat() if method.last_used else None,
                    'created_at': method.created_at.isoformat()
                }
                
                # Add method-specific information
                if method.method == MFAMethod.SMS.value:
                    phone = self._decrypt_secret(method.secret_key)
                    method_info['phone_number'] = self._mask_phone_number(phone)
                elif method.method == MFAMethod.BACKUP_CODES.value:
                    backup_codes = json.loads(method.backup_codes)
                    method_info['remaining_codes'] = len(backup_codes)
                
                methods.append(method_info)
            
            return {
                'user_id': user_id,
                'methods': methods,
                'mfa_enabled': len(methods) > 0
            }
            
        except Exception as e:
            logger.error(f"Error getting MFA methods for user {user_id}: {str(e)}")
            return {'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def disable_mfa_method(self, user_id: int, method: MFAMethod) -> Dict:
        """
        Disable a specific MFA method for a user.
        
        Args:
            user_id: User identifier
            method: MFA method to disable
            
        Returns:
            Disable result
        """
        try:
            session = get_postgres_session()
            
            mfa_config = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.method == method.value
            ).first()
            
            if not mfa_config:
                return {
                    'success': False,
                    'error': f'{method.value} MFA is not configured for this user'
                }
            
            mfa_config.status = MFAStatus.DISABLED.value
            mfa_config.updated_at = datetime.utcnow()
            
            session.commit()
            
            logger.info(f"{method.value} MFA disabled for user {user_id}")
            
            return {
                'success': True,
                'message': f'{method.value} MFA has been disabled'
            }
            
        except Exception as e:
            logger.error(f"Error disabling {method.value} MFA for user {user_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            close_postgres_session(session)
    
    def generate_new_backup_codes(self, user_id: int) -> Dict:
        """
        Generate new backup codes for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            New backup codes
        """
        try:
            session = get_postgres_session()
            
            backup_config = session.query(UserMFA).filter(
                UserMFA.user_id == user_id,
                UserMFA.method == MFAMethod.BACKUP_CODES.value
            ).first()
            
            if not backup_config:
                return {
                    'success': False,
                    'error': 'Backup codes are not configured for this user'
                }
            
            # Generate new backup codes
            new_codes = self._generate_backup_codes()
            backup_config.backup_codes = json.dumps([self._hash_backup_code(code) for code in new_codes])
            backup_config.updated_at = datetime.utcnow()
            
            session.commit()
            
            logger.info(f"New backup codes generated for user {user_id}")
            
            return {
                'success': True,
                'backup_codes': new_codes,
                'message': 'New backup codes generated. Save them in a secure location.'
            }
            
        except Exception as e:
            logger.error(f"Error generating backup codes for user {user_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            close_postgres_session(session)
    
    # Helper methods
    def _verify_totp_code(self, session, user_id: int, code: str) -> Dict:
        """Verify TOTP code."""
        totp_config = session.query(UserMFA).filter(
            UserMFA.user_id == user_id,
            UserMFA.method == MFAMethod.TOTP.value,
            UserMFA.status == MFAStatus.ACTIVE.value
        ).first()
        
        if not totp_config:
            return {'success': False, 'error': 'TOTP not configured'}
        
        secret = self._decrypt_secret(totp_config.secret_key)
        totp = pyotp.TOTP(secret)
        
        if totp.verify(code, valid_window=self.totp_window):
            totp_config.last_used = datetime.utcnow()
            session.commit()
            return {'success': True, 'method': 'totp'}
        
        return {'success': False}
    
    def _verify_sms_code(self, user_id: int, code: str, challenge_id: Optional[str]) -> Dict:
        """Verify SMS code."""
        if not challenge_id or challenge_id not in self.active_challenges:
            return {'success': False, 'error': 'Invalid or expired challenge'}
        
        challenge = self.active_challenges[challenge_id]
        
        if challenge.user_id != user_id:
            return {'success': False, 'error': 'Challenge mismatch'}
        
        if datetime.utcnow() > challenge.expires_at:
            del self.active_challenges[challenge_id]
            return {'success': False, 'error': 'Challenge expired'}
        
        if challenge.attempts >= challenge.max_attempts:
            del self.active_challenges[challenge_id]
            return {'success': False, 'error': 'Too many attempts'}
        
        challenge.attempts += 1
        
        if challenge.code == code:
            del self.active_challenges[challenge_id]
            return {'success': True, 'method': 'sms'}
        
        return {'success': False, 'error': 'Invalid code'}
    
    def _verify_backup_code(self, session, user_id: int, code: str) -> Dict:
        """Verify backup code."""
        backup_config = session.query(UserMFA).filter(
            UserMFA.user_id == user_id,
            UserMFA.method == MFAMethod.BACKUP_CODES.value,
            UserMFA.status == MFAStatus.ACTIVE.value
        ).first()
        
        if not backup_config:
            return {'success': False, 'error': 'Backup codes not configured'}
        
        backup_codes = json.loads(backup_config.backup_codes)
        code_hash = self._hash_backup_code(code)
        
        if code_hash in backup_codes:
            # Remove used backup code
            backup_codes.remove(code_hash)
            backup_config.backup_codes = json.dumps(backup_codes)
            backup_config.last_used = datetime.utcnow()
            session.commit()
            
            return {
                'success': True,
                'method': 'backup_code',
                'remaining_codes': len(backup_codes)
            }
        
        return {'success': False}
    
    def _generate_qr_code(self, data: str) -> str:
        """Generate QR code as base64 image."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def _generate_backup_codes(self) -> List[str]:
        """Generate backup codes."""
        codes = []
        for _ in range(self.backup_code_count):
            code = ''.join(secrets.choice('0123456789') for _ in range(self.backup_code_length))
            codes.append(code)
        return codes
    
    def _hash_backup_code(self, code: str) -> str:
        """Hash backup code for storage."""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def _generate_sms_code(self) -> str:
        """Generate SMS verification code."""
        return ''.join(secrets.choice('0123456789') for _ in range(6))
    
    def _encrypt_secret(self, secret: str) -> str:
        """Encrypt secret for storage (simplified - use proper encryption in production)."""
        return base64.b64encode(secret.encode()).decode()
    
    def _decrypt_secret(self, encrypted_secret: str) -> str:
        """Decrypt secret from storage (simplified - use proper decryption in production)."""
        return base64.b64decode(encrypted_secret.encode()).decode()
    
    def _validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format."""
        import re
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone.replace(' ', '').replace('-', '')))
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for display."""
        if len(phone) > 4:
            return f"***-***-{phone[-4:]}"
        return "***-***-****"
    
    def _send_sms(self, phone: str, code: str) -> bool:
        """Send SMS (mock implementation - integrate with SMS service in production)."""
        logger.info(f"SMS code {code} would be sent to {phone}")
        return True  # Mock success
    
    def _log_mfa_attempt(self, user_id: int, method: MFAMethod, success: bool, failure_reason: str = None):
        """Log MFA attempt."""
        try:
            session = get_postgres_session()
            
            attempt = MFAAttempt(
                user_id=user_id,
                method=method.value,
                success=success,
                failure_reason=failure_reason
            )
            
            session.add(attempt)
            session.commit()
            
        except Exception as e:
            logger.error(f"Error logging MFA attempt: {str(e)}")
        finally:
            close_postgres_session(session)
    
    def _is_user_locked_out(self, user_id: int) -> bool:
        """Check if user is locked out due to failed attempts."""
        try:
            session = get_postgres_session()
            
            # Check failed attempts in the last lockout duration
            since = datetime.utcnow() - self.lockout_duration
            
            failed_attempts = session.query(MFAAttempt).filter(
                MFAAttempt.user_id == user_id,
                MFAAttempt.success == False,
                MFAAttempt.timestamp >= since
            ).count()
            
            return failed_attempts >= self.max_attempts
            
        except Exception as e:
            logger.error(f"Error checking lockout status: {str(e)}")
            return False
        finally:
            close_postgres_session(session)
    
    def _get_lockout_expiry(self, user_id: int) -> datetime:
        """Get lockout expiry time."""
        try:
            session = get_postgres_session()
            
            latest_attempt = session.query(MFAAttempt).filter(
                MFAAttempt.user_id == user_id,
                MFAAttempt.success == False
            ).order_by(MFAAttempt.timestamp.desc()).first()
            
            if latest_attempt:
                return latest_attempt.timestamp + self.lockout_duration
            
            return datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error getting lockout expiry: {str(e)}")
            return datetime.utcnow()
        finally:
            close_postgres_session(session)
    
    def _get_remaining_attempts(self, user_id: int) -> int:
        """Get remaining MFA attempts before lockout."""
        try:
            session = get_postgres_session()
            
            since = datetime.utcnow() - self.lockout_duration
            
            failed_attempts = session.query(MFAAttempt).filter(
                MFAAttempt.user_id == user_id,
                MFAAttempt.success == False,
                MFAAttempt.timestamp >= since
            ).count()
            
            return max(0, self.max_attempts - failed_attempts)
            
        except Exception as e:
            logger.error(f"Error getting remaining attempts: {str(e)}")
            return 0
        finally:
            close_postgres_session(session)
    
    def get_mfa_statistics(self, user_id: Optional[int] = None) -> Dict:
        """
        Get MFA usage statistics.
        
        Args:
            user_id: Optional user ID for user-specific stats
            
        Returns:
            MFA statistics
        """
        try:
            session = get_postgres_session()
            
            stats = {
                'total_users_with_mfa': 0,
                'methods_breakdown': {},
                'recent_attempts': 0,
                'success_rate': 0.0
            }
            
            # Get users with MFA enabled
            query = session.query(UserMFA).filter(UserMFA.status == MFAStatus.ACTIVE.value)
            if user_id:
                query = query.filter(UserMFA.user_id == user_id)
            
            active_mfa = query.all()
            
            # Count by method
            for mfa in active_mfa:
                method = mfa.method
                if method not in stats['methods_breakdown']:
                    stats['methods_breakdown'][method] = 0
                stats['methods_breakdown'][method] += 1
            
            stats['total_users_with_mfa'] = len(set(mfa.user_id for mfa in active_mfa))
            
            # Get attempt statistics
            attempt_query = session.query(MFAAttempt)
            if user_id:
                attempt_query = attempt_query.filter(MFAAttempt.user_id == user_id)
            
            # Recent attempts (last 24 hours)
            since = datetime.utcnow() - timedelta(hours=24)
            recent_attempts = attempt_query.filter(MFAAttempt.timestamp >= since).all()
            
            stats['recent_attempts'] = len(recent_attempts)
            
            if recent_attempts:
                successful = len([a for a in recent_attempts if a.success])
                stats['success_rate'] = (successful / len(recent_attempts)) * 100
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting MFA statistics: {str(e)}")
            return {'error': str(e)}
        finally:
            close_postgres_session(session)