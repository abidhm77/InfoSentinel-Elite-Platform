"""Enterprise-grade logging and audit system for InfoSentinel."""
import logging
import json
import traceback
from datetime import datetime
from typing import Dict, Any, Optional
from functools import wraps
from flask import request, g
import os
import sys
from logging.handlers import RotatingFileHandler, SMTPHandler
from services.database_service import db_service

class EnterpriseLogger:
    """Enterprise-grade logging system with audit trails and compliance features."""
    
    def __init__(self, app=None):
        self.app = app
        self.logger = None
        self.audit_logger = None
        self.security_logger = None
        self.error_logger = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize logging for Flask application."""
        self.app = app
        
        # Create logs directory
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure main application logger
        self._setup_application_logger(log_dir)
        
        # Configure audit logger
        self._setup_audit_logger(log_dir)
        
        # Configure security logger
        self._setup_security_logger(log_dir)
        
        # Configure error logger
        self._setup_error_logger(log_dir)
        
        # Set up request logging
        self._setup_request_logging()
        
        # Set up error handlers
        self._setup_error_handlers()
    
    def _setup_application_logger(self, log_dir):
        """Set up main application logger."""
        self.logger = logging.getLogger('infosentinel')
        self.logger.setLevel(logging.INFO)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'application.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _setup_audit_logger(self, log_dir):
        """Set up audit trail logger for compliance."""
        self.audit_logger = logging.getLogger('infosentinel.audit')
        self.audit_logger.setLevel(logging.INFO)
        
        # Audit log handler
        audit_handler = RotatingFileHandler(
            os.path.join(log_dir, 'audit.log'),
            maxBytes=50*1024*1024,  # 50MB
            backupCount=20
        )
        audit_handler.setLevel(logging.INFO)
        
        # JSON formatter for structured audit logs
        audit_formatter = logging.Formatter('%(message)s')
        audit_handler.setFormatter(audit_formatter)
        
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.propagate = False
    
    def _setup_security_logger(self, log_dir):
        """Set up security events logger."""
        self.security_logger = logging.getLogger('infosentinel.security')
        self.security_logger.setLevel(logging.WARNING)
        
        # Security log handler
        security_handler = RotatingFileHandler(
            os.path.join(log_dir, 'security.log'),
            maxBytes=20*1024*1024,  # 20MB
            backupCount=15
        )
        security_handler.setLevel(logging.WARNING)
        
        # JSON formatter for structured security logs
        security_formatter = logging.Formatter('%(message)s')
        security_handler.setFormatter(security_formatter)
        
        self.security_logger.addHandler(security_handler)
        self.security_logger.propagate = False
    
    def _setup_error_logger(self, log_dir):
        """Set up error logger with detailed stack traces."""
        self.error_logger = logging.getLogger('infosentinel.errors')
        self.error_logger.setLevel(logging.ERROR)
        
        # Error log handler
        error_handler = RotatingFileHandler(
            os.path.join(log_dir, 'errors.log'),
            maxBytes=20*1024*1024,  # 20MB
            backupCount=10
        )
        error_handler.setLevel(logging.ERROR)
        
        # Detailed formatter for errors
        error_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s'
        )
        error_handler.setFormatter(error_formatter)
        
        self.error_logger.addHandler(error_handler)
        self.error_logger.propagate = False
    
    def _setup_request_logging(self):
        """Set up automatic request logging."""
        @self.app.before_request
        def log_request_info():
            """Log incoming request information."""
            if request.endpoint not in ['static', 'health']:
                self.log_request(
                    method=request.method,
                    url=request.url,
                    endpoint=request.endpoint,
                    user_agent=request.headers.get('User-Agent'),
                    ip_address=request.remote_addr
                )
        
        @self.app.after_request
        def log_response_info(response):
            """Log response information."""
            if request.endpoint not in ['static', 'health']:
                self.log_response(
                    status_code=response.status_code,
                    content_length=response.content_length
                )
            return response
    
    def _setup_error_handlers(self):
        """Set up global error handlers."""
        @self.app.errorhandler(400)
        def handle_bad_request(error):
            self.log_security_event(
                event_type='bad_request',
                severity='medium',
                description='Bad request received',
                details={'error': str(error), 'url': request.url}
            )
            return {'error': 'Bad request'}, 400
        
        @self.app.errorhandler(401)
        def handle_unauthorized(error):
            self.log_security_event(
                event_type='unauthorized_access',
                severity='high',
                description='Unauthorized access attempt',
                details={'error': str(error), 'url': request.url}
            )
            return {'error': 'Unauthorized'}, 401
        
        @self.app.errorhandler(403)
        def handle_forbidden(error):
            self.log_security_event(
                event_type='forbidden_access',
                severity='high',
                description='Forbidden access attempt',
                details={'error': str(error), 'url': request.url}
            )
            return {'error': 'Forbidden'}, 403
        
        @self.app.errorhandler(404)
        def handle_not_found(error):
            self.log_info(f"404 Not Found: {request.url}")
            return {'error': 'Not found'}, 404
        
        @self.app.errorhandler(500)
        def handle_internal_error(error):
            self.log_error(
                message='Internal server error',
                error=error,
                traceback_str=traceback.format_exc()
            )
            return {'error': 'Internal server error'}, 500
    
    def log_info(self, message: str, **kwargs):
        """Log informational message."""
        if self.logger:
            extra_info = ' - '.join([f"{k}={v}" for k, v in kwargs.items()])
            full_message = f"{message} - {extra_info}" if extra_info else message
            self.logger.info(full_message)
    
    def log_warning(self, message: str, **kwargs):
        """Log warning message."""
        if self.logger:
            extra_info = ' - '.join([f"{k}={v}" for k, v in kwargs.items()])
            full_message = f"{message} - {extra_info}" if extra_info else message
            self.logger.warning(full_message)
    
    def log_error(self, message: str, error: Exception = None, traceback_str: str = None, **kwargs):
        """Log error with detailed information."""
        if self.error_logger:
            error_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'message': message,
                'error_type': type(error).__name__ if error else 'Unknown',
                'error_message': str(error) if error else 'No error object',
                'traceback': traceback_str or traceback.format_exc(),
                'request_info': self._get_request_info(),
                'additional_data': kwargs
            }
            
            self.error_logger.error(json.dumps(error_data, indent=2))
    
    def log_audit_event(self, action: str, resource: str = None, resource_id: str = None, 
                       user_id: int = None, details: Dict[str, Any] = None, 
                       outcome: str = 'success', compliance_standard: str = None,
                       evidence_type: str = None):
        """Log audit event for compliance tracking."""
        if self.audit_logger:
            audit_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'audit',
                'action': action,
                'resource': resource,
                'resource_id': resource_id,
                'user_id': user_id,
                'outcome': outcome,
                'compliance_standard': compliance_standard,
                'evidence_type': evidence_type,
                'request_info': self._get_request_info(),
                'details': details or {}
            }
            
            self.audit_logger.info(json.dumps(audit_data))
            
            # Also store in database for querying
            try:
                db_service.log_action(
                    user_id=user_id,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    details=details,
                    ip_address=request.remote_addr if request else None,
                    user_agent=request.headers.get('User-Agent') if request else None
                )
            except Exception as e:
                self.log_error("Failed to store audit log in database", error=e)
    
    def log_security_event(self, event_type: str, severity: str, description: str, 
                          details: Dict[str, Any] = None, user_id: int = None):
        """Log security-related events."""
        if self.security_logger:
            security_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'description': description,
                'user_id': user_id,
                'request_info': self._get_request_info(),
                'details': details or {}
            }
            
            self.security_logger.warning(json.dumps(security_data))
            
            # Create security event in database
            try:
                db_service.create_security_event(
                    event_type=event_type,
                    severity=severity,
                    source=request.remote_addr if request else 'system',
                    target=request.url if request else 'unknown',
                    description=description,
                    details=details
                )
            except Exception as e:
                self.log_error("Failed to store security event in database", error=e)
    
    def log_request(self, method: str, url: str, endpoint: str = None, 
                   user_agent: str = None, ip_address: str = None):
        """Log HTTP request information."""
        request_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'request',
            'method': method,
            'url': url,
            'endpoint': endpoint,
            'user_agent': user_agent,
            'ip_address': ip_address
        }
        
        if self.logger:
            self.logger.info(f"REQUEST: {method} {url} from {ip_address}")
    
    def log_response(self, status_code: int, content_length: int = None):
        """Log HTTP response information."""
        response_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'response',
            'status_code': status_code,
            'content_length': content_length
        }
        
        if self.logger:
            self.logger.info(f"RESPONSE: {status_code} ({content_length} bytes)")
    
    def _get_request_info(self) -> Dict[str, Any]:
        """Get current request information."""
        if not request:
            return {}
        
        return {
            'method': request.method,
            'url': request.url,
            'endpoint': request.endpoint,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'content_type': request.headers.get('Content-Type'),
            'content_length': request.headers.get('Content-Length')
        }

def audit_log(action: str, resource: str = None):
    """Decorator for automatic audit logging."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = getattr(g, 'current_user_id', None)
            resource_id = kwargs.get('id') or kwargs.get('scan_id') or kwargs.get('user_id')
            
            try:
                result = f(*args, **kwargs)
                
                # Log successful action
                enterprise_logger.log_audit_event(
                    action=action,
                    resource=resource,
                    resource_id=str(resource_id) if resource_id else None,
                    user_id=user_id,
                    outcome='success'
                )
                
                return result
                
            except Exception as e:
                # Log failed action
                enterprise_logger.log_audit_event(
                    action=action,
                    resource=resource,
                    resource_id=str(resource_id) if resource_id else None,
                    user_id=user_id,
                    outcome='failure',
                    details={'error': str(e)}
                )
                
                # Log the error
                enterprise_logger.log_error(
                    message=f"Error in {action}",
                    error=e
                )
                
                raise
        
        return decorated_function
    return decorator

def security_log(event_type: str, severity: str = 'medium'):
    """Decorator for automatic security event logging."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = getattr(g, 'current_user_id', None)
            
            try:
                result = f(*args, **kwargs)
                return result
                
            except Exception as e:
                # Log security event on failure
                enterprise_logger.log_security_event(
                    event_type=event_type,
                    severity=severity,
                    description=f"Security event in {f.__name__}: {str(e)}",
                    user_id=user_id,
                    details={'function': f.__name__, 'error': str(e)}
                )
                
                raise
        
        return decorated_function
    return decorator

# Global logger instance
enterprise_logger = EnterpriseLogger()

# Convenience functions
def log_info(message: str, **kwargs):
    """Log informational message."""
    enterprise_logger.log_info(message, **kwargs)

def log_warning(message: str, **kwargs):
    """Log warning message."""
    enterprise_logger.log_warning(message, **kwargs)

def log_error(message: str, error: Exception = None, **kwargs):
    """Log error message."""
    enterprise_logger.log_error(message, error=error, **kwargs)

def log_audit(action: str, resource: str = None, resource_id: str = None, 
             user_id: int = None, details: Dict[str, Any] = None,
             compliance_standard: str = None, evidence_type: str = None):
    """Log audit event."""
    enterprise_logger.log_audit_event(action, resource, resource_id, user_id, details,
                                     compliance_standard=compliance_standard, 
                                     evidence_type=evidence_type)

def log_security(event_type: str, severity: str, description: str, 
                details: Dict[str, Any] = None, user_id: int = None):
    """Log security event."""
    enterprise_logger.log_security_event(event_type, severity, description, details, user_id)