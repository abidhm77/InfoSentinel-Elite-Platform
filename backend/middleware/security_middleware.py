"""Security middleware for InfoSentinel Enterprise Platform."""
import time
import re
import json
from functools import wraps
from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import request, jsonify, g
from services.enterprise_logger import log_security, log_warning
from typing import Dict, Any, Optional, List

class RateLimiter:
    """Rate limiting middleware for API endpoints."""
    
    def __init__(self):
        self.requests = defaultdict(deque)
        self.blocked_ips = {}
        
    def is_rate_limited(self, identifier: str, limit: int, window: int) -> bool:
        """Check if identifier is rate limited."""
        now = time.time()
        
        # Clean old requests
        cutoff = now - window
        while self.requests[identifier] and self.requests[identifier][0] < cutoff:
            self.requests[identifier].popleft()
        
        # Check if limit exceeded
        if len(self.requests[identifier]) >= limit:
            return True
        
        # Add current request
        self.requests[identifier].append(now)
        return False
    
    def block_ip(self, ip: str, duration: int = 3600):
        """Block IP address for specified duration."""
        self.blocked_ips[ip] = time.time() + duration
        log_security(
            event_type='ip_blocked',
            severity='high',
            description=f'IP address {ip} blocked for {duration} seconds due to rate limiting'
        )
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False

class InputValidator:
    """Input validation and sanitization middleware."""
    
    # Common injection patterns
    SQL_INJECTION_PATTERNS = [
        r"('|(\-\-)|(;)|(\||\|)|(\*|\*))",
        r"(union|select|insert|delete|update|drop|create|alter|exec|execute)",
        r"(script|javascript|vbscript|onload|onerror|onclick)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(;|\||&|`|\$\(|\$\{)",
        r"(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)",
        r"(\.\./)|(\.\.\\)"
    ]
    
    @classmethod
    def validate_input(cls, data: Any, field_name: str = '') -> Dict[str, Any]:
        """Validate and sanitize input data."""
        issues = []
        
        if isinstance(data, str):
            issues.extend(cls._check_string_patterns(data, field_name))
        elif isinstance(data, dict):
            for key, value in data.items():
                sub_issues = cls.validate_input(value, f"{field_name}.{key}" if field_name else key)
                issues.extend(sub_issues['issues'])
        elif isinstance(data, list):
            for i, item in enumerate(data):
                sub_issues = cls.validate_input(item, f"{field_name}[{i}]" if field_name else f"[{i}]")
                issues.extend(sub_issues['issues'])
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'sanitized_data': cls._sanitize_data(data)
        }
    
    @classmethod
    def _check_string_patterns(cls, text: str, field_name: str) -> List[Dict[str, str]]:
        """Check string for malicious patterns."""
        issues = []
        text_lower = text.lower()
        
        # Check for SQL injection
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                issues.append({
                    'type': 'sql_injection',
                    'field': field_name,
                    'description': f'Potential SQL injection detected in {field_name}',
                    'pattern': pattern
                })
                break
        
        # Check for XSS
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append({
                    'type': 'xss',
                    'field': field_name,
                    'description': f'Potential XSS detected in {field_name}',
                    'pattern': pattern
                })
                break
        
        # Check for command injection
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append({
                    'type': 'command_injection',
                    'field': field_name,
                    'description': f'Potential command injection detected in {field_name}',
                    'pattern': pattern
                })
                break
        
        return issues
    
    @classmethod
    def _sanitize_data(cls, data: Any) -> Any:
        """Sanitize data by removing/escaping dangerous characters."""
        if isinstance(data, str):
            # Basic HTML escaping
            data = data.replace('&', '&amp;')
            data = data.replace('<', '&lt;')
            data = data.replace('>', '&gt;')
            data = data.replace('"', '&quot;')
            data = data.replace("'", '&#x27;')
            return data
        elif isinstance(data, dict):
            return {key: cls._sanitize_data(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [cls._sanitize_data(item) for item in data]
        else:
            return data

class SecurityHeaders:
    """Security headers middleware."""
    
    DEFAULT_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    @classmethod
    def add_security_headers(cls, response):
        """Add security headers to response."""
        for header, value in cls.DEFAULT_HEADERS.items():
            response.headers[header] = value
        return response

# Global instances
rate_limiter = RateLimiter()
input_validator = InputValidator()

def rate_limit(limit: int = 100, window: int = 3600, per: str = 'ip'):
    """Rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine identifier
            if per == 'ip':
                identifier = request.remote_addr
            elif per == 'user':
                identifier = getattr(g, 'current_user_id', request.remote_addr)
            else:
                identifier = request.remote_addr
            
            # Check if IP is blocked
            if rate_limiter.is_blocked(identifier):
                log_security(
                    event_type='blocked_request',
                    severity='medium',
                    description=f'Request from blocked IP: {identifier}'
                )
                return jsonify({
                    'error': 'IP address is temporarily blocked',
                    'retry_after': 3600
                }), 429
            
            # Check rate limit
            if rate_limiter.is_rate_limited(identifier, limit, window):
                # Block IP after repeated violations
                rate_limiter.block_ip(identifier)
                
                log_security(
                    event_type='rate_limit_exceeded',
                    severity='medium',
                    description=f'Rate limit exceeded for {identifier}',
                    details={'limit': limit, 'window': window, 'endpoint': request.endpoint}
                )
                
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': limit,
                    'window': window,
                    'retry_after': window
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(strict: bool = True):
    """Input validation decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Validate JSON input
            if request.is_json:
                try:
                    data = request.get_json()
                    if data:
                        validation_result = input_validator.validate_input(data)
                        
                        if not validation_result['valid']:
                            log_security(
                                event_type='malicious_input_detected',
                                severity='high',
                                description='Malicious input patterns detected',
                                details={
                                    'issues': validation_result['issues'],
                                    'endpoint': request.endpoint,
                                    'ip': request.remote_addr
                                }
                            )
                            
                            if strict:
                                return jsonify({
                                    'error': 'Invalid input detected',
                                    'issues': [issue['description'] for issue in validation_result['issues']]
                                }), 400
                            else:
                                # Use sanitized data
                                request._cached_json = validation_result['sanitized_data']
                except Exception as e:
                    log_warning(f"Input validation error: {e}")
            
            # Validate URL parameters
            for key, value in request.args.items():
                validation_result = input_validator.validate_input(value, key)
                if not validation_result['valid']:
                    log_security(
                        event_type='malicious_parameter_detected',
                        severity='medium',
                        description=f'Malicious parameter detected: {key}',
                        details={'issues': validation_result['issues']}
                    )
                    
                    if strict:
                        return jsonify({
                            'error': f'Invalid parameter: {key}'
                        }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def security_headers(f):
    """Security headers decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if hasattr(response, 'headers'):
            return SecurityHeaders.add_security_headers(response)
        return response
    return decorated_function

def audit_request(f):
    """Request auditing decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        # Log request
        log_security(
            event_type='api_request',
            severity='low',
            description=f'API request: {request.method} {request.path}',
            details={
                'method': request.method,
                'path': request.path,
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'endpoint': request.endpoint
            }
        )
        
        try:
            response = f(*args, **kwargs)
            
            # Log successful response
            duration = time.time() - start_time
            log_security(
                event_type='api_response',
                severity='low',
                description=f'API response: {request.method} {request.path}',
                details={
                    'status_code': getattr(response, 'status_code', 200),
                    'duration': duration,
                    'endpoint': request.endpoint
                }
            )
            
            return response
            
        except Exception as e:
            # Log error
            duration = time.time() - start_time
            log_security(
                event_type='api_error',
                severity='high',
                description=f'API error: {request.method} {request.path}',
                details={
                    'error': str(e),
                    'duration': duration,
                    'endpoint': request.endpoint
                }
            )
            raise
    
    return decorated_function

def require_https(f):
    """HTTPS enforcement decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure and not request.headers.get('X-Forwarded-Proto') == 'https':
            log_security(
                event_type='insecure_request',
                severity='medium',
                description='HTTP request to secure endpoint',
                details={'endpoint': request.endpoint, 'ip': request.remote_addr}
            )
            return jsonify({
                'error': 'HTTPS required for this endpoint'
            }), 400
        
        return f(*args, **kwargs)
    return decorated_function

def ip_whitelist(allowed_ips: List[str]):
    """IP whitelist decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            
            if client_ip not in allowed_ips:
                log_security(
                    event_type='unauthorized_ip_access',
                    severity='high',
                    description=f'Access attempt from unauthorized IP: {client_ip}',
                    details={'endpoint': request.endpoint, 'allowed_ips': allowed_ips}
                )
                return jsonify({
                    'error': 'Access denied from this IP address'
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Convenience decorators for common security levels
def high_security(f):
    """High security decorator combining multiple security measures."""
    return rate_limit(limit=10, window=3600)(
        validate_input(strict=True)(
            security_headers(
                audit_request(
                    require_https(f)
                )
            )
        )
    )

def medium_security(f):
    """Medium security decorator."""
    return rate_limit(limit=50, window=3600)(
        validate_input(strict=False)(
            security_headers(
                audit_request(f)
            )
        )
    )

def basic_security(f):
    """Basic security decorator."""
    return rate_limit(limit=100, window=3600)(
        security_headers(
            audit_request(f)
        )
    )