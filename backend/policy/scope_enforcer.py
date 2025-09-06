#!/usr/bin/env python3
"""
Scope Enforcer - Policy-based target validation for InfoSentinel Pentest AI
Ensures scans only target authorized assets and comply with organizational policies.
"""

import re
import ipaddress
from typing import List, Dict, Any
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class ScopeEnforcer:
    """Enforces scanning scope and policy compliance"""
    
    def __init__(self):
        # Default allowed/blocked patterns
        # In production, these would be loaded from database/config
        self.allowed_domains = [
            "localhost",
            "127.0.0.1",
            "*.example.com",
            "*.test.local"
        ]
        
        self.blocked_domains = [
            "*.gov",
            "*.mil",
            "*.edu",
            "facebook.com",
            "google.com",
            "microsoft.com",
            "amazon.com"
        ]
        
        self.allowed_ip_ranges = [
            "127.0.0.0/8",      # Loopback
            "10.0.0.0/8",       # Private Class A
            "172.16.0.0/12",    # Private Class B
            "192.168.0.0/16"    # Private Class C
        ]
        
        self.blocked_ip_ranges = [
            "0.0.0.0/8",        # Current network
            "169.254.0.0/16",   # Link-local
            "224.0.0.0/4"       # Multicast
        ]
        
        # Risk-based scan type restrictions
        self.scan_type_policies = {
            "exploit_validation": {
                "requires_approval": True,
                "max_risk_level": "high",
                "allowed_users": ["admin", "senior_pentester"]
            },
            "comprehensive": {
                "requires_approval": False,
                "max_risk_level": "medium",
                "rate_limit_per_hour": 5
            }
        }
    
    def validate_target(self, target: str, user_id: int, scan_type: str) -> List[str]:
        """Validate if target is within authorized scope
        
        Args:
            target: Target URL or IP to validate
            user_id: ID of user requesting scan
            scan_type: Type of scan being requested
            
        Returns:
            List of policy violations (empty if valid)
        """
        violations = []
        
        try:
            # Parse target
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port
            else:
                # Assume it's a hostname or IP
                hostname = target
                port = None
            
            # Validate hostname/IP
            ip_violations = self._validate_ip_address(hostname)
            violations.extend(ip_violations)
            
            domain_violations = self._validate_domain(hostname)
            violations.extend(domain_violations)
            
            # Validate scan type permissions
            scan_violations = self._validate_scan_type(scan_type, user_id)
            violations.extend(scan_violations)
            
            # Validate port restrictions
            if port:
                port_violations = self._validate_port(port, scan_type)
                violations.extend(port_violations)
            
            logger.info(f"Scope validation for {target}: {len(violations)} violations")
            
        except Exception as e:
            logger.error(f"Scope validation error: {e}")
            violations.append(f"Target validation failed: {str(e)}")
        
        return violations
    
    def _validate_ip_address(self, hostname: str) -> List[str]:
        """Validate IP address against allowed/blocked ranges"""
        violations = []
        
        try:
            ip = ipaddress.ip_address(hostname)
            
            # Check against blocked ranges first
            for blocked_range in self.blocked_ip_ranges:
                if ip in ipaddress.ip_network(blocked_range):
                    violations.append(f"IP {hostname} is in blocked range {blocked_range}")
                    return violations
            
            # Check if in allowed ranges
            in_allowed_range = False
            for allowed_range in self.allowed_ip_ranges:
                if ip in ipaddress.ip_network(allowed_range):
                    in_allowed_range = True
                    break
            
            if not in_allowed_range:
                violations.append(f"IP {hostname} is not in any allowed range")
                
        except ipaddress.AddressValueError:
            # Not an IP address, skip IP validation
            pass
        except Exception as e:
            violations.append(f"IP validation error: {str(e)}")
        
        return violations
    
    def _validate_domain(self, hostname: str) -> List[str]:
        """Validate domain against allowed/blocked lists"""
        violations = []
        
        if not hostname:
            return violations
        
        # Check against blocked domains
        for blocked_pattern in self.blocked_domains:
            if self._match_domain_pattern(hostname, blocked_pattern):
                violations.append(f"Domain {hostname} matches blocked pattern {blocked_pattern}")
                return violations
        
        # Check if in allowed domains
        in_allowed_domain = False
        for allowed_pattern in self.allowed_domains:
            if self._match_domain_pattern(hostname, allowed_pattern):
                in_allowed_domain = True
                break
        
        if not in_allowed_domain:
            violations.append(f"Domain {hostname} is not in allowed domains list")
        
        return violations
    
    def _validate_scan_type(self, scan_type: str, user_id: int) -> List[str]:
        """Validate scan type permissions"""
        violations = []
        
        if scan_type in self.scan_type_policies:
            policy = self.scan_type_policies[scan_type]
            
            # Check user permissions (simplified - would integrate with real auth)
            if "allowed_users" in policy:
                # In real implementation, would check user roles from database
                # For now, assume user_id 1 is admin
                if user_id != 1 and "admin" in policy["allowed_users"]:
                    violations.append(f"Scan type {scan_type} requires admin privileges")
        
        return violations
    
    def _validate_port(self, port: int, scan_type: str) -> List[str]:
        """Validate port restrictions"""
        violations = []
        
        # Block dangerous ports
        dangerous_ports = [25, 465, 587, 993, 995]  # Email ports
        if port in dangerous_ports:
            violations.append(f"Port {port} is restricted for security reasons")
        
        return violations
    
    def _match_domain_pattern(self, hostname: str, pattern: str) -> bool:
        """Match hostname against domain pattern (supports wildcards)"""
        if pattern.startswith("*."):
            # Wildcard subdomain matching
            domain_suffix = pattern[2:]
            return hostname.endswith(domain_suffix) or hostname == domain_suffix
        else:
            # Exact match
            return hostname == pattern
    
    def get_allowed_targets(self, user_id: int) -> Dict[str, Any]:
        """Get list of allowed targets for user"""
        return {
            "allowed_domains": self.allowed_domains,
            "allowed_ip_ranges": self.allowed_ip_ranges,
            "scan_type_policies": self.scan_type_policies
        }
    
    def add_allowed_domain(self, domain: str, user_id: int) -> bool:
        """Add domain to allowed list (admin only)"""
        # In real implementation, would check admin permissions
        if user_id == 1:  # Simplified admin check
            self.allowed_domains.append(domain)
            logger.info(f"Added allowed domain: {domain}")
            return True
        return False
    
    def remove_allowed_domain(self, domain: str, user_id: int) -> bool:
        """Remove domain from allowed list (admin only)"""
        if user_id == 1 and domain in self.allowed_domains:
            self.allowed_domains.remove(domain)
            logger.info(f"Removed allowed domain: {domain}")
            return True
        return False