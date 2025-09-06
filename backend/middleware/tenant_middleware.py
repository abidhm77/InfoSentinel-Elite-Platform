"""
Tenant Context Middleware for InfoSentinel.

This middleware handles tenant context propagation throughout the application stack,
ensuring proper data isolation and access control for multi-tenant environments.
"""

import json
import logging
from typing import Optional, Dict, Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.orm import Session

from backend.enterprise.tenant_manager import TenantManager
from backend.services.enterprise_logger import logger

# Thread-local storage for tenant context
from contextvars import ContextVar

# Global context variable to store tenant information
tenant_context_var: ContextVar[Dict] = ContextVar("tenant_context", default=None)


def get_current_tenant_id() -> Optional[str]:
    """
    Get the current tenant ID from the context.
    
    Returns:
        Current tenant ID or None if not in tenant context
    """
    context = tenant_context_var.get()
    return context.get("tenant_id") if context else None


def get_tenant_context() -> Optional[Dict]:
    """
    Get the full tenant context.
    
    Returns:
        Current tenant context or None
    """
    return tenant_context_var.get()


def set_tenant_context(tenant_data: Dict) -> None:
    """
    Set the tenant context.
    
    Args:
        tenant_data: Tenant context data
    """
    tenant_context_var.set(tenant_data)


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Middleware for handling tenant context in requests.
    
    This middleware:
    1. Extracts tenant information from request headers or tokens
    2. Validates tenant access and permissions
    3. Sets tenant context for the request lifecycle
    4. Ensures proper cleanup after request processing
    """
    
    def __init__(self, app: ASGIApp):
        """
        Initialize the tenant middleware.
        
        Args:
            app: ASGI application
        """
        super().__init__(app)
        self.tenant_manager = TenantManager()
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and set tenant context.
        
        Args:
            request: HTTP request
            call_next: Next middleware in chain
            
        Returns:
            HTTP response
        """
        tenant_id = None
        tenant_context = None
        
        # Extract tenant ID from various sources
        # 1. From header (preferred for API calls)
        if "X-Tenant-ID" in request.headers:
            tenant_id = request.headers.get("X-Tenant-ID")
        
        # 2. From authorization token (JWT)
        elif "Authorization" in request.headers:
            # Extract tenant from JWT token (implementation depends on your auth system)
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.replace("Bearer ", "")
                # This would be replaced with your actual JWT parsing logic
                try:
                    # Placeholder for JWT token parsing
                    # In a real implementation, you would decode and validate the JWT
                    # and extract tenant information from claims
                    pass
                except Exception as e:
                    logger.error(f"Error parsing JWT token: {str(e)}")
        
        # 3. From subdomain (for web UI)
        host = request.headers.get("host", "")
        if not tenant_id and "." in host and not host.startswith("www."):
            subdomain = host.split(".")[0]
            # Look up tenant by subdomain
            # This is a placeholder - you would implement the actual lookup
            
        # 4. From path parameter (for some API endpoints)
        path = request.url.path
        if not tenant_id and "/api/tenants/" in path:
            # Extract tenant ID from path
            # Example: /api/tenants/{tenant_id}/resources
            path_parts = path.split("/")
            if len(path_parts) > 3 and path_parts[2] == "tenants":
                tenant_id = path_parts[3]
        
        # If tenant ID is found, validate and set context
        if tenant_id:
            # Get tenant information from database
            tenant_data = self.tenant_manager.get_organization(tenant_id)
            
            if tenant_data:
                # Set tenant context for this request
                tenant_context = {
                    "tenant_id": tenant_id,
                    "name": tenant_data.get("name"),
                    "subscription_tier": tenant_data.get("subscription_tier"),
                    "status": tenant_data.get("status")
                }
                set_tenant_context(tenant_context)
                logger.debug(f"Tenant context set: {tenant_id}")
            else:
                logger.warning(f"Invalid tenant ID: {tenant_id}")
        
        # Add tenant ID to request state for easy access in route handlers
        request.state.tenant_id = tenant_id
        request.state.tenant_context = tenant_context
        
        # Process the request
        try:
            response = await call_next(request)
            
            # Add tenant ID to response headers for debugging
            if tenant_id and response:
                response.headers["X-Tenant-ID"] = tenant_id
                
            return response
        finally:
            # Clear tenant context after request is processed
            if tenant_context:
                set_tenant_context(None)
                logger.debug(f"Tenant context cleared: {tenant_id}")