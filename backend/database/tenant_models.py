"""
Tenant-aware database models for InfoSentinel.

This module defines base classes and mixins for tenant-aware models,
ensuring proper data isolation between tenants.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Index, event
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Session, Query, relationship
from sqlalchemy.sql import operators
from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID, JSONB

from backend.database.db import Base
from backend.middleware.tenant_middleware import get_current_tenant_id


class TenantMixin:
    """
    Mixin for tenant-aware models.
    
    This mixin adds tenant_id column to models and automatically
    filters queries by the current tenant context.
    """
    
    @declared_attr
    def tenant_id(cls):
        """Add tenant_id column to model."""
        return Column(String(36), nullable=False, index=True)
    
    @declared_attr
    def __table_args__(cls):
        """Add tenant_id index to model."""
        return (
            Index(f"ix_{cls.__tablename__}_tenant_id", "tenant_id"),
        )
    
    @classmethod
    def get_for_tenant(cls, session: Session, tenant_id: str) -> Query:
        """
        Get query filtered by tenant ID.
        
        Args:
            session: Database session
            tenant_id: Tenant ID to filter by
            
        Returns:
            Query filtered by tenant ID
        """
        return session.query(cls).filter(cls.tenant_id == tenant_id)
    
    @classmethod
    def get_for_current_tenant(cls, session: Session) -> Query:
        """
        Get query filtered by current tenant context.
        
        Args:
            session: Database session
            
        Returns:
            Query filtered by current tenant ID
        """
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            raise ValueError("No tenant context found")
        
        return cls.get_for_tenant(session, tenant_id)


class TenantAwareBase(Base):
    """
    Base class for tenant-aware models.
    
    This class combines the SQLAlchemy Base with the TenantMixin.
    """
    __abstract__ = True
    
    # Include tenant mixin
    tenant_id = Column(String(36), nullable=False, index=True)
    
    # Common fields for all tenant-aware models
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    @declared_attr
    def __table_args__(cls):
        """Add tenant_id index to model."""
        return (
            Index(f"ix_{cls.__tablename__}_tenant_id", "tenant_id"),
        )


# SQLAlchemy event listeners to enforce tenant isolation

@event.listens_for(Session, "before_flush")
def set_tenant_id_before_flush(session, flush_context, instances):
    """
    Set tenant_id on new objects before flush.
    
    This ensures that all new objects have the current tenant ID.
    """
    tenant_id = get_current_tenant_id()
    
    if not tenant_id:
        # Skip if no tenant context (e.g., system operations)
        return
    
    for obj in session.new:
        if hasattr(obj, "tenant_id") and not getattr(obj, "tenant_id", None):
            setattr(obj, "tenant_id", tenant_id)


@event.listens_for(Query, "before_compile", retval=True)
def filter_query_by_tenant(query):
    """
    Filter queries by tenant ID automatically.
    
    This ensures that queries only return data for the current tenant.
    """
    tenant_id = get_current_tenant_id()
    
    # Skip filtering for non-tenant-aware models or system operations
    if not tenant_id:
        return query
    
    # Check if any of the models in the query are tenant-aware
    for entity in query.column_descriptions:
        entity_cls = entity["entity"]
        
        # Skip if not a class or not tenant-aware
        if not hasattr(entity_cls, "tenant_id"):
            continue
        
        # Add tenant filter to query
        query = query.filter(entity_cls.tenant_id == tenant_id)
        break
    
    return query


# Tenant-specific configuration model

class TenantConfig(TenantAwareBase):
    """
    Tenant-specific configuration settings.
    
    This model stores configuration settings for each tenant,
    allowing for customization of the application behavior.
    """
    __tablename__ = "tenant_configs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Configuration categories
    security_policy = Column(JSONB, default=dict)
    compliance_frameworks = Column(JSONB, default=dict)
    scan_settings = Column(JSONB, default=dict)
    notification_settings = Column(JSONB, default=dict)
    branding = Column(JSONB, default=dict)
    integration_settings = Column(JSONB, default=dict)
    
    # Audit trail
    last_modified_by = Column(String(255))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "security_policy": self.security_policy,
            "compliance_frameworks": self.compliance_frameworks,
            "scan_settings": self.scan_settings,
            "notification_settings": self.notification_settings,
            "branding": self.branding,
            "integration_settings": self.integration_settings,
            "last_modified_by": self.last_modified_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


# Tenant encryption key model

class TenantEncryptionKey(TenantAwareBase):
    """
    Tenant-specific encryption keys.
    
    This model stores encryption keys for each tenant,
    enabling tenant-specific data encryption.
    """
    __tablename__ = "tenant_encryption_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Key information
    key_id = Column(String(255), nullable=False, unique=True)
    key_type = Column(String(50), nullable=False)  # data, config, etc.
    active = Column(Boolean, default=True)
    
    # Encrypted key material (encrypted with master key)
    encrypted_key = Column(String(1024), nullable=False)
    
    # Key rotation
    created_by = Column(String(255))
    expires_at = Column(DateTime(timezone=True))
    rotated_at = Column(DateTime(timezone=True))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "key_id": self.key_id,
            "key_type": self.key_type,
            "active": self.active,
            "created_by": self.created_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }