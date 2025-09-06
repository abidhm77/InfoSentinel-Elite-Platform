#!/usr/bin/env python3
"""
Multi-Tenant Architecture Manager for InfoSentinel Enterprise.
Provides organization management, tenant isolation, and resource allocation.
"""
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from database.db import get_postgres_session, close_postgres_session
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)
Base = declarative_base()

class TenantStatus(Enum):
    """Tenant status types."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"
    PENDING = "pending"

class SubscriptionTier(Enum):
    """Subscription tier types."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"

class UserRole(Enum):
    """User role types within organizations."""
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    ANALYST = "analyst"
    VIEWER = "viewer"
    GUEST = "guest"

@dataclass
class ResourceLimits:
    """Resource limits for tenants."""
    max_scans_per_month: int
    max_concurrent_scans: int
    max_users: int
    max_assets: int
    max_storage_gb: float
    max_api_calls_per_hour: int
    retention_days: int
    advanced_features: bool

class Organization(Base):
    """Organization/Tenant model."""
    __tablename__ = 'organizations'
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True)
    status = Column(String(20), default=TenantStatus.ACTIVE.value)
    subscription_tier = Column(String(20), default=SubscriptionTier.FREE.value)
    industry = Column(String(100))
    company_size = Column(String(50))
    country = Column(String(100))
    
    # Subscription details
    subscription_start = Column(DateTime, default=datetime.utcnow)
    subscription_end = Column(DateTime)
    trial_end = Column(DateTime)
    
    # Resource limits (JSON)
    resource_limits = Column(Text)  # JSON serialized ResourceLimits
    
    # Usage tracking
    current_users = Column(Integer, default=0)
    current_scans_this_month = Column(Integer, default=0)
    current_storage_gb = Column(Float, default=0.0)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    # Metadata
    settings = Column(Text)  # JSON for organization-specific settings
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("OrganizationUser", back_populates="organization")
    usage_logs = relationship("UsageLog", back_populates="organization")

class OrganizationUser(Base):
    """User membership in organizations."""
    __tablename__ = 'organization_users'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    user_id = Column(Integer, nullable=False)  # References main user table
    role = Column(String(20), default=UserRole.VIEWER.value)
    permissions = Column(Text)  # JSON array of specific permissions
    
    # Status
    is_active = Column(Boolean, default=True)
    invited_by = Column(Integer)  # User ID who sent invitation
    invited_at = Column(DateTime)
    joined_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")

class UsageLog(Base):
    """Usage tracking for organizations."""
    __tablename__ = 'usage_logs'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    user_id = Column(Integer)
    
    # Usage metrics
    resource_type = Column(String(50), nullable=False)  # scan, api_call, storage, etc.
    resource_count = Column(Integer, default=1)
    resource_size = Column(Float)  # For storage, data transfer, etc.
    
    # Context
    action = Column(String(100))  # specific action performed
    metadata = Column(Text)  # JSON with additional context
    
    # Timing
    timestamp = Column(DateTime, default=datetime.utcnow)
    billing_period = Column(String(7))  # YYYY-MM format
    
    # Relationships
    organization = relationship("Organization", back_populates="usage_logs")

class TenantInvitation(Base):
    """Invitations to join organizations."""
    __tablename__ = 'tenant_invitations'
    
    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    email = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.VIEWER.value)
    
    # Invitation details
    invited_by = Column(Integer, nullable=False)  # User ID
    invitation_token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Status
    is_accepted = Column(Boolean, default=False)
    accepted_at = Column(DateTime)
    accepted_by = Column(Integer)  # User ID who accepted
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)

class TenantManager:
    """
    Multi-tenant architecture manager.
    """
    
    def __init__(self):
        """
        Initialize the tenant manager.
        """
        # Default resource limits by subscription tier
        self.tier_limits = {
            SubscriptionTier.FREE: ResourceLimits(
                max_scans_per_month=10,
                max_concurrent_scans=1,
                max_users=3,
                max_assets=50,
                max_storage_gb=1.0,
                max_api_calls_per_hour=100,
                retention_days=30,
                advanced_features=False
            ),
            SubscriptionTier.STARTER: ResourceLimits(
                max_scans_per_month=100,
                max_concurrent_scans=3,
                max_users=10,
                max_assets=500,
                max_storage_gb=10.0,
                max_api_calls_per_hour=1000,
                retention_days=90,
                advanced_features=False
            ),
            SubscriptionTier.PROFESSIONAL: ResourceLimits(
                max_scans_per_month=1000,
                max_concurrent_scans=10,
                max_users=50,
                max_assets=5000,
                max_storage_gb=100.0,
                max_api_calls_per_hour=10000,
                retention_days=365,
                advanced_features=True
            ),
            SubscriptionTier.ENTERPRISE: ResourceLimits(
                max_scans_per_month=10000,
                max_concurrent_scans=50,
                max_users=500,
                max_assets=50000,
                max_storage_gb=1000.0,
                max_api_calls_per_hour=100000,
                retention_days=1095,  # 3 years
                advanced_features=True
            )
        }
        
        # Role permissions mapping
        self.role_permissions = {
            UserRole.OWNER: [
                'org.manage', 'org.delete', 'org.billing',
                'users.invite', 'users.remove', 'users.manage_roles',
                'scans.create', 'scans.view', 'scans.delete',
                'reports.create', 'reports.view', 'reports.export',
                'settings.manage', 'integrations.manage'
            ],
            UserRole.ADMIN: [
                'org.view', 'users.invite', 'users.manage_roles',
                'scans.create', 'scans.view', 'scans.delete',
                'reports.create', 'reports.view', 'reports.export',
                'settings.manage', 'integrations.manage'
            ],
            UserRole.MANAGER: [
                'org.view', 'users.invite',
                'scans.create', 'scans.view',
                'reports.create', 'reports.view', 'reports.export',
                'settings.view'
            ],
            UserRole.ANALYST: [
                'org.view', 'scans.create', 'scans.view',
                'reports.create', 'reports.view'
            ],
            UserRole.VIEWER: [
                'org.view', 'scans.view', 'reports.view'
            ],
            UserRole.GUEST: [
                'reports.view'
            ]
        }
    
    def create_organization(self, name: str, domain: str, owner_user_id: int, 
                          subscription_tier: SubscriptionTier = SubscriptionTier.FREE,
                          industry: str = None, company_size: str = None) -> Dict:
        """
        Create a new organization/tenant.
        
        Args:
            name: Organization name
            domain: Organization domain
            owner_user_id: User ID of the organization owner
            subscription_tier: Subscription tier
            industry: Industry sector
            company_size: Company size category
            
        Returns:
            Organization creation result
        """
        try:
            session = get_postgres_session()
            
            # Check if domain already exists
            existing_org = session.query(Organization).filter(Organization.domain == domain).first()
            if existing_org:
                return {
                    'success': False,
                    'error': 'Domain already exists'
                }
            
            # Get resource limits for tier
            limits = self.tier_limits.get(subscription_tier, self.tier_limits[SubscriptionTier.FREE])
            
            # Set trial period for non-free tiers
            trial_end = None
            if subscription_tier != SubscriptionTier.FREE:
                trial_end = datetime.utcnow() + timedelta(days=14)  # 14-day trial
            
            # Create organization
            organization = Organization(
                name=name,
                domain=domain,
                status=TenantStatus.TRIAL.value if trial_end else TenantStatus.ACTIVE.value,
                subscription_tier=subscription_tier.value,
                industry=industry,
                company_size=company_size,
                trial_end=trial_end,
                resource_limits=json.dumps(limits.__dict__),
                current_users=1  # Owner
            )
            
            session.add(organization)
            session.flush()  # Get the ID
            
            # Add owner as organization user
            owner_membership = OrganizationUser(
                organization_id=organization.id,
                user_id=owner_user_id,
                role=UserRole.OWNER.value,
                permissions=json.dumps(self.role_permissions[UserRole.OWNER])
            )
            
            session.add(owner_membership)
            session.commit()
            
            logger.info(f"Organization created: {name} (ID: {organization.id}, Tenant: {organization.tenant_id})")
            
            return {
                'success': True,
                'organization': {
                    'id': organization.id,
                    'tenant_id': organization.tenant_id,
                    'name': organization.name,
                    'domain': organization.domain,
                    'status': organization.status,
                    'subscription_tier': organization.subscription_tier,
                    'trial_end': organization.trial_end.isoformat() if organization.trial_end else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating organization: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def get_organization(self, tenant_id: str) -> Optional[Dict]:
        """
        Get organization by tenant ID.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Organization data or None
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return None
            
            # Parse resource limits
            limits = json.loads(organization.resource_limits) if organization.resource_limits else {}
            
            return {
                'id': organization.id,
                'tenant_id': organization.tenant_id,
                'name': organization.name,
                'domain': organization.domain,
                'status': organization.status,
                'subscription_tier': organization.subscription_tier,
                'industry': organization.industry,
                'company_size': organization.company_size,
                'subscription_start': organization.subscription_start.isoformat() if organization.subscription_start else None,
                'subscription_end': organization.subscription_end.isoformat() if organization.subscription_end else None,
                'trial_end': organization.trial_end.isoformat() if organization.trial_end else None,
                'resource_limits': limits,
                'current_usage': {
                    'users': organization.current_users,
                    'scans_this_month': organization.current_scans_this_month,
                    'storage_gb': organization.current_storage_gb
                },
                'last_activity': organization.last_activity.isoformat() if organization.last_activity else None,
                'created_at': organization.created_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting organization {tenant_id}: {str(e)}")
            return None
        finally:
            close_postgres_session(session)
    
    def invite_user(self, tenant_id: str, email: str, role: UserRole, 
                   invited_by_user_id: int) -> Dict:
        """
        Invite a user to join an organization.
        
        Args:
            tenant_id: Tenant identifier
            email: Email address to invite
            role: Role to assign
            invited_by_user_id: User ID sending the invitation
            
        Returns:
            Invitation result
        """
        try:
            session = get_postgres_session()
            
            # Get organization
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return {
                    'success': False,
                    'error': 'Organization not found'
                }
            
            # Check if user can invite (permission check would go here)
            # For now, assume the check is done at the API level
            
            # Check resource limits
            limits = json.loads(organization.resource_limits)
            if organization.current_users >= limits.get('max_users', 1):
                return {
                    'success': False,
                    'error': 'User limit reached for this subscription tier'
                }
            
            # Check if invitation already exists
            existing_invitation = session.query(TenantInvitation).filter(
                TenantInvitation.organization_id == organization.id,
                TenantInvitation.email == email,
                TenantInvitation.is_accepted == False,
                TenantInvitation.expires_at > datetime.utcnow()
            ).first()
            
            if existing_invitation:
                return {
                    'success': False,
                    'error': 'Invitation already sent to this email'
                }
            
            # Create invitation
            invitation_token = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(days=7)  # 7-day expiry
            
            invitation = TenantInvitation(
                organization_id=organization.id,
                email=email,
                role=role.value,
                invited_by=invited_by_user_id,
                invitation_token=invitation_token,
                expires_at=expires_at
            )
            
            session.add(invitation)
            session.commit()
            
            logger.info(f"User invited to organization {organization.name}: {email} as {role.value}")
            
            # In a real implementation, you would send an email here
            
            return {
                'success': True,
                'invitation': {
                    'id': invitation.id,
                    'email': invitation.email,
                    'role': invitation.role,
                    'token': invitation_token,
                    'expires_at': invitation.expires_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error inviting user: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def accept_invitation(self, invitation_token: str, user_id: int) -> Dict:
        """
        Accept an organization invitation.
        
        Args:
            invitation_token: Invitation token
            user_id: User ID accepting the invitation
            
        Returns:
            Acceptance result
        """
        try:
            session = get_postgres_session()
            
            # Get invitation
            invitation = session.query(TenantInvitation).filter(
                TenantInvitation.invitation_token == invitation_token,
                TenantInvitation.is_accepted == False,
                TenantInvitation.expires_at > datetime.utcnow()
            ).first()
            
            if not invitation:
                return {
                    'success': False,
                    'error': 'Invalid or expired invitation'
                }
            
            # Get organization
            organization = session.query(Organization).filter(
                Organization.id == invitation.organization_id
            ).first()
            
            # Check if user is already a member
            existing_membership = session.query(OrganizationUser).filter(
                OrganizationUser.organization_id == organization.id,
                OrganizationUser.user_id == user_id
            ).first()
            
            if existing_membership:
                return {
                    'success': False,
                    'error': 'User is already a member of this organization'
                }
            
            # Create organization membership
            role = UserRole(invitation.role)
            membership = OrganizationUser(
                organization_id=organization.id,
                user_id=user_id,
                role=invitation.role,
                permissions=json.dumps(self.role_permissions[role]),
                invited_by=invitation.invited_by,
                invited_at=invitation.created_at
            )
            
            session.add(membership)
            
            # Mark invitation as accepted
            invitation.is_accepted = True
            invitation.accepted_at = datetime.utcnow()
            invitation.accepted_by = user_id
            
            # Update organization user count
            organization.current_users += 1
            
            session.commit()
            
            logger.info(f"User {user_id} accepted invitation to organization {organization.name}")
            
            return {
                'success': True,
                'organization': {
                    'id': organization.id,
                    'tenant_id': organization.tenant_id,
                    'name': organization.name,
                    'role': invitation.role
                }
            }
            
        except Exception as e:
            logger.error(f"Error accepting invitation: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def check_resource_limits(self, tenant_id: str, resource_type: str, 
                            requested_amount: int = 1) -> Dict:
        """
        Check if organization can use requested resources.
        
        Args:
            tenant_id: Tenant identifier
            resource_type: Type of resource (scans, users, storage, etc.)
            requested_amount: Amount of resource requested
            
        Returns:
            Resource check result
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return {
                    'allowed': False,
                    'error': 'Organization not found'
                }
            
            # Check organization status
            if organization.status in [TenantStatus.SUSPENDED.value, TenantStatus.EXPIRED.value]:
                return {
                    'allowed': False,
                    'error': f'Organization is {organization.status}'
                }
            
            # Parse resource limits
            limits = json.loads(organization.resource_limits)
            
            # Check specific resource limits
            if resource_type == 'scans':
                current_scans = organization.current_scans_this_month
                max_scans = limits.get('max_scans_per_month', 0)
                
                if current_scans + requested_amount > max_scans:
                    return {
                        'allowed': False,
                        'error': f'Monthly scan limit exceeded ({current_scans}/{max_scans})',
                        'current_usage': current_scans,
                        'limit': max_scans
                    }
            
            elif resource_type == 'users':
                current_users = organization.current_users
                max_users = limits.get('max_users', 0)
                
                if current_users + requested_amount > max_users:
                    return {
                        'allowed': False,
                        'error': f'User limit exceeded ({current_users}/{max_users})',
                        'current_usage': current_users,
                        'limit': max_users
                    }
            
            elif resource_type == 'storage':
                current_storage = organization.current_storage_gb
                max_storage = limits.get('max_storage_gb', 0)
                
                if current_storage + requested_amount > max_storage:
                    return {
                        'allowed': False,
                        'error': f'Storage limit exceeded ({current_storage:.1f}/{max_storage}GB)',
                        'current_usage': current_storage,
                        'limit': max_storage
                    }
            
            return {
                'allowed': True,
                'limits': limits
            }
            
        except Exception as e:
            logger.error(f"Error checking resource limits: {str(e)}")
            return {
                'allowed': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def log_resource_usage(self, tenant_id: str, user_id: int, resource_type: str,
                          resource_count: int = 1, resource_size: float = None,
                          action: str = None, metadata: Dict = None) -> bool:
        """
        Log resource usage for billing and monitoring.
        
        Args:
            tenant_id: Tenant identifier
            user_id: User ID performing the action
            resource_type: Type of resource used
            resource_count: Number of resources used
            resource_size: Size of resource (for storage, etc.)
            action: Specific action performed
            metadata: Additional context
            
        Returns:
            Success status
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return False
            
            # Create usage log
            billing_period = datetime.utcnow().strftime('%Y-%m')
            
            usage_log = UsageLog(
                organization_id=organization.id,
                user_id=user_id,
                resource_type=resource_type,
                resource_count=resource_count,
                resource_size=resource_size,
                action=action,
                metadata=json.dumps(metadata) if metadata else None,
                billing_period=billing_period
            )
            
            session.add(usage_log)
            
            # Update organization usage counters
            if resource_type == 'scan':
                organization.current_scans_this_month += resource_count
            elif resource_type == 'storage':
                organization.current_storage_gb += resource_size or 0
            
            organization.last_activity = datetime.utcnow()
            
            session.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging resource usage: {str(e)}")
            session.rollback()
            return False
        finally:
            close_postgres_session(session)
    
    def get_organization_users(self, tenant_id: str) -> List[Dict]:
        """
        Get all users in an organization.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            List of organization users
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return []
            
            users = session.query(OrganizationUser).filter(
                OrganizationUser.organization_id == organization.id,
                OrganizationUser.is_active == True
            ).all()
            
            user_list = []
            for user in users:
                user_list.append({
                    'id': user.id,
                    'user_id': user.user_id,
                    'role': user.role,
                    'permissions': json.loads(user.permissions) if user.permissions else [],
                    'joined_at': user.joined_at.isoformat() if user.joined_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'invited_by': user.invited_by
                })
            
            return user_list
            
        except Exception as e:
            logger.error(f"Error getting organization users: {str(e)}")
            return []
        finally:
            close_postgres_session(session)
    
    def get_usage_statistics(self, tenant_id: str, period_months: int = 12) -> Dict:
        """
        Get usage statistics for an organization.
        
        Args:
            tenant_id: Tenant identifier
            period_months: Number of months to analyze
            
        Returns:
            Usage statistics
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return {}
            
            # Get usage logs for the period
            start_date = datetime.utcnow() - timedelta(days=30 * period_months)
            
            usage_logs = session.query(UsageLog).filter(
                UsageLog.organization_id == organization.id,
                UsageLog.timestamp >= start_date
            ).all()
            
            # Aggregate usage by type and month
            usage_by_month = {}
            resource_totals = {}
            
            for log in usage_logs:
                month = log.billing_period
                resource_type = log.resource_type
                
                if month not in usage_by_month:
                    usage_by_month[month] = {}
                
                if resource_type not in usage_by_month[month]:
                    usage_by_month[month][resource_type] = 0
                
                usage_by_month[month][resource_type] += log.resource_count
                
                # Track totals
                if resource_type not in resource_totals:
                    resource_totals[resource_type] = 0
                resource_totals[resource_type] += log.resource_count
            
            # Get current limits
            limits = json.loads(organization.resource_limits)
            
            return {
                'organization': {
                    'name': organization.name,
                    'subscription_tier': organization.subscription_tier,
                    'status': organization.status
                },
                'current_usage': {
                    'users': organization.current_users,
                    'scans_this_month': organization.current_scans_this_month,
                    'storage_gb': organization.current_storage_gb
                },
                'limits': limits,
                'usage_by_month': usage_by_month,
                'resource_totals': resource_totals,
                'utilization_percentages': {
                    'users': (organization.current_users / limits.get('max_users', 1)) * 100,
                    'scans': (organization.current_scans_this_month / limits.get('max_scans_per_month', 1)) * 100,
                    'storage': (organization.current_storage_gb / limits.get('max_storage_gb', 1)) * 100
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting usage statistics: {str(e)}")
            return {}
        finally:
            close_postgres_session(session)
    
    def update_subscription(self, tenant_id: str, new_tier: SubscriptionTier) -> Dict:
        """
        Update organization subscription tier.
        
        Args:
            tenant_id: Tenant identifier
            new_tier: New subscription tier
            
        Returns:
            Update result
        """
        try:
            session = get_postgres_session()
            
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return {
                    'success': False,
                    'error': 'Organization not found'
                }
            
            # Get new limits
            new_limits = self.tier_limits.get(new_tier, self.tier_limits[SubscriptionTier.FREE])
            
            # Update organization
            organization.subscription_tier = new_tier.value
            organization.resource_limits = json.dumps(new_limits.__dict__)
            organization.subscription_start = datetime.utcnow()
            
            # Set subscription end date (1 year from now for paid tiers)
            if new_tier != SubscriptionTier.FREE:
                organization.subscription_end = datetime.utcnow() + timedelta(days=365)
            
            # Update status
            organization.status = TenantStatus.ACTIVE.value
            
            session.commit()
            
            logger.info(f"Subscription updated for organization {organization.name}: {new_tier.value}")
            
            return {
                'success': True,
                'organization': {
                    'name': organization.name,
                    'subscription_tier': organization.subscription_tier,
                    'subscription_end': organization.subscription_end.isoformat() if organization.subscription_end else None,
                    'new_limits': new_limits.__dict__
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating subscription: {str(e)}")
            session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            close_postgres_session(session)
    
    def check_user_permissions(self, tenant_id: str, user_id: int, required_permission: str) -> bool:
        """
        Check if user has required permission in organization.
        
        Args:
            tenant_id: Tenant identifier
            user_id: User ID
            required_permission: Permission to check
            
        Returns:
            Permission status
        """
        try:
            session = get_postgres_session()
            
            # Get organization
            organization = session.query(Organization).filter(
                Organization.tenant_id == tenant_id
            ).first()
            
            if not organization:
                return False
            
            # Get user membership
            membership = session.query(OrganizationUser).filter(
                OrganizationUser.organization_id == organization.id,
                OrganizationUser.user_id == user_id,
                OrganizationUser.is_active == True
            ).first()
            
            if not membership:
                return False
            
            # Check permissions
            user_permissions = json.loads(membership.permissions) if membership.permissions else []
            
            return required_permission in user_permissions
            
        except Exception as e:
            logger.error(f"Error checking user permissions: {str(e)}")
            return False
        finally:
            close_postgres_session(session)
    
    def get_tenant_context(self, user_id: int) -> List[Dict]:
        """
        Get all organizations a user belongs to.
        
        Args:
            user_id: User ID
            
        Returns:
            List of organizations with user's role
        """
        try:
            session = get_postgres_session()
            
            memberships = session.query(OrganizationUser, Organization).join(
                Organization, OrganizationUser.organization_id == Organization.id
            ).filter(
                OrganizationUser.user_id == user_id,
                OrganizationUser.is_active == True
            ).all()
            
            organizations = []
            for membership, org in memberships:
                organizations.append({
                    'tenant_id': org.tenant_id,
                    'name': org.name,
                    'domain': org.domain,
                    'role': membership.role,
                    'subscription_tier': org.subscription_tier,
                    'status': org.status,
                    'permissions': json.loads(membership.permissions) if membership.permissions else []
                })
            
            return organizations
            
        except Exception as e:
            logger.error(f"Error getting tenant context: {str(e)}")
            return []
        finally:
            close_postgres_session(session)