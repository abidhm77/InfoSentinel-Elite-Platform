# InfoSentinel Enterprise Multi-Tenancy Implementation

This document provides an overview of the enterprise-grade multi-tenancy implementation for InfoSentinel.

## Overview

The multi-tenancy architecture enables InfoSentinel to securely serve multiple organizations (tenants) from a single deployment while maintaining strict data isolation and providing tenant-specific configurations.

## Key Components

### 1. Tenant Middleware
- Automatically extracts tenant context from requests
- Validates tenant access permissions
- Propagates tenant context throughout the request lifecycle

### 2. Tenant-Aware Database Models
- Row-level security for all tenant data
- Automatic tenant filtering on database queries
- Prevents cross-tenant data access

### 3. Tenant Management API
- Create, update, and manage tenants
- Configure tenant-specific settings
- Handle tenant lifecycle (onboarding/offboarding)

### 4. MSP Cross-Tenant Reporting
- Aggregated security posture views across tenants
- Comparative analysis for managed service providers
- Compliance status tracking across the tenant portfolio

### 5. Tenant Onboarding Workflow
- Streamlined tenant creation process
- Industry-specific templates and configurations
- Secure tenant provisioning

## Getting Started

### Prerequisites
- InfoSentinel backend running
- Database with multi-tenancy schema updates

### Testing Multi-Tenancy

Run the test script to verify functionality:

```bash
python backend/test_multi_tenancy.py
```

### Creating a New Tenant

Use the tenant onboarding UI at `/tenants/onboard` or make a direct API call:

```bash
curl -X POST http://localhost:8000/api/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": {
      "name": "Example Corp",
      "domain": "example.com",
      "industry": "technology",
      "subscription_tier": "standard"
    },
    "owner": {
      "name": "Admin User",
      "email": "admin@example.com"
    }
  }'
```

### Accessing Tenant-Specific Data

All API requests must include the tenant context, either via:
- `X-Tenant-ID` header
- JWT token with tenant_id claim
- Subdomain (if configured)

Example:
```bash
curl -X GET http://localhost:8000/api/scans \
  -H "Authorization: Bearer <token>" \
  -H "X-Tenant-ID: <tenant_id>"
```

## Architecture Details

### Data Isolation Strategy
- Each database record is associated with a tenant_id
- Tenant middleware enforces access control
- Query filtering automatically applied at the ORM level

### Tenant Configuration
- Tenant-specific security policies
- Custom compliance frameworks
- Scan frequency and notification preferences
- Branding and UI customization

### MSP Features
- Multi-tenant dashboard for service providers
- Cross-tenant vulnerability reporting
- Comparative security posture analysis

## Security Considerations

- Tenant data is encrypted with tenant-specific keys
- Strict validation of tenant context in all requests
- Regular audit logging of cross-tenant operations
- Tenant isolation testing as part of CI/CD

## Next Steps

1. Complete the tenant management dashboard UI
2. Implement tenant-specific reporting templates
3. Add tenant data migration tools
4. Enhance MSP comparative analytics