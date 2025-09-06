"""
Multi-Tenancy Test Script

This script tests the core functionality of the multi-tenancy implementation.
"""

import requests
import json
import uuid

# Base URL for the API
BASE_URL = "http://localhost:8000"

def test_tenant_creation():
    """Test creating a new tenant"""
    print("\n=== Testing Tenant Creation ===")
    
    # Generate unique tenant name
    tenant_name = f"Test Tenant {uuid.uuid4().hex[:8]}"
    
    # Create tenant payload
    payload = {
        "tenant": {
            "name": tenant_name,
            "domain": f"{tenant_name.lower().replace(' ', '')}.example.com",
            "industry": "technology",
            "subscription_tier": "standard"
        },
        "owner": {
            "name": "Test Admin",
            "email": f"admin@{tenant_name.lower().replace(' ', '')}.example.com"
        }
    }
    
    # Send request
    response = requests.post(f"{BASE_URL}/api/tenants", json=payload)
    
    # Print results
    print(f"Status Code: {response.status_code}")
    if response.status_code == 201:
        tenant_data = response.json()
        print(f"Tenant Created: {tenant_data['name']} (ID: {tenant_data['tenant_id']})")
        return tenant_data
    else:
        print(f"Error: {response.text}")
        return None

def test_tenant_authentication(tenant_id, admin_email):
    """Test tenant-specific authentication"""
    print("\n=== Testing Tenant Authentication ===")
    
    # Authentication payload
    payload = {
        "username": admin_email,
        "password": "password"  # Assuming default password for test
    }
    
    # Add tenant ID header
    headers = {"X-Tenant-ID": tenant_id}
    
    # Send request
    response = requests.post(f"{BASE_URL}/token", data=payload, headers=headers)
    
    # Print results
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        token_data = response.json()
        print(f"Authentication Successful: {token_data['token_type']} token received")
        return token_data
    else:
        print(f"Error: {response.text}")
        return None

def test_tenant_scan(tenant_id, token):
    """Test tenant-specific scan"""
    print("\n=== Testing Tenant-Specific Scan ===")
    
    # Scan payload
    payload = {
        "target": "example.com",
        "scan_type": "network",
        "options": {"port_range": "1-1000"}
    }
    
    # Set headers with token and tenant ID
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "X-Tenant-ID": tenant_id
    }
    
    # Send request
    response = requests.post(f"{BASE_URL}/scan", json=payload, headers=headers)
    
    # Print results
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        scan_data = response.json()
        print(f"Scan Started: {scan_data['id']} for tenant {scan_data['tenant_id']}")
        return scan_data
    else:
        print(f"Error: {response.text}")
        return None

def test_msp_reporting(msp_token):
    """Test MSP cross-tenant reporting"""
    print("\n=== Testing MSP Cross-Tenant Reporting ===")
    
    # Set headers with MSP token
    headers = {
        "Authorization": f"Bearer {msp_token}"
    }
    
    # Send request
    response = requests.get(f"{BASE_URL}/api/msp/tenants", headers=headers)
    
    # Print results
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        tenants_data = response.json()
        print(f"Managed Tenants: {len(tenants_data['tenants'])}")
        return tenants_data
    else:
        print(f"Error: {response.text}")
        return None

def run_tests():
    """Run all multi-tenancy tests"""
    print("Starting Multi-Tenancy Tests...")
    
    # Test tenant creation
    tenant_data = test_tenant_creation()
    if not tenant_data:
        print("Tenant creation failed. Stopping tests.")
        return
    
    # Test tenant authentication
    token_data = test_tenant_authentication(
        tenant_data['tenant_id'], 
        f"admin@{tenant_data['name'].lower().replace(' ', '')}.example.com"
    )
    if not token_data:
        print("Tenant authentication failed. Stopping tests.")
        return
    
    # Test tenant-specific scan
    scan_data = test_tenant_scan(tenant_data['tenant_id'], token_data)
    if not scan_data:
        print("Tenant scan failed.")
    
    print("\nMulti-Tenancy Tests Completed!")

if __name__ == "__main__":
    run_tests()