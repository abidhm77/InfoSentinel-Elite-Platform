#!/usr/bin/env python3
"""
Test script for cryptographic audit trail functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from compliance.grc.grc_engine import GRCManager, SecurityException

def test_audit_trail_integrity():
    """Test cryptographic audit trail with HMAC and digital signatures"""
    print("Testing Cryptographic Audit Trail Implementation...")
    
    # Initialize GRC manager
    grc = GRCManager()
    
    # Add some sample controls
    grc.add_control('AC-1', 'NIST_800_53', 'Access control policy')
    grc.add_control('A.5.1', 'ISO_27001', 'Information security policy')
    
    # Log audit events
    print("\n1. Logging audit events...")
    grc.log_audit_event('CONTROL_ADDED', 'Added AC-1 access control policy')
    grc.log_audit_event('CONTROL_ADDED', 'Added A.5.1 information security policy')
    grc.log_audit_event('COMPLIANCE_CHECK', 'Initial compliance assessment completed')
    
    print(f"   Total audit events: {len(grc.audit_trail)}")
    
    # Display audit trail structure
    print("\n2. Audit trail structure:")
    for i, event in enumerate(grc.audit_trail):
        print(f"   Event {i+1}:")
        print(f"     Timestamp: {event['timestamp']}")
        print(f"     Type: {event['event_type']}")
        print(f"     Details: {event['details']}")
        print(f"     Hash: {event['event_hash'][:16]}...")
        print(f"     HMAC: {event['hmac'][:16]}...")
        print(f"     Signature: {event['signature'][:16]}...")
        print(f"     Prev Hash: {event['prev_hash'][:16]}...")
    
    # Test integrity verification
    print("\n3. Testing integrity verification...")
    try:
        grc.verify_audit_integrity()
        print("   ✓ Audit trail integrity verified successfully")
    except SecurityException as e:
        print(f"   ✗ Integrity check failed: {e}")
        return False
    
    # Test tampering detection
    print("\n4. Testing tampering detection...")
    
    # Attempt to tamper with an event
    original_details = grc.audit_trail[1]['details']
    grc.audit_trail[1]['details'] = "TAMPERED: Malicious modification"
    
    try:
        grc.verify_audit_integrity()
        print("   ✗ Tampering not detected - security failure!")
        return False
    except SecurityException as e:
        print(f"   ✓ Tampering correctly detected: {e}")
    
    # Restore original data
    grc.audit_trail[1]['details'] = original_details
    
    # Test HMAC validation
    print("\n5. Testing HMAC validation...")
    original_hmac = grc.audit_trail[2]['hmac']
    grc.audit_trail[2]['hmac'] = "0" * 64  # Invalid HMAC
    
    try:
        grc.verify_audit_integrity()
        print("   ✗ HMAC validation failed to detect tampering!")
        return False
    except SecurityException as e:
        print(f"   ✓ HMAC validation correctly detected tampering: {e}")
    
    # Restore original HMAC
    grc.audit_trail[2]['hmac'] = original_hmac
    
    print("\n✓ All cryptographic audit trail tests passed!")
    return True

def test_performance():
    """Test performance with large audit trail"""
    print("\nTesting performance with 1000 audit events...")
    
    grc = GRCManager()
    
    # Generate large audit trail
    for i in range(1000):
        grc.log_audit_event(f'EVENT_{i}', f'Test event number {i}')
    
    print(f"   Generated {len(grc.audit_trail)} audit events")
    
    # Verify integrity
    try:
        grc.verify_audit_integrity()
        print("   ✓ Large audit trail integrity verified")
    except SecurityException as e:
        print(f"   ✗ Large audit trail failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("CRYPTOGRAPHIC AUDIT TRAIL TEST SUITE")
    print("=" * 60)
    
    success = True
    success &= test_audit_trail_integrity()
    success &= test_performance()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 ALL TESTS PASSED - Cryptographic audit trail is secure!")
    else:
        print("❌ SOME TESTS FAILED - Review implementation")
    print("=" * 60)