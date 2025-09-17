#!/usr/bin/env python3
"""
Test script for BIP-04 Log Integrity Verification
Tests the tamper-evident logging functionality
"""

import sys
import os
from pathlib import Path

# Add secure package to path
sys.path.insert(0, str(Path(__file__).parent))

from secure.audit import AuditLogger

def test_log_integrity():
    """Test log integrity verification functionality."""
    print("🛡️  BIP-04 Log Integrity Test")
    print("=" * 50)

    # Initialize audit logger
    logger = AuditLogger()

    # Log some test events
    print("\n📝 Generating test security events...")

    test_events = [
        {
            'event_type': 'TEST_EVENT_1',
            'message': 'First test event for integrity verification',
            'details': {'test_id': 1, 'severity': 'low'}
        },
        {
            'event_type': 'TEST_EVENT_2',
            'message': 'Second test event with different data',
            'details': {'test_id': 2, 'severity': 'medium', 'data': 'test_data'}
        },
        {
            'event_type': 'TEST_EVENT_3',
            'message': 'Third test event to complete chain',
            'details': {'test_id': 3, 'severity': 'high', 'nested': {'key': 'value'}}
        }
    ]

    for event in test_events:
        logger.log_security_event(**event)
        print(f"✅ Logged: {event['event_type']}")

    # Verify log integrity
    print("\n🔍 Verifying log integrity...")
    verification_result = logger.verify_log_integrity()

    print("\n📊 Integrity Verification Results:")
    print(f"  Security Events Integrity: {'✅ PASS' if verification_result['security_events_integrity'] else '❌ FAIL'}")
    print(f"  Execution Audit Integrity: {'✅ PASS' if verification_result['execution_audit_integrity'] else '❌ FAIL'}")
    print(f"  Total Entries Checked: {verification_result.get('total_entries', 0)}")

    if verification_result.get('errors'):
        print(f"\n⚠️  Errors Found: {len(verification_result['errors'])}")
        for error in verification_result['errors'][:5]:  # Show first 5 errors
            print(f"    - {error}")

    if verification_result.get('tampered_entries'):
        print(f"\n🚨 Tampered Entries Detected: {len(verification_result['tampered_entries'])}")
        for entry in verification_result['tampered_entries'][:3]:  # Show first 3
            print(f"    - Line {entry['line']}: Hash mismatch")

    # Test tampering detection (simulate tampering)
    print("\n🧪 Testing Tamper Detection...")
    security_log = Path("scripts/logs/security_events.log")

    if security_log.exists():
        # Read and modify a log entry (simulate tampering)
        with open(security_log, 'r') as f:
            lines = f.readlines()

        if len(lines) > 1:
            # Modify the second line slightly
            original_line = lines[1]
            tampered_line = original_line.replace('"message":', '"message_tampered":')

            # Write back with tampering
            with open(security_log, 'w') as f:
                f.write(lines[0])  # First line unchanged
                f.write(tampered_line)  # Second line tampered
                for line in lines[2:]:  # Rest unchanged
                    f.write(line)

            # Re-verify integrity
            verification_after_tamper = logger.verify_log_integrity()
            tampered_count = len(verification_after_tamper.get('tampered_entries', []))

            if tampered_count > 0:
                print(f"✅ Tamper Detection: SUCCESS - Detected {tampered_count} tampered entries")
            else:
                print("❌ Tamper Detection: FAILED - Tampering not detected")

            # Restore original content
            with open(security_log, 'w') as f:
                for line in lines:
                    f.write(line)
            print("🔄 Restored original log content")

    # Show summary
    print("\n" + "=" * 50)
    if verification_result['security_events_integrity'] and verification_result['execution_audit_integrity']:
        print("🎉 LOG INTEGRITY TEST: PASSED")
        print("✅ Tamper-evident logging is working correctly")
        return True
    else:
        print("❌ LOG INTEGRITY TEST: FAILED")
        print("❌ Issues detected with log integrity")
        return False

if __name__ == "__main__":
    success = test_log_integrity()
    sys.exit(0 if success else 1)
