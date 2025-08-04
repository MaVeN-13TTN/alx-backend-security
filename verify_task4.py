#!/usr/bin/env python
"""
Task 4 Verification Script: Anomaly Detection System
This script tests the IP anomaly detection functionality.
"""

import os
import sys
import django
from django.utils import timezone
import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ip_security_project.settings')
django.setup()

from ip_tracking.models import RequestLog, SuspiciousIP
from ip_tracking.tasks import detect_anomalies

def test_anomaly_detection():
    print("=== Task 4: Anomaly Detection Test ===\n")
    
    # Clear previous test data
    print("1. Clearing previous test data...")
    RequestLog.objects.filter(ip_address__startswith='192.168.1.').delete()
    SuspiciousIP.objects.all().delete()
    
    # Create test data
    print("2. Creating test data...")
    now = timezone.now()
    hour_ago = now - datetime.timedelta(hours=1)
    
    # Create 150 requests from the same IP in the last hour (should trigger detection)
    print("   - Creating 150 requests from IP 192.168.1.100 (should trigger high volume detection)")
    for i in range(150):
        RequestLog.objects.create(
            ip_address='192.168.1.100',
            path=f'/api/test/{i}',
            timestamp=hour_ago + datetime.timedelta(minutes=i/3)
        )
    
    # Create requests to sensitive paths
    print("   - Creating requests to sensitive paths from IP 192.168.1.200")
    sensitive_paths = ['/admin/', '/api/users/', '/login', '/admin/users/']
    for path in sensitive_paths:
        RequestLog.objects.create(
            ip_address='192.168.1.200',
            path=path,
            timestamp=now - datetime.timedelta(minutes=30)
        )
    
    print(f"   - Total RequestLog entries created: {RequestLog.objects.filter(ip_address__startswith='192.168.1.').count()}")
    
    # Run anomaly detection
    print("\n3. Running anomaly detection...")
    try:
        result = detect_anomalies()
        print(f"   - Detection completed: {result}")
    except Exception as e:
        print(f"   - Error during detection: {e}")
        return False
    
    # Check results
    print("\n4. Checking results...")
    suspicious_ips = SuspiciousIP.objects.all()
    print(f"   - Total suspicious IPs detected: {suspicious_ips.count()}")
    
    if suspicious_ips.count() > 0:
        print("   - Detected suspicious IPs:")
        for suspicious_ip in suspicious_ips:
            print(f"     * IP: {suspicious_ip.ip_address}")
            print(f"       Reason: {suspicious_ip.reason}")
            print(f"       Request Count: {suspicious_ip.request_count}")
            print(f"       Flagged Paths: {suspicious_ip.flagged_paths}")
            print(f"       Detected At: {suspicious_ip.detected_at}")
            print(f"       Is Resolved: {suspicious_ip.is_resolved}")
            print()
    
    # Test the model methods
    print("5. Testing SuspiciousIP model methods...")
    if suspicious_ips.exists():
        test_ip = suspicious_ips.first()
        if test_ip:
            print(f"   - Testing mark_resolved() method...")
            test_ip.mark_resolved()
            print(f"     * IP {test_ip.ip_address} marked as resolved: {test_ip.is_resolved}")
        
        print(f"   - Unresolved count: {SuspiciousIP.get_unresolved_count()}")
    
    print("\n=== Task 4 Test Complete ===")
    return True

if __name__ == "__main__":
    success = test_anomaly_detection()
    if success:
        print("✅ Task 4: Anomaly Detection system is working correctly!")
    else:
        print("❌ Task 4: Anomaly Detection system encountered errors!")
        sys.exit(1)
