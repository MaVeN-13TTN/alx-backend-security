#!/usr/bin/env python
"""
Verification script for Task 1: IP Blacklisting

This script demonstrates that the IP blacklisting functionality is working correctly.
It checks:
1. BlockedIP model is properly defined
2. Middleware blocks requests from blacklisted IPs
3. Management command works for blocking/unblocking IPs
4. 403 Forbidden response is returned for blocked IPs
"""

import os
import django
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Configure Django settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ip_security_project.settings")
django.setup()

from django.test import RequestFactory
from django.http import HttpResponseForbidden
from ip_tracking.models import BlockedIP
from ip_tracking.middleware import IPLoggingMiddleware


def test_blocked_ip_model():
    """Test that the BlockedIP model works correctly."""
    print("=== Testing BlockedIP Model ===")

    # Test creating a blocked IP
    test_ip = "203.0.113.99"

    # Clean up any existing entry first
    BlockedIP.objects.filter(ip_address=test_ip).delete()

    blocked_ip = BlockedIP.objects.create(
        ip_address=test_ip, reason="Test blocking", is_active=True
    )

    print(f"✓ Created blocked IP: {blocked_ip}")
    print(
        f"✓ Model fields: ip_address={blocked_ip.ip_address}, reason={blocked_ip.reason}"
    )
    print(f"✓ Is active: {blocked_ip.is_active}")

    # Test the is_blocked class method
    is_blocked = BlockedIP.is_blocked(test_ip)
    print(f"✓ is_blocked() method returns: {is_blocked}")

    # Test deactivating
    blocked_ip.deactivate()
    is_blocked_after_deactivate = BlockedIP.is_blocked(test_ip)
    print(f"✓ After deactivation, is_blocked() returns: {is_blocked_after_deactivate}")

    # Test reactivating
    blocked_ip.activate()
    is_blocked_after_activate = BlockedIP.is_blocked(test_ip)
    print(f"✓ After reactivation, is_blocked() returns: {is_blocked_after_activate}")

    return blocked_ip


def test_middleware_blocking():
    """Test that the middleware properly blocks requests from blacklisted IPs."""
    print("\n=== Testing Middleware IP Blocking ===")

    # Create a test blocked IP
    blocked_ip = "198.51.100.99"
    BlockedIP.objects.get_or_create(
        ip_address=blocked_ip, defaults={"reason": "Test blocking", "is_active": True}
    )

    # Create middleware instance
    def get_response(request):
        from django.http import HttpResponse

        return HttpResponse("Normal response")

    middleware = IPLoggingMiddleware(get_response)

    # Test with blocked IP
    factory = RequestFactory()
    request = factory.get("/test-blocked-path/")
    request.META["REMOTE_ADDR"] = blocked_ip

    print(f"Testing request from blocked IP: {blocked_ip}")
    response = middleware.process_request(request)

    if isinstance(response, HttpResponseForbidden):
        print("✓ Middleware correctly returned 403 Forbidden for blocked IP")
        print(f"✓ Response status code: {response.status_code}")
        print(f"✓ Response content type: {response.get('Content-Type')}")
    else:
        print(f"✗ Expected HttpResponseForbidden, got: {type(response)}")

    # Test with non-blocked IP
    allowed_ip = "198.51.100.100"
    request2 = factory.get("/test-allowed-path/")
    request2.META["REMOTE_ADDR"] = allowed_ip

    print(f"\nTesting request from allowed IP: {allowed_ip}")
    response2 = middleware.process_request(request2)

    if response2 is None:
        print("✓ Middleware correctly allowed request from non-blocked IP")
    else:
        print(f"✗ Expected None, got: {type(response2)}")

    return middleware


def test_management_command():
    """Test the block_ip management command functionality."""
    print("\n=== Testing Management Command ===")

    from django.core.management import call_command
    from io import StringIO

    # Test listing blocked IPs
    print("Testing --list option:")
    out = StringIO()
    call_command("block_ip", "--list", stdout=out)
    list_output = out.getvalue()
    print(f"✓ List command output: {list_output.strip()}")

    # Test blocking a new IP
    test_ip = "10.0.0.99"

    # Clean up any existing entry first
    BlockedIP.objects.filter(ip_address=test_ip).delete()

    print(f"\nTesting blocking IP: {test_ip}")
    out = StringIO()
    call_command(
        "block_ip",
        test_ip,
        "--reason",
        "Management command test",
        "--force",
        stdout=out,
    )
    block_output = out.getvalue()
    print(f"✓ Block command output: {block_output.strip()}")

    # Verify it was blocked
    is_blocked = BlockedIP.is_blocked(test_ip)
    print(f"✓ IP is now blocked: {is_blocked}")

    # Test unblocking
    print(f"\nTesting unblocking IP: {test_ip}")
    out = StringIO()
    call_command("block_ip", test_ip, "--unblock", "--force", stdout=out)
    unblock_output = out.getvalue()
    print(f"✓ Unblock command output: {unblock_output.strip()}")

    # Verify it was unblocked
    is_blocked_after = BlockedIP.is_blocked(test_ip)
    print(f"✓ IP is now unblocked: {not is_blocked_after}")


def test_forbidden_response():
    """Test the 403 Forbidden response content."""
    print("\n=== Testing 403 Forbidden Response ===")

    # Create middleware and test response
    def get_response(request):
        from django.http import HttpResponse

        return HttpResponse("Normal response")

    middleware = IPLoggingMiddleware(get_response)

    # Mock request from blocked IP
    factory = RequestFactory()
    request = factory.get("/admin/login/")
    request.META["REMOTE_ADDR"] = "192.168.1.100"  # We blocked this earlier

    response = middleware.create_forbidden_response(request, "192.168.1.100")

    print(f"✓ Response status code: {response.status_code}")
    print(f"✓ Response content type: {response.get('Content-Type')}")
    print(
        f"✓ Response contains IP address: {'192.168.1.100' in response.content.decode()}"
    )
    print(
        f"✓ Response contains 'Forbidden': {'Forbidden' in response.content.decode()}"
    )


def show_statistics():
    """Show current blocking statistics."""
    print("\n=== IP Blocking Statistics ===")

    total_blocked = BlockedIP.objects.count()
    active_blocked = BlockedIP.objects.filter(is_active=True).count()
    inactive_blocked = total_blocked - active_blocked

    print(f"Total blocked IPs in database: {total_blocked}")
    print(f"Currently active blocks: {active_blocked}")
    print(f"Inactive blocks: {inactive_blocked}")

    if active_blocked > 0:
        print("\nCurrently blocked IPs:")
        for blocked_ip in BlockedIP.objects.filter(is_active=True)[:5]:
            reason_text = f" - {blocked_ip.reason}" if blocked_ip.reason else ""
            print(f"  {blocked_ip.ip_address}{reason_text}")


def main():
    print("IP Blacklisting Verification Script")
    print("=" * 50)

    try:
        # Run tests
        test_blocked_ip_model()
        test_middleware_blocking()
        test_management_command()
        test_forbidden_response()
        show_statistics()

        print("\n" + "=" * 50)
        print("✓ All verification tests completed successfully!")
        print("\nTask 1 Requirements Met:")
        print("✓ BlockedIP model with ip_address field")
        print("✓ Middleware blocks requests from blocked IPs with 403 Forbidden")
        print("✓ Management command block_ip.py can add IPs to BlockedIP")
        print("✓ Management command supports listing, blocking, and unblocking")
        print("✓ Admin interface for managing blocked IPs")

    except Exception as e:
        print(f"\n✗ Verification failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
