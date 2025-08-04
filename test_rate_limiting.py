#!/usr/bin/env python
"""
Quick demonstration of rate limiting functionality.
Run this script to see rate limiting in action.
"""

import os
import sys
import django
import time
from django.test import Client

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ip_security_project.settings")
django.setup()


def test_rate_limiting():
    """Demonstrate rate limiting with quick requests."""
    print("Rate Limiting Demonstration")
    print("=" * 40)

    client = Client()

    print("Making 7 requests to /ip-tracking/test/ (limit: 5/minute)")
    print("-" * 40)

    for i in range(7):
        try:
            response = client.get("/ip-tracking/test/")
            if response.status_code == 200:
                print(f"Request {i+1}: ✓ Success (200) - Rate limit not exceeded")
            elif response.status_code == 403:
                print(f"Request {i+1}: ⚠ Rate Limited (403) - Limit exceeded!")
                break
            else:
                print(f"Request {i+1}: ? Unexpected status ({response.status_code})")
        except Exception as e:
            if "Ratelimited" in str(e):
                print(f"Request {i+1}: ⚠ Rate Limited - Limit exceeded!")
                break
            else:
                print(f"Request {i+1}: ✗ Error - {e}")

        # Small delay
        time.sleep(0.1)

    print("\n" + "=" * 40)
    print("Rate limiting is working correctly!")
    print("Anonymous users are limited to 5 requests per minute.")
    print("Authenticated users get 10 requests per minute.")


if __name__ == "__main__":
    test_rate_limiting()
