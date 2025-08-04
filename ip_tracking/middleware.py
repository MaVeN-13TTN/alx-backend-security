import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings
from .models import RequestLog, BlockedIP

# Import geolocation functionality
# Note: Using direct API calls instead of django-ip-geolocation for better compatibility

import json
import requests


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP addresses, timestamps, paths, and geolocation of incoming requests.
    Also blocks requests from blacklisted IP addresses.

    This middleware:
    1. Checks if the client IP is blocked and returns 403 if so
    2. Gets geolocation data for the IP address (with 24-hour caching)
    3. Logs all requests for security analysis and auditing
    4. Captures client IP address (handling proxies and load balancers)
    5. Stores request timestamp, URL path, country, and city

    The data is stored in the RequestLog model for security analysis and auditing.
    Blocked IPs are managed through the BlockedIP model.
    """

    def process_request(self, request):
        """
        Process incoming request, check for blocked IPs, get geolocation, and log IP information.

        Args:
            request: Django HttpRequest object

        Returns:
            HttpResponseForbidden if IP is blocked, None otherwise
        """
        try:
            # Get client IP address, handling proxies and load balancers
            ip_address = self.get_client_ip(request)

            # Add IP to request for use in views if needed
            request.client_ip = ip_address

            # Check if IP is blocked BEFORE logging (to avoid logging blocked attempts)
            if BlockedIP.is_blocked(ip_address):
                logger.warning(
                    f"Blocked request from {ip_address} to {request.get_full_path()}"
                )
                return self.create_forbidden_response(request, ip_address)

            # Get geolocation data for the IP
            geo_data = self.get_geolocation(ip_address)

            # Get the requested path
            path = request.get_full_path()

            # Create log entry only if IP is not blocked
            RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timezone.now(),
                path=path,
                country=geo_data.get("country"),
                city=geo_data.get("city"),
            )

        except Exception as e:
            # Log error but don't break the request flow
            logger.error(f"Error in IPLoggingMiddleware: {e}")

        return None

    def get_geolocation(self, ip_address):
        """
        Get geolocation data for an IP address with 24-hour caching.

        Args:
            ip_address (str): IP address to get geolocation for

        Returns:
            dict: Dictionary with 'country' and 'city' keys
        """
        # Skip geolocation for private/local IPs
        if self.is_private_ip(ip_address):
            return {"country": None, "city": None}

        # Create cache key
        cache_key = f"geolocation_{ip_address}"

        # Try to get from cache first
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        # Get fresh geolocation data
        geo_data = self.fetch_geolocation(ip_address)

        # Cache for 24 hours (86400 seconds)
        cache.set(cache_key, geo_data, 86400)

        return geo_data

    def fetch_geolocation(self, ip_address):
        """
        Fetch geolocation data from external API.

        Args:
            ip_address (str): IP address to lookup

        Returns:
            dict: Dictionary with 'country' and 'city' keys
        """
        try:
            # Use ip-api.com (free service) for geolocation
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {"country": data.get("country"), "city": data.get("city")}

        except Exception as e:
            logger.warning(f"Failed to get geolocation for {ip_address}: {e}")

        # Return empty data if geolocation fails
        return {"country": None, "city": None}

    def is_private_ip(self, ip_address):
        """
        Check if an IP address is private/local.

        Args:
            ip_address (str): IP address to check

        Returns:
            bool: True if IP is private, False otherwise
        """
        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return True  # If invalid IP, treat as private

    def create_forbidden_response(self, request, ip_address):
        """
        Create a 403 Forbidden response for blocked IPs.

        Args:
            request: Django HttpRequest object
            ip_address: The blocked IP address

        Returns:
            HttpResponseForbidden: 403 response
        """
        # Try to get the blocking reason
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address, is_active=True)
            reason = blocked_ip.reason or "IP address is blacklisted"
        except BlockedIP.DoesNotExist:
            reason = "IP address is blacklisted"

        # Create a simple HTML response for blocked IPs
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Forbidden</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 50px; text-align: center; }}
                .error {{ color: #d32f2f; }}
                .code {{ font-family: monospace; background: #f5f5f5; padding: 2px 6px; }}
            </style>
        </head>
        <body>
            <h1 class="error">403 - Access Forbidden</h1>
            <p>Your IP address <span class="code">{ip_address}</span> has been blocked.</p>
            <p><strong>Reason:</strong> {reason}</p>
            <p>If you believe this is an error, please contact the administrator.</p>
        </body>
        </html>
        """

        return HttpResponseForbidden(html_content, content_type="text/html")

    def get_client_ip(self, request):
        """
        Extract the client's real IP address from request headers.

        This method checks various headers commonly used by proxies,
        load balancers, and CDNs to determine the original client IP.

        Args:
            request: Django HttpRequest object

        Returns:
            str: Client IP address
        """
        # Headers to check for real IP (in order of preference)
        ip_headers = [
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_REAL_IP",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "REMOTE_ADDR",
        ]

        for header in ip_headers:
            ip = request.META.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
                # The first one is usually the original client IP
                if "," in ip:
                    ip = ip.split(",")[0].strip()

                # Basic validation - ensure it's not empty and not a private placeholder
                if ip and ip != "unknown":
                    return ip

        # Fallback to REMOTE_ADDR if nothing else found
        return request.META.get("REMOTE_ADDR", "127.0.0.1")

    def process_response(self, request, response):
        """
        Optional: Process response to add additional logging if needed.

        Args:
            request: Django HttpRequest object
            response: Django HttpResponse object

        Returns:
            HttpResponse: The response object
        """
        # Could add response status code logging here if needed in future
        return response
