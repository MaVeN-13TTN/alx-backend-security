import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.template.loader import render_to_string
from .models import RequestLog, BlockedIP


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP addresses, timestamps, and paths of incoming requests.
    Also blocks requests from blacklisted IP addresses.

    This middleware:
    1. Checks if the client IP is blocked and returns 403 if so
    2. Logs all requests for security analysis and auditing
    3. Captures client IP address (handling proxies and load balancers)
    4. Stores request timestamp and URL path

    The data is stored in the RequestLog model for security analysis and auditing.
    Blocked IPs are managed through the BlockedIP model.
    """

    def process_request(self, request):
        """
        Process incoming request, check for blocked IPs, and log IP information.

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

            # Get the requested path
            path = request.get_full_path()

            # Create log entry only if IP is not blocked
            RequestLog.objects.create(
                ip_address=ip_address, timestamp=timezone.now(), path=path
            )

        except Exception as e:
            # Log error but don't break the request flow
            logger.error(f"Error in IPLoggingMiddleware: {e}")

        return None

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
