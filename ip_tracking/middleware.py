import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from .models import RequestLog


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP addresses, timestamps, and paths of incoming requests.

    This middleware captures:
    - Client IP address (handling proxies and load balancers)
    - Request timestamp
    - Requested URL path

    The data is stored in the RequestLog model for security analysis and auditing.
    """

    def process_request(self, request):
        """
        Process incoming request and log IP information.

        Args:
            request: Django HttpRequest object

        Returns:
            None (continues processing)
        """
        try:
            # Get client IP address, handling proxies and load balancers
            ip_address = self.get_client_ip(request)

            # Get the requested path
            path = request.get_full_path()

            # Create log entry
            RequestLog.objects.create(
                ip_address=ip_address, timestamp=timezone.now(), path=path
            )

            # Add IP to request for use in views if needed
            request.client_ip = ip_address

        except Exception as e:
            # Log error but don't break the request flow
            logger.error(f"Error in IPLoggingMiddleware: {e}")

        return None

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
