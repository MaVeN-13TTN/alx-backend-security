from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to store IP address logging information for each request.

    Fields:
    - ip_address: The client's IP address
    - timestamp: When the request was made
    - path: The requested URL path
    """

    ip_address = models.GenericIPAddressField(
        help_text="Client IP address (IPv4 or IPv6)"
    )
    timestamp = models.DateTimeField(
        default=timezone.now, help_text="Timestamp when the request was made"
    )
    path = models.CharField(max_length=500, help_text="The requested URL path")

    class Meta:
        db_table = "ip_tracking_request_log"
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ["-timestamp"]  # Most recent first
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["timestamp"]),
            models.Index(fields=["path"]),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"
