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


class BlockedIP(models.Model):
    """
    Model to store IP addresses that should be blocked from accessing the application.

    Fields:
    - ip_address: The IP address to block
    - reason: Optional reason for blocking
    - created_at: When the IP was blocked
    - is_active: Whether the block is currently active
    """

    ip_address = models.GenericIPAddressField(
        unique=True, help_text="IP address to block (IPv4 or IPv6)"
    )
    reason = models.CharField(
        max_length=255, blank=True, help_text="Reason for blocking this IP address"
    )
    created_at = models.DateTimeField(
        default=timezone.now, help_text="When this IP was added to the blacklist"
    )
    is_active = models.BooleanField(
        default=True, help_text="Whether this block is currently active"
    )

    class Meta:
        db_table = "ip_tracking_blocked_ip"
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.ip_address} ({status})"

    @classmethod
    def is_blocked(cls, ip_address):
        """
        Check if an IP address is currently blocked.

        Args:
            ip_address (str): IP address to check

        Returns:
            bool: True if IP is blocked, False otherwise
        """
        return cls.objects.filter(ip_address=ip_address, is_active=True).exists()

    def activate(self):
        """Activate this IP block."""
        self.is_active = True
        self.save(update_fields=["is_active"])

    def deactivate(self):
        """Deactivate this IP block."""
        self.is_active = False
        self.save(update_fields=["is_active"])
