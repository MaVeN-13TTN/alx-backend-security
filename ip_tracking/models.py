from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to store IP address logging information for each request.

    Fields:
    - ip_address: The client's IP address
    - timestamp: When the request was made
    - path: The requested URL path
    - country: Country code from IP geolocation
    - city: City name from IP geolocation
    """

    ip_address = models.GenericIPAddressField(
        help_text="Client IP address (IPv4 or IPv6)"
    )
    timestamp = models.DateTimeField(
        default=timezone.now, help_text="Timestamp when the request was made"
    )
    path = models.CharField(max_length=500, help_text="The requested URL path")
    country = models.CharField(
        max_length=100, blank=True, null=True, help_text="Country from IP geolocation"
    )
    city = models.CharField(
        max_length=100, blank=True, null=True, help_text="City from IP geolocation"
    )

    class Meta:
        db_table = "ip_tracking_request_log"
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ["-timestamp"]  # Most recent first
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["timestamp"]),
            models.Index(fields=["path"]),
            models.Index(fields=["country"]),
            models.Index(fields=["city"]),
        ]

    def __str__(self):
        location = ""
        if self.city and self.country:
            location = f" ({self.city}, {self.country})"
        elif self.country:
            location = f" ({self.country})"
        return f"{self.ip_address}{location} - {self.path} at {self.timestamp}"


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


class SuspiciousIP(models.Model):
    """
    Model to store IP addresses flagged as suspicious by anomaly detection.

    Fields:
    - ip_address: The suspicious IP address
    - reason: Reason why this IP was flagged as suspicious
    - detected_at: When the suspicious activity was detected
    - request_count: Number of requests that triggered the detection
    - is_resolved: Whether this suspicious activity has been resolved/reviewed
    - flagged_paths: JSON field storing paths that triggered the detection
    """

    ip_address = models.GenericIPAddressField(
        help_text="Suspicious IP address (IPv4 or IPv6)"
    )
    reason = models.CharField(
        max_length=255, help_text="Reason for flagging this IP as suspicious"
    )
    detected_at = models.DateTimeField(
        default=timezone.now, help_text="When the suspicious activity was detected"
    )
    request_count = models.PositiveIntegerField(
        default=0, help_text="Number of requests that triggered detection"
    )
    is_resolved = models.BooleanField(
        default=False, help_text="Whether this suspicious activity has been reviewed"
    )
    flagged_paths = models.JSONField(
        default=list, blank=True, help_text="List of suspicious paths accessed"
    )

    class Meta:
        db_table = "ip_tracking_suspicious_ip"
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["detected_at"]),
            models.Index(fields=["is_resolved"]),
        ]

    def __str__(self):
        status = "Resolved" if self.is_resolved else "Active"
        return f"{self.ip_address} - {self.reason} ({status})"

    def mark_resolved(self):
        """Mark this suspicious activity as resolved."""
        self.is_resolved = True
        self.save(update_fields=["is_resolved"])

    @classmethod
    def get_unresolved_count(cls):
        """Get count of unresolved suspicious IPs."""
        return cls.objects.filter(is_resolved=False).count()

    @classmethod
    def flag_ip(cls, ip_address, reason, request_count=0, paths=None):
        """
        Flag an IP as suspicious.

        Args:
            ip_address (str): IP address to flag
            reason (str): Reason for flagging
            request_count (int): Number of requests that triggered detection
            paths (list): List of suspicious paths

        Returns:
            SuspiciousIP: Created or updated suspicious IP record
        """
        if paths is None:
            paths = []

        # Check if IP was already flagged recently (within last hour)
        from datetime import timedelta
        recent_threshold = timezone.now() - timedelta(hours=1)
        
        recent_flag = cls.objects.filter(
            ip_address=ip_address,
            reason=reason,
            detected_at__gte=recent_threshold,
            is_resolved=False
        ).first()
        
        if recent_flag:
            # Update existing recent flag
            recent_flag.request_count += request_count
            recent_flag.flagged_paths.extend(paths)
            recent_flag.flagged_paths = list(set(recent_flag.flagged_paths))  # Remove duplicates
            recent_flag.save()
            return recent_flag
        else:
            # Create new suspicious IP record
            return cls.objects.create(
                ip_address=ip_address,
                reason=reason,
                request_count=request_count,
                flagged_paths=paths
            )
