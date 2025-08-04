from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """
    Admin interface for RequestLog model.
    """

    list_display = ("ip_address", "country", "city", "path", "timestamp")
    list_filter = ("timestamp", "country", "city")
    search_fields = ("ip_address", "path", "country", "city")
    readonly_fields = ("ip_address", "timestamp", "path", "country", "city")
    ordering = ["-timestamp"]
    list_per_page = 50

    fieldsets = (
        ("Request Information", {"fields": ("ip_address", "path", "timestamp")}),
        ("Geolocation", {"fields": ("country", "city"), "classes": ("collapse",)}),
    )

    def has_add_permission(self, request):
        """Disable manual addition of logs through admin."""
        return False

    def has_change_permission(self, request, obj=None):
        """Make logs read-only in admin."""
        return False


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    """
    Admin interface for BlockedIP model.
    """

    list_display = ("ip_address", "is_active", "reason", "created_at")
    list_filter = ("is_active", "created_at")
    search_fields = ("ip_address", "reason")
    readonly_fields = ("created_at",)
    ordering = ["-created_at"]
    list_per_page = 50

    fieldsets = (
        (None, {"fields": ("ip_address", "is_active")}),
        ("Details", {"fields": ("reason", "created_at"), "classes": ("collapse",)}),
    )

    actions = ["activate_blocks", "deactivate_blocks"]


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    """Admin interface for managing suspicious IP addresses detected by anomaly detection."""
    
    list_display = ["ip_address", "reason", "request_count", "detected_at", "is_resolved"]
    list_filter = ["is_resolved", "detected_at", "reason"]
    search_fields = ["ip_address", "reason"]
    readonly_fields = ["detected_at"]
    
    fieldsets = (
        ("IP Information", {
            "fields": ("ip_address", "reason", "request_count")
        }),
        ("Detection Details", {
            "fields": ("detected_at", "flagged_paths")
        }),
        ("Status", {
            "fields": ("is_resolved",)
        }),
    )
    
    @admin.action(description="Mark selected IPs as resolved")
    def mark_resolved(self, request, queryset):
        """Mark selected suspicious IPs as resolved."""
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f"{updated} suspicious IPs marked as resolved.")
    
    @admin.action(description="Block selected suspicious IPs")
    def block_suspicious_ips(self, request, queryset):
        """Block selected suspicious IPs."""
        blocked_count = 0
        for suspicious_ip in queryset:
            # Create or update blocked IP
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f"Blocked due to suspicious activity: {suspicious_ip.reason}",
                    'is_active': True
                }
            )
            if not created and not blocked_ip.is_active:
                blocked_ip.activate()
            
            # Mark as resolved
            suspicious_ip.mark_resolved()
            blocked_count += 1
            
        self.message_user(request, f"{blocked_count} suspicious IPs have been blocked.")
    
    actions = ["mark_resolved", "block_suspicious_ips"]

    @admin.action(description="Activate selected IP blocks")
    def activate_blocks(self, request, queryset):
        """Activate selected IP blocks."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Successfully activated {updated} IP block(s).")

    @admin.action(description="Deactivate selected IP blocks")
    def deactivate_blocks(self, request, queryset):
        """Deactivate selected IP blocks."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Successfully deactivated {updated} IP block(s).")
