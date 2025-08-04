from django.contrib import admin
from .models import RequestLog, BlockedIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """
    Admin interface for RequestLog model.
    """

    list_display = ("ip_address", "path", "timestamp")
    list_filter = ("timestamp", "ip_address")
    search_fields = ("ip_address", "path")
    readonly_fields = ("ip_address", "timestamp", "path")
    ordering = ["-timestamp"]
    list_per_page = 50

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
