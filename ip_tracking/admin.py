from django.contrib import admin
from .models import RequestLog


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
