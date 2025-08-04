from django.core.management.base import BaseCommand
from django.utils import timezone
from ip_tracking.models import RequestLog


class Command(BaseCommand):
    help = "Test the IP tracking functionality by creating sample log entries"

    def handle(self, *args, **options):
        # Create some sample log entries for testing
        sample_logs = [
            {
                "ip_address": "192.168.1.1",
                "path": "/admin/",
                "timestamp": timezone.now(),
            },
            {
                "ip_address": "10.0.0.1",
                "path": "/ip-tracking/test/",
                "timestamp": timezone.now(),
            },
            {
                "ip_address": "127.0.0.1",
                "path": "/ip-tracking/stats/",
                "timestamp": timezone.now(),
            },
            {
                "ip_address": "192.168.1.1",
                "path": "/admin/login/",
                "timestamp": timezone.now(),
            },
        ]

        for log_data in sample_logs:
            RequestLog.objects.create(**log_data)

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully created {len(sample_logs)} test log entries"
            )
        )

        # Display current log count
        total_logs = RequestLog.objects.count()
        unique_ips = RequestLog.objects.values("ip_address").distinct().count()

        self.stdout.write(f"Total log entries: {total_logs}")
        self.stdout.write(f"Unique IP addresses: {unique_ips}")

        # Show recent entries
        self.stdout.write("\nRecent log entries:")
        recent_logs = RequestLog.objects.order_by("-timestamp")[:5]
        for log in recent_logs:
            self.stdout.write(f"  {log.ip_address} - {log.path} at {log.timestamp}")
