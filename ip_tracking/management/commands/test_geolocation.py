from django.core.management.base import BaseCommand
from ip_tracking.middleware import IPLoggingMiddleware
from ip_tracking.models import RequestLog
from django.utils import timezone


class Command(BaseCommand):
    help = "Test IP geolocation functionality"

    def add_arguments(self, parser):
        parser.add_argument(
            "ip_address",
            type=str,
            nargs="?",
            default="8.8.8.8",
            help="IP address to test geolocation for (default: 8.8.8.8)",
        )

    def handle(self, *args, **options):
        ip_address = options["ip_address"]

        self.stdout.write(f"Testing geolocation for IP: {ip_address}")

        # Create middleware instance to test geolocation
        from django.http import HttpResponse

        def dummy_get_response(request):
            return HttpResponse("Test")

        middleware = IPLoggingMiddleware(dummy_get_response)

        # Test geolocation lookup
        self.stdout.write("Fetching geolocation data...")
        geo_data = middleware.get_geolocation(ip_address)

        self.stdout.write(f'Country: {geo_data.get("country", "Unknown")}')
        self.stdout.write(f'City: {geo_data.get("city", "Unknown")}')

        # Test caching
        self.stdout.write("\nTesting cache (second lookup should be faster)...")
        import time

        start_time = time.time()
        cached_geo_data = middleware.get_geolocation(ip_address)
        end_time = time.time()

        self.stdout.write(f"Cached lookup took: {end_time - start_time:.4f} seconds")
        self.stdout.write(
            f'Cached country: {cached_geo_data.get("country", "Unknown")}'
        )
        self.stdout.write(f'Cached city: {cached_geo_data.get("city", "Unknown")}')

        # Create a test log entry
        if geo_data.get("country") or geo_data.get("city"):
            test_log = RequestLog.objects.create(
                ip_address=ip_address,
                path="/test-geolocation/",
                timestamp=timezone.now(),
                country=geo_data.get("country"),
                city=geo_data.get("city"),
            )
            self.stdout.write(f"\nCreated test log entry: {test_log}")
        else:
            self.stdout.write("\nNo geolocation data received - no test log created")

        # Show recent logs with geolocation
        self.stdout.write("\nRecent logs with geolocation data:")
        recent_logs = (
            RequestLog.objects.filter(country__isnull=False)
            .exclude(country="")
            .order_by("-timestamp")[:5]
        )

        for log in recent_logs:
            location = f"{log.city}, {log.country}" if log.city else log.country
            self.stdout.write(f"  {log.ip_address} ({location}) - {log.path}")

        if not recent_logs.exists():
            self.stdout.write("  No logs with geolocation data found")

        self.stdout.write(
            self.style.SUCCESS(f"Geolocation test completed for {ip_address}")
        )
