from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Block or unblock IP addresses from accessing the application"

    def add_arguments(self, parser):
        parser.add_argument(
            "ip_address", type=str, nargs="?", help="IP address to block or unblock"
        )
        parser.add_argument(
            "--reason", type=str, default="", help="Reason for blocking the IP address"
        )
        parser.add_argument(
            "--unblock",
            action="store_true",
            help="Unblock the IP address instead of blocking it",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force the operation without confirmation",
        )
        parser.add_argument(
            "--list", action="store_true", help="List all blocked IP addresses"
        )

    def handle(self, *args, **options):
        # Handle list operation
        if options["list"]:
            self.list_blocked_ips()
            return

        ip_address = options["ip_address"]

        if not ip_address:
            raise CommandError("IP address is required unless using --list")

        reason = options["reason"]
        unblock = options["unblock"]
        force = options["force"]

        # Validate IP address
        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            raise CommandError(f"'{ip_address}' is not a valid IP address")

        if unblock:
            self.unblock_ip(ip_address, force)
        else:
            self.block_ip(ip_address, reason, force)

    def block_ip(self, ip_address, reason, force):
        """Block an IP address."""
        try:
            # Check if IP is already blocked
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            if blocked_ip.is_active:
                self.stdout.write(
                    self.style.WARNING(f"IP {ip_address} is already blocked")
                )
                return
            else:
                # Reactivate existing blocked IP
                blocked_ip.is_active = True
                blocked_ip.reason = reason or blocked_ip.reason
                blocked_ip.save(update_fields=["is_active", "reason"])
                self.stdout.write(
                    self.style.SUCCESS(f"Reactivated block for IP {ip_address}")
                )
                return
        except BlockedIP.DoesNotExist:
            pass

        # Confirm blocking unless force is used
        if not force:
            confirm = input(f"Are you sure you want to block IP {ip_address}? [y/N]: ")
            if confirm.lower() not in ["y", "yes"]:
                self.stdout.write(self.style.WARNING("Operation cancelled"))
                return

        # Create new blocked IP entry
        try:
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address, reason=reason, is_active=True
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully blocked IP {ip_address}"
                    + (f" (Reason: {reason})" if reason else "")
                )
            )
        except Exception as e:
            raise CommandError(f"Failed to block IP {ip_address}: {e}")

    def unblock_ip(self, ip_address, force):
        """Unblock an IP address."""
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            if not blocked_ip.is_active:
                self.stdout.write(
                    self.style.WARNING(f"IP {ip_address} is not currently blocked")
                )
                return
        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f"IP {ip_address} is not in the blocked list")
            )
            return

        # Confirm unblocking unless force is used
        if not force:
            confirm = input(
                f"Are you sure you want to unblock IP {ip_address}? [y/N]: "
            )
            if confirm.lower() not in ["y", "yes"]:
                self.stdout.write(self.style.WARNING("Operation cancelled"))
                return

        # Deactivate the blocked IP
        try:
            blocked_ip.is_active = False
            blocked_ip.save(update_fields=["is_active"])
            self.stdout.write(
                self.style.SUCCESS(f"Successfully unblocked IP {ip_address}")
            )
        except Exception as e:
            raise CommandError(f"Failed to unblock IP {ip_address}: {e}")

    def list_blocked_ips(self):
        """List all blocked IP addresses."""
        blocked_ips = BlockedIP.objects.filter(is_active=True).order_by("-created_at")

        if not blocked_ips.exists():
            self.stdout.write(
                self.style.WARNING("No IP addresses are currently blocked")
            )
            return

        self.stdout.write(
            self.style.SUCCESS(
                f"Currently blocked IP addresses ({blocked_ips.count()}):"
            )
        )
        self.stdout.write("-" * 80)

        for blocked_ip in blocked_ips:
            reason_text = f" - {blocked_ip.reason}" if blocked_ip.reason else ""
            self.stdout.write(
                f"{blocked_ip.ip_address:<15} "
                f"(Blocked: {blocked_ip.created_at.strftime('%Y-%m-%d %H:%M:%S')})"
                f"{reason_text}"
            )

        # Also show inactive blocks
        inactive_blocks = BlockedIP.objects.filter(is_active=False).count()
        if inactive_blocks > 0:
            self.stdout.write(f"\nNote: {inactive_blocks} inactive blocks in database")

        self.stdout.write("\nUsage examples:")
        self.stdout.write(
            "  python manage.py block_ip 192.168.1.100 --reason 'Suspicious activity'"
        )
        self.stdout.write("  python manage.py block_ip 192.168.1.100 --unblock")
        self.stdout.write("  python manage.py block_ip --list")
