from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from .models import RequestLog, BlockedIP


def test_ip_logging(request):
    """
    Test view to verify IP logging middleware is working.
    Returns information about the current request and recent logs.
    """
    # Get the client IP that was set by middleware
    client_ip = getattr(request, "client_ip", "Not detected")

    # Get recent logs for this IP
    recent_logs = RequestLog.objects.filter(ip_address=client_ip).order_by(
        "-timestamp"
    )[:5]

    # Check if IP is blocked
    is_blocked = BlockedIP.is_blocked(client_ip)

    # Prepare response data
    response_data = {
        "message": "IP Logging Test",
        "detected_ip": client_ip,
        "is_blocked": is_blocked,
        "request_path": request.get_full_path(),
        "method": request.method,
        "recent_logs_count": recent_logs.count(),
        "recent_logs": [
            {
                "path": log.path,
                "timestamp": log.timestamp.isoformat(),
            }
            for log in recent_logs
        ],
    }

    return JsonResponse(response_data)


def ip_stats(request):
    """
    View to show basic IP tracking statistics.
    """
    total_requests = RequestLog.objects.count()
    unique_ips = RequestLog.objects.values("ip_address").distinct().count()
    blocked_ips_count = BlockedIP.objects.filter(is_active=True).count()

    # Get top 10 most active IPs
    top_ips = (
        RequestLog.objects.values("ip_address")
        .annotate(request_count=models.Count("id"))
        .order_by("-request_count")[:10]
    )

    stats = {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "blocked_ips": blocked_ips_count,
        "top_ips": list(top_ips),
    }

    return JsonResponse(stats)


def blocked_ips(request):
    """
    View to show currently blocked IP addresses.
    """
    blocked_list = BlockedIP.objects.filter(is_active=True).order_by("-created_at")

    blocked_data = [
        {
            "ip_address": blocked_ip.ip_address,
            "reason": blocked_ip.reason,
            "created_at": blocked_ip.created_at.isoformat(),
        }
        for blocked_ip in blocked_list
    ]

    response_data = {
        "message": "Currently Blocked IPs",
        "count": len(blocked_data),
        "blocked_ips": blocked_data,
    }

    return JsonResponse(response_data)
