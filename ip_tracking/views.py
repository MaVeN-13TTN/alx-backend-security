from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from .models import RequestLog


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

    # Prepare response data
    response_data = {
        "message": "IP Logging Test",
        "detected_ip": client_ip,
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

    # Get top 10 most active IPs
    top_ips = (
        RequestLog.objects.values("ip_address")
        .annotate(request_count=models.Count("id"))
        .order_by("-request_count")[:10]
    )

    stats = {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "top_ips": list(top_ips),
    }

    return JsonResponse(stats)
