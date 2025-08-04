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
                "country": log.country,
                "city": log.city,
            }
            for log in recent_logs
        ],
    }

    return JsonResponse(response_data)


def ip_stats(request):
    """
    View to show basic IP tracking statistics including geolocation data.
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

    # Get country statistics
    country_stats = (
        RequestLog.objects.filter(country__isnull=False)
        .values("country")
        .annotate(request_count=models.Count("id"))
        .order_by("-request_count")[:10]
    )

    # Get city statistics
    city_stats = (
        RequestLog.objects.filter(city__isnull=False)
        .values("city", "country")
        .annotate(request_count=models.Count("id"))
        .order_by("-request_count")[:10]
    )

    stats = {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "blocked_ips": blocked_ips_count,
        "top_ips": list(top_ips),
        "top_countries": list(country_stats),
        "top_cities": list(city_stats),
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


def geolocation_analytics(request):
    """
    View to show detailed geolocation analytics.
    """
    # Get requests with geolocation data
    geo_requests = RequestLog.objects.filter(country__isnull=False).exclude(country="")

    total_geo_requests = geo_requests.count()

    # Country breakdown
    countries = (
        geo_requests.values("country")
        .annotate(
            request_count=models.Count("id"),
            unique_ips=models.Count("ip_address", distinct=True),
        )
        .order_by("-request_count")
    )

    # City breakdown
    cities = (
        geo_requests.filter(city__isnull=False)
        .exclude(city="")
        .values("city", "country")
        .annotate(
            request_count=models.Count("id"),
            unique_ips=models.Count("ip_address", distinct=True),
        )
        .order_by("-request_count")[:20]
    )

    # Recent requests with geolocation
    recent_geo_requests = geo_requests.order_by("-timestamp")[:20].values(
        "ip_address", "country", "city", "path", "timestamp"
    )

    response_data = {
        "message": "Geolocation Analytics",
        "total_requests_with_geo": total_geo_requests,
        "countries": list(countries),
        "top_cities": list(cities),
        "recent_requests": [
            {
                "ip_address": req["ip_address"],
                "location": (
                    f"{req['city']}, {req['country']}"
                    if req["city"]
                    else req["country"]
                ),
                "path": req["path"],
                "timestamp": req["timestamp"].isoformat(),
            }
            for req in recent_geo_requests
        ],
    }

    return JsonResponse(response_data)
