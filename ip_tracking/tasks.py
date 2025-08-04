"""
Celery tasks for IP tracking anomaly detection.

This module contains background tasks for:
- Detecting suspicious IP behavior
- Flagging high-volume requests
- Identifying access to sensitive paths
- Cleaning up old log entries
"""

import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Q
from celery import shared_task
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)

# Anomaly detection thresholds
HOURLY_REQUEST_THRESHOLD = 100  # Flag IPs with >100 requests/hour
SENSITIVE_PATHS = [
    '/admin', '/admin/', '/admin/login', '/admin/login/',
    '/login', '/login/', '/api/login', '/api/login/',
    '/auth', '/auth/', '/authentication', '/authentication/',
    '/wp-admin', '/wp-admin/', '/wp-login.php',
    '/phpmyadmin', '/phpmyadmin/', '/mysql', '/mysql/',
    '/.env', '/config', '/config/', '/api/config',
    '/debug', '/debug/', '/test', '/test/',
    '/backup', '/backup/', '/db', '/db/',
]


@shared_task(bind=True)
def detect_anomalies(self):
    """
    Detect anomalies in IP behavior and flag suspicious IPs.
    
    This task runs hourly and detects:
    1. IPs exceeding request rate thresholds
    2. IPs accessing sensitive paths
    3. IPs with unusual access patterns
    
    Returns:
        dict: Summary of anomaly detection results
    """
    logger.info("Starting anomaly detection task")
    
    # Define time window (last hour)
    end_time = timezone.now()
    start_time = end_time - timedelta(hours=1)
    
    results = {
        'high_volume_ips': 0,
        'sensitive_path_ips': 0,
        'total_flagged': 0,
        'detection_time': end_time.isoformat(),
        'time_window': f"{start_time.isoformat()} to {end_time.isoformat()}"
    }
    
    try:
        # 1. Detect high-volume IPs (>100 requests/hour)
        high_volume_results = detect_high_volume_ips(start_time, end_time)
        results['high_volume_ips'] = high_volume_results
        
        # 2. Detect IPs accessing sensitive paths
        sensitive_path_results = detect_sensitive_path_access(start_time, end_time)
        results['sensitive_path_ips'] = sensitive_path_results
        
        # 3. Calculate total flagged IPs
        results['total_flagged'] = high_volume_results + sensitive_path_results
        
        logger.info(f"Anomaly detection completed: {results}")
        
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}")
        results['error'] = str(e)
        
    return results


def detect_high_volume_ips(start_time, end_time):
    """
    Detect IPs with high request volume in the given time window.
    
    Args:
        start_time (datetime): Start of detection window
        end_time (datetime): End of detection window
        
    Returns:
        int: Number of IPs flagged for high volume
    """
    logger.info(f"Detecting high-volume IPs from {start_time} to {end_time}")
    
    # Get IPs with request count > threshold in the time window
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=start_time, timestamp__lt=end_time)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=HOURLY_REQUEST_THRESHOLD)
    )
    
    flagged_count = 0
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if IP is already blocked
        if BlockedIP.is_blocked(ip_address):
            logger.info(f"Skipping already blocked IP: {ip_address}")
            continue
        
        # Get recent paths accessed by this IP
        recent_paths = list(
            RequestLog.objects
            .filter(
                ip_address=ip_address,
                timestamp__gte=start_time,
                timestamp__lt=end_time
            )
            .values_list('path', flat=True)
            .distinct()[:20]  # Limit to 20 paths
        )
        
        # Flag the IP as suspicious
        reason = f"High request volume: {request_count} requests in 1 hour (threshold: {HOURLY_REQUEST_THRESHOLD})"
        
        SuspiciousIP.flag_ip(
            ip_address=ip_address,
            reason=reason,
            request_count=request_count,
            paths=recent_paths
        )
        
        flagged_count += 1
        logger.warning(f"Flagged high-volume IP: {ip_address} ({request_count} requests)")
    
    return flagged_count


def detect_sensitive_path_access(start_time, end_time):
    """
    Detect IPs accessing sensitive paths in the given time window.
    
    Args:
        start_time (datetime): Start of detection window
        end_time (datetime): End of detection window
        
    Returns:
        int: Number of IPs flagged for sensitive path access
    """
    logger.info(f"Detecting sensitive path access from {start_time} to {end_time}")
    
    # Build query for sensitive paths
    sensitive_path_query = Q()
    for path in SENSITIVE_PATHS:
        sensitive_path_query |= Q(path__icontains=path)
    
    # Get IPs accessing sensitive paths
    sensitive_access_ips = (
        RequestLog.objects
        .filter(
            timestamp__gte=start_time,
            timestamp__lt=end_time
        )
        .filter(sensitive_path_query)
        .values('ip_address')
        .annotate(
            access_count=Count('id'),
            accessed_paths=Count('path', distinct=True)
        )
        .distinct()
    )
    
    flagged_count = 0
    
    for ip_data in sensitive_access_ips:
        ip_address = ip_data['ip_address']
        access_count = ip_data['access_count']
        unique_paths = ip_data['accessed_paths']
        
        # Skip if IP is already blocked
        if BlockedIP.is_blocked(ip_address):
            logger.info(f"Skipping already blocked IP: {ip_address}")
            continue
        
        # Get the actual sensitive paths accessed
        accessed_sensitive_paths = list(
            RequestLog.objects
            .filter(
                ip_address=ip_address,
                timestamp__gte=start_time,
                timestamp__lt=end_time
            )
            .filter(sensitive_path_query)
            .values_list('path', flat=True)
            .distinct()
        )
        
        # Flag the IP as suspicious
        reason = f"Sensitive path access: {access_count} attempts to {unique_paths} sensitive paths"
        
        SuspiciousIP.flag_ip(
            ip_address=ip_address,
            reason=reason,
            request_count=access_count,
            paths=accessed_sensitive_paths
        )
        
        flagged_count += 1
        logger.warning(
            f"Flagged sensitive path access: {ip_address} "
            f"({access_count} attempts to {accessed_sensitive_paths})"
        )
    
    return flagged_count


@shared_task(bind=True)
def cleanup_old_logs(self, days_to_keep=30):
    """
    Clean up old request logs to prevent database bloat.
    
    Args:
        days_to_keep (int): Number of days of logs to retain
        
    Returns:
        dict: Summary of cleanup results
    """
    logger.info(f"Starting cleanup of logs older than {days_to_keep} days")
    
    cutoff_date = timezone.now() - timedelta(days=days_to_keep)
    
    try:
        # Count logs to be deleted
        old_logs_count = RequestLog.objects.filter(timestamp__lt=cutoff_date).count()
        
        # Delete old logs
        deleted_count, _ = RequestLog.objects.filter(timestamp__lt=cutoff_date).delete()
        
        # Clean up resolved suspicious IPs older than 7 days
        old_suspicious_cutoff = timezone.now() - timedelta(days=7)
        old_suspicious_count, _ = SuspiciousIP.objects.filter(
            detected_at__lt=old_suspicious_cutoff,
            is_resolved=True
        ).delete()
        
        results = {
            'logs_deleted': deleted_count,
            'suspicious_ips_cleaned': old_suspicious_count,
            'cutoff_date': cutoff_date.isoformat(),
            'cleanup_time': timezone.now().isoformat()
        }
        
        logger.info(f"Cleanup completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {e}")
        return {'error': str(e)}


@shared_task(bind=True)
def analyze_ip_patterns(self, ip_address):
    """
    Analyze patterns for a specific IP address.
    
    Args:
        ip_address (str): IP address to analyze
        
    Returns:
        dict: Analysis results for the IP
    """
    logger.info(f"Analyzing patterns for IP: {ip_address}")
    
    try:
        # Get last 24 hours of activity
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=24)
        
        logs = RequestLog.objects.filter(
            ip_address=ip_address,
            timestamp__gte=start_time
        ).order_by('timestamp')
        
        if not logs.exists():
            return {'ip_address': ip_address, 'message': 'No recent activity'}
        
        # Analyze patterns
        total_requests = logs.count()
        unique_paths = logs.values('path').distinct().count()
        
        first_log = logs.first()
        last_log = logs.last()
        if first_log and last_log:
            time_span = last_log.timestamp - first_log.timestamp
        else:
            time_span = timedelta(0)
        
        # Get most accessed paths
        top_paths = list(
            logs.values('path')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Check for suspicious patterns
        suspicious_indicators = []
        
        # High frequency in short time
        if total_requests > 50 and time_span.total_seconds() < 3600:  # >50 requests in <1 hour
            suspicious_indicators.append(f"High frequency: {total_requests} requests in {time_span}")
        
        # Accessing many different paths
        if unique_paths > 20:
            suspicious_indicators.append(f"Path scanning: {unique_paths} unique paths accessed")
        
        # Accessing sensitive paths
        sensitive_accessed = [
            path for path in logs.values_list('path', flat=True).distinct()
            if any(sensitive in path.lower() for sensitive in SENSITIVE_PATHS)
        ]
        if sensitive_accessed:
            suspicious_indicators.append(f"Sensitive paths: {sensitive_accessed}")
        
        results = {
            'ip_address': ip_address,
            'analysis_period': f"{start_time.isoformat()} to {end_time.isoformat()}",
            'total_requests': total_requests,
            'unique_paths': unique_paths,
            'time_span_seconds': time_span.total_seconds(),
            'top_paths': top_paths,
            'suspicious_indicators': suspicious_indicators,
            'risk_level': 'HIGH' if len(suspicious_indicators) >= 2 else 'MEDIUM' if suspicious_indicators else 'LOW'
        }
        
        logger.info(f"IP analysis completed for {ip_address}: Risk level {results['risk_level']}")
        return results
        
    except Exception as e:
        logger.error(f"Error analyzing IP {ip_address}: {e}")
        return {'ip_address': ip_address, 'error': str(e)}


@shared_task(bind=True)
def generate_security_report(self):
    """
    Generate a comprehensive security report.
    
    Returns:
        dict: Security report with various metrics
    """
    logger.info("Generating security report")
    
    try:
        # Get time windows
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)
        
        # Basic metrics
        total_requests_24h = RequestLog.objects.filter(timestamp__gte=last_24h).count()
        total_requests_7d = RequestLog.objects.filter(timestamp__gte=last_7d).count()
        unique_ips_24h = RequestLog.objects.filter(timestamp__gte=last_24h).values('ip_address').distinct().count()
        
        # Security metrics
        blocked_ips = BlockedIP.objects.filter(is_active=True).count()
        suspicious_ips_unresolved = SuspiciousIP.objects.filter(is_resolved=False).count()
        suspicious_ips_24h = SuspiciousIP.objects.filter(detected_at__gte=last_24h).count()
        
        # Top countries/cities (if geolocation data available)
        top_countries = list(
            RequestLog.objects
            .filter(timestamp__gte=last_7d, country__isnull=False)
            .exclude(country='')
            .values('country')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Most accessed paths
        top_paths = list(
            RequestLog.objects
            .filter(timestamp__gte=last_24h)
            .values('path')
            .annotate(count=Count('id'))
            .order_by('-count')[:15]
        )
        
        report = {
            'generated_at': now.isoformat(),
            'requests': {
                'last_24h': total_requests_24h,
                'last_7d': total_requests_7d,
                'unique_ips_24h': unique_ips_24h
            },
            'security': {
                'blocked_ips': blocked_ips,
                'suspicious_ips_unresolved': suspicious_ips_unresolved,
                'suspicious_ips_24h': suspicious_ips_24h
            },
            'top_countries': top_countries,
            'top_paths': top_paths,
            'recommendations': []
        }
        
        # Add recommendations based on metrics
        if suspicious_ips_unresolved > 5:
            report['recommendations'].append(
                f"High number of unresolved suspicious IPs ({suspicious_ips_unresolved}). Consider reviewing and blocking persistent threats."
            )
        
        if total_requests_24h > 10000:
            report['recommendations'].append(
                f"High traffic volume ({total_requests_24h} requests in 24h). Monitor for potential DDoS attacks."
            )
        
        logger.info("Security report generated successfully")
        return report
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return {'error': str(e)}
