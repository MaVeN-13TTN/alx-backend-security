"""
Celery configuration for ip_security_project.

This module sets up Celery for handling background tasks including:
- Anomaly detection for suspicious IP behavior
- Periodic cleanup tasks
- Email notifications for security alerts
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ip_security_project.settings')

app = Celery('ip_security_project')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
app.conf.beat_schedule = {
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': 60.0 * 60.0,  # Run every hour (3600 seconds)
    },
    'cleanup-old-logs-daily': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': 60.0 * 60.0 * 24.0,  # Run daily (86400 seconds)
    },
}

# Configure timezone settings
app.conf.update(
    timezone='UTC',
    enable_utc=True,
)

@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')
