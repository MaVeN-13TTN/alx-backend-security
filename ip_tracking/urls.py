from django.urls import path
from . import views

app_name = "ip_tracking"

urlpatterns = [
    path("test/", views.test_ip_logging, name="test_ip_logging"),
    path("stats/", views.ip_stats, name="ip_stats"),
    path("blocked/", views.blocked_ips, name="blocked_ips"),
]
