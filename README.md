# IP Tracking: Security and Analytics

## Task 0: Basic IP Logging Middleware ✅

### Overview

This implementation provides basic IP logging functionality using Django middleware to track all incoming requests for security and analytics purposes.

### Components Implemented

#### 1. RequestLog Model (`ip_tracking/models.py`)

- **Fields:**
  - `ip_address`: GenericIPAddressField (supports IPv4 and IPv6)
  - `timestamp`: DateTimeField with auto-generation
  - `path`: CharField for storing request URL paths
- **Features:**
  - Database indexes for performance
  - Clean string representation
  - Ordered by timestamp (most recent first)

#### 2. IPLoggingMiddleware (`ip_tracking/middleware.py`)

- **Functionality:**
  - Logs every incoming request automatically
  - Extracts real client IP from various headers (handles proxies/load balancers)
  - Stores IP, timestamp, and request path
  - Graceful error handling
- **Headers Checked:**
  - HTTP_X_FORWARDED_FOR
  - HTTP_X_REAL_IP
  - HTTP_X_FORWARDED
  - HTTP_X_CLUSTER_CLIENT_IP
  - HTTP_FORWARDED_FOR
  - HTTP_FORWARDED
  - REMOTE_ADDR

#### 3. Configuration (`ip_security_project/settings.py`)

- Added `ip_tracking` to `INSTALLED_APPS`
- Registered `IPLoggingMiddleware` in `MIDDLEWARE`
- Configured logging for error tracking

#### 4. Admin Interface (`ip_tracking/admin.py`)

- Read-only admin interface for viewing logs
- Searchable and filterable by IP and path
- Prevents manual log creation/editing

### Project Structure

```
alx-backend-security/
├── .venv/                          # Virtual environment
├── ip_security_project/            # Django project
│   ├── settings.py                 # ✅ Middleware registered
│   └── urls.py                     # URL configuration
├── ip_tracking/                    # ✅ IP tracking app
│   ├── models.py                   # ✅ RequestLog model
│   ├── middleware.py               # ✅ IPLoggingMiddleware
│   ├── admin.py                    # Admin interface
│   ├── views.py                    # Test views
│   ├── urls.py                     # URL patterns
│   └── management/commands/        # Management commands
├── manage.py                       # Django management
└── verify_task0.py                 # Verification script
```

### Testing

Run the verification script to test all components:

```bash
source .venv/bin/activate
python verify_task0.py
```

Create sample log entries:

```bash
python manage.py test_ip_logging
```

### Key Features

- **Security Focused:** Logs all requests for audit trails
- **Proxy Aware:** Correctly identifies client IPs behind proxies
- **Performance Optimized:** Database indexes for fast queries
- **Error Resistant:** Graceful handling of edge cases
- **Privacy Conscious:** Ready for anonymization/retention policies

### Usage Examples

#### View Recent Logs

```python
from ip_tracking.models import RequestLog

# Get recent requests
recent = RequestLog.objects.order_by('-timestamp')[:10]

# Get requests from specific IP
ip_requests = RequestLog.objects.filter(ip_address='192.168.1.1')

# Get requests to specific paths
admin_requests = RequestLog.objects.filter(path__startswith='/admin/')
```

#### Access Client IP in Views

The middleware adds `client_ip` to the request object:

```python
def my_view(request):
    client_ip = request.client_ip  # Set by middleware
    # ... rest of view logic
```

### Next Steps

This basic implementation provides the foundation for:

- IP blacklisting and access control
- Geolocation integration
- Rate limiting
- Anomaly detection
- Advanced analytics

### Compliance Notes

- Consider IP anonymization for GDPR compliance
- Implement data retention policies
- Update privacy policy to disclose IP tracking
- Monitor storage usage and implement log rotation

---

**Status:** ✅ Task 0 Complete
**Files:** `ip_tracking/middleware.py`, `ip_tracking/models.py`
**Repository:** `alx-backend-security`
