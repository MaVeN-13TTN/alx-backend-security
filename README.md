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


## Task 1: IP Blacklisting ✅

### Overview
Extended the IP tracking system with comprehensive IP blacklisting functionality to block malicious or unwanted traffic.

### Components Implemented

#### 1. BlockedIP Model (`ip_tracking/models.py`)
- **Fields:** `ip_address`, `reason`, `created_at`, `is_active`
- **Methods:** `is_blocked()`, `activate()`, `deactivate()`

#### 2. Enhanced Middleware (`ip_tracking/middleware.py`)
- Checks IP against BlockedIP model before processing
- Returns 403 Forbidden for blocked IPs with custom HTML page
- Logs blocked attempts and skips logging for blocked requests

#### 3. Management Command (`ip_tracking/management/commands/block_ip.py`)
- Block/unblock IPs with reasons: `python manage.py block_ip 1.2.3.4 --reason "Spam"`
- List blocked IPs: `python manage.py block_ip --list`
- Force operations: `--force` flag to skip confirmations

### Usage Examples
```bash
# Block an IP
python manage.py block_ip 192.168.1.100 --reason "Suspicious activity" --force

# List blocked IPs  
python manage.py block_ip --list

# Unblock an IP
python manage.py block_ip 192.168.1.100 --unblock --force
```


## Task 2: IP Geolocation Analytics ✅

### Overview
Enhanced the IP tracking system with geolocation capabilities to provide geographic insights into request origins for better security analysis and user experience personalization.

### Components Implemented

#### 1. Enhanced RequestLog Model (`ip_tracking/models.py`)
- **New Fields:** `country`, `city` for storing geolocation data
- **Indexes:** Database indexes on country and city fields for fast queries
- **String Representation:** Updated to include location information

#### 2. Geolocation Middleware (`ip_tracking/middleware.py`)
- **API Integration:** Uses django-ip-geolocation and fallback to ip-api.com
- **24-Hour Caching:** Geolocation results cached for 24 hours to minimize API calls
- **Private IP Handling:** Skips geolocation for private/local IP addresses
- **Error Handling:** Graceful fallback when geolocation services are unavailable

#### 3. Enhanced API Endpoints
- **Stats Endpoint:** Now includes country and city statistics
- **Geo Analytics:** New `/ip-tracking/geo-analytics/` endpoint for detailed geolocation insights
- **Test Endpoint:** Enhanced to show geolocation data in responses

#### 4. Cache Configuration
- **Local Memory Cache:** Configured for 24-hour geolocation data caching
- **Performance Optimization:** Reduces API calls and improves response times
- **Configurable:** Easy to switch to Redis or other cache backends

### Usage Examples

```bash
# Test geolocation functionality
python manage.py test_geolocation 8.8.8.8

# View geolocation analytics
curl http://localhost:8000/ip-tracking/geo-analytics/

# View enhanced stats
curl http://localhost:8000/ip-tracking/stats/
```

### API Response Examples

**Geolocation Analytics:** `GET /ip-tracking/geo-analytics/`
```json
{
  "total_requests_with_geo": 6,
  "countries": [
    {"country": "United States", "request_count": 3, "unique_ips": 2},
    {"country": "Australia", "request_count": 2, "unique_ips": 1}
  ],
  "top_cities": [
    {"city": "Ashburn", "country": "United States", "request_count": 2}
  ]
}
```

### Security Benefits
- **Geographic Analysis:** Identify suspicious traffic patterns by location
- **Fraud Detection:** Flag requests from unexpected geographic regions
- **Compliance:** Support for geographic data protection regulations
- **Analytics:** Better understanding of user demographics and traffic sources

---
**Updated Status:** ✅ Task 0 Complete, ✅ Task 1 Complete, ✅ Task 2 Complete
