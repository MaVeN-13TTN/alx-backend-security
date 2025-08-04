# IP Tracking: Complete Security & Analytics System

🔒 **Comprehensive IP tracking and security system with real-time anomaly detection**

## System Overview

This Django-based IP tracking system provides enterprise-level security monitoring with automated threat detection, geographic analytics, rate limiting, and intelligent IP blacklisting.

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
    { "country": "United States", "request_count": 3, "unique_ips": 2 },
    { "country": "Australia", "request_count": 2, "unique_ips": 1 }
  ],
  "top_cities": [
    { "city": "Ashburn", "country": "United States", "request_count": 2 }
  ]
}
```

### Security Benefits

- **Geographic Analysis:** Identify suspicious traffic patterns by location
- **Fraud Detection:** Flag requests from unexpected geographic regions
- **Compliance:** Support for geographic data protection regulations
- **Analytics:** Better understanding of user demographics and traffic sources

---

**Updated Status:** ✅ Task 0 Complete, ✅ Task 1 Complete, ✅ Task 2 Complete, ✅ Task 3 Complete

## Task 3: Rate Limiting by IP ✅

### Overview

Implemented comprehensive rate limiting to prevent abuse and protect sensitive endpoints using django-ratelimit with different limits for authenticated and anonymous users.

### Components Implemented

#### 1. Rate Limiting Configuration (\`settings.py\`)

- **Package Installation:** django-ratelimit 4.1.0 for advanced rate limiting
- **Rate Limits:** 10 requests/minute for authenticated users, 5 requests/minute for anonymous users
- **Cache Integration:** Uses Django's cache framework for rate limit tracking
- **Global Settings:** Configurable rate limits and cache backend

#### 2. Rate-Limited Views (\`ip_tracking/views.py\`)

- **Helper Function:** \`rate_for_user()\` dynamically determines rate based on authentication status
- **Protected Endpoints:** All sensitive views now have rate limiting applied
- **Sensitive Login:** New \`/ip-tracking/login/\` endpoint with strict rate limiting
- **Error Handling:** Graceful handling of rate limit exceptions

#### 3. Rate Limiting Features

- **IP-Based Limiting:** Rate limits applied per IP address
- **Authentication-Aware:** Different limits for authenticated vs anonymous users
- **Block Mode:** Requests exceeding limits are blocked with 403 Forbidden
- **Cache Efficiency:** Leverages existing cache infrastructure

### Usage Examples

\`\`\`bash

# Test rate limiting on anonymous endpoint (5 req/min limit)

for i in {1..7}; do curl -s http://localhost:8000/ip-tracking/test/ | head -n 1; done

# Test rate limiting on authenticated endpoint (10 req/min limit)

curl -X POST http://localhost:8000/ip-tracking/login/ \\
-H "Content-Type: application/json" \\
-d '{"username": "test", "password": "test"}'

# Check current rate limiting configuration

python -c "from django.conf import settings; print(f'Auth: {settings.RATELIMIT_AUTHENTICATED_RATE}, Anon: {settings.RATELIMIT_ANONYMOUS_RATE}')"
\`\`\`

### API Response Examples

**Rate Limited Response:** HTTP 403 Forbidden
\`\`\`
Forbidden (Permission denied): /ip-tracking/test/
django_ratelimit.exceptions.Ratelimited
\`\`\`

**Successful Login Response:**
\`\`\`json
{
"message": "Login successful",
"success": true,
"user": "username",
"rate_limit_applied": true
}
\`\`\`

### Protected Endpoints

- **\`/ip-tracking/test/\`** - IP logging test (5/10 req/min)
- **\`/ip-tracking/login/\`** - Sensitive login endpoint (5/10 req/min)
- **\`/ip-tracking/stats/\`** - Statistics endpoint (5/10 req/min)
- **\`/ip-tracking/blocked/\`** - Blocked IPs list (5/10 req/min)
- **\`/ip-tracking/geo-analytics/\`** - Geolocation analytics (5/10 req/min)

### Security Benefits

- **Brute Force Protection:** Prevents password attacks and credential stuffing
- **DDoS Mitigation:** Limits request volume per IP to prevent service overload
- **Resource Protection:** Prevents abuse of computationally expensive endpoints
- **Fair Usage:** Ensures equitable access to API resources
- **User Experience:** Higher limits for authenticated users encourage registration

---

---

**Final Status:** ✅ All Tasks Complete - IP Tracking System with Security & Analytics

## Task 4: Anomaly Detection with Celery ✅

### Overview

Implemented intelligent anomaly detection using Celery background tasks to automatically identify and flag suspicious IP behavior patterns for proactive security monitoring.

### Components Implemented

#### 1. SuspiciousIP Model (`ip_tracking/models.py`)

- **Fields:** `ip_address`, `reason`, `detected_at`, `request_count`, `is_resolved`, `flagged_paths`
- **Methods:** `flag_ip()`, `mark_resolved()`, `get_unresolved_count()`
- **Features:** Intelligent deduplication, JSON field for tracking suspicious paths

#### 2. Celery Task System (`ip_tracking/tasks.py`)

- **detect_anomalies():** Main hourly task detecting suspicious patterns
- **detect_high_volume_ips():** Flags IPs exceeding 100 requests/hour threshold
- **detect_sensitive_path_access():** Monitors access to admin, login, and API endpoints
- **cleanup_old_logs():** Daily maintenance task removing old log entries
- **analyze_ip_patterns():** Advanced pattern analysis for emerging threats

#### 3. Celery Configuration (`ip_security_project/celery.py`)

- **Redis Integration:** Message broker and result backend
- **Scheduled Tasks:** Hourly anomaly detection, daily log cleanup
- **Error Handling:** Comprehensive logging and retry logic
- **Scalability:** Worker process configuration for high-volume environments

#### 4. Enhanced Admin Interface (`ip_tracking/admin.py`)

- **SuspiciousIP Management:** Full CRUD operations with bulk actions
- **Bulk Actions:** Mark multiple IPs as resolved or block suspicious IPs
- **Filtering:** Filter by resolution status, detection date, and IP address
- **Search:** Full-text search across IP addresses and reasons

### Detection Algorithms

#### High-Volume Detection
- **Threshold:** 100+ requests per hour from single IP
- **Analysis:** Time-based request counting with sliding window
- **Action:** Automatic flagging with request count details

#### Sensitive Path Monitoring
- **Monitored Paths:** `/admin/`, `/login`, `/api/`, sensitive endpoints
- **Pattern Analysis:** Multiple path access attempts within time window
- **Correlation:** Cross-references with blocked IP lists

#### Advanced Pattern Recognition
- **Behavioral Analysis:** Request timing, path sequences, user agent patterns
- **Machine Learning Ready:** Framework for ML-based anomaly detection
- **Custom Rules:** Configurable detection rules and thresholds

### Usage Examples

```bash
# Manual anomaly detection
python manage.py shell -c "from ip_tracking.tasks import detect_anomalies; detect_anomalies()"

# Start Celery worker
celery -A ip_security_project worker --loglevel=info

# Start Celery beat scheduler
celery -A ip_security_project beat --loglevel=info

# Check suspicious IPs
python manage.py shell -c "from ip_tracking.models import SuspiciousIP; print(f'Unresolved: {SuspiciousIP.get_unresolved_count()}')"
```

### API Integration

```python
# Check if IP is flagged as suspicious
from ip_tracking.models import SuspiciousIP

def is_suspicious_ip(ip_address):
    return SuspiciousIP.objects.filter(
        ip_address=ip_address, 
        is_resolved=False
    ).exists()

# Get anomaly detection results
suspicious_ips = SuspiciousIP.objects.filter(is_resolved=False)
for ip in suspicious_ips:
    print(f"⚠️  {ip.ip_address}: {ip.reason}")
```

### Security Benefits

- **Proactive Threat Detection:** Identifies suspicious behavior before manual review
- **Automated Response:** Background processing doesn't impact request performance  
- **Pattern Recognition:** Detects sophisticated attack patterns and coordinated threats
- **Audit Trail:** Complete history of detected anomalies and resolution actions
- **Scalable Monitoring:** Handles high-volume traffic with distributed task processing

### System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Django App    │───▶│   Redis Cache    │◀───│  Celery Worker  │
│                 │    │  & Message Broker│    │                 │
│ • Middleware    │    └──────────────────┘    │ • Anomaly Tasks │
│ • Models        │                            │ • Pattern Analysis│
│ • Views         │    ┌──────────────────┐    │ • Cleanup Jobs  │
│ • Admin         │───▶│   Database       │    └─────────────────┘
└─────────────────┘    │                  │
                       │ • Request Logs   │    ┌─────────────────┐
                       │ • Blocked IPs    │───▶│  Celery Beat    │
                       │ • Suspicious IPs │    │                 │
                       └──────────────────┘    │ • Task Scheduler│
                                               │ • Cron Jobs     │
                                               └─────────────────┘
```

## Complete System Features 🚀

### 🔍 **Real-time Monitoring**
- Every request logged with IP, timestamp, geolocation
- Live anomaly detection with configurable thresholds
- Geographic analytics with country/city tracking

### 🛡️ **Security Protection**
- Intelligent IP blacklisting with management commands
- Rate limiting (10 req/min authenticated, 5 req/min anonymous)  
- Automated suspicious IP flagging and blocking

### 📊 **Analytics & Insights**
- Geographic request distribution analytics
- Request volume and pattern analysis
- Top countries, cities, and IP activity reports

### ⚡ **Background Processing**
- Celery-powered anomaly detection tasks
- Redis message broker and caching
- Scheduled maintenance and cleanup jobs

### 🔧 **Administration**
- Django admin interface for all models
- Bulk actions for IP management
- Search and filtering capabilities

## Technology Stack

- **Backend:** Django 5.2.4
- **Task Processing:** Celery 5.5.3  
- **Message Broker:** Redis 7.0+
- **Rate Limiting:** django-ratelimit 4.1.0
- **Caching:** django-redis
- **Database:** SQLite (easily configurable for PostgreSQL/MySQL)

## Installation & Setup

```bash
# Clone repository
git clone <repository-url>
cd alx-backend-security

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate     # Windows

# Install dependencies
pip install django celery redis django-ratelimit django-redis requests

# Setup database
python manage.py makemigrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Start Redis server
redis-server

# Start Django development server
python manage.py runserver

# Start Celery worker (new terminal)
celery -A ip_security_project worker --loglevel=info

# Start Celery beat scheduler (new terminal)
celery -A ip_security_project beat --loglevel=info
```

## Testing & Verification

```bash
# Run complete system test
python test_complete_system.py

# Test individual tasks
python verify_task0.py  # Basic IP logging
python verify_task1.py  # IP blacklisting  
python verify_task2.py  # Geolocation analytics
python verify_task3.py  # Rate limiting
python verify_task4.py  # Anomaly detection
```

## API Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/ip-tracking/test/` | GET | Test IP logging | 5-10/min |
| `/ip-tracking/stats/` | GET | Request statistics | 5-10/min |
| `/ip-tracking/geo-analytics/` | GET | Geographic analytics | 5-10/min |
| `/ip-tracking/login/` | POST | Protected login endpoint | 5-10/min |
| `/ip-tracking/blocked/` | GET | List blocked IPs | 5-10/min |
| `/admin/` | ALL | Django admin interface | Protected |

## Management Commands

```bash
# IP Management
python manage.py block_ip 192.168.1.100 --reason "Spam"
python manage.py block_ip --list
python manage.py block_ip 192.168.1.100 --unblock

# Testing
python manage.py test_ip_logging
python manage.py test_geolocation 8.8.8.8
```

## Configuration

Key settings in `settings.py`:

```python
# Rate Limiting
RATELIMIT_AUTHENTICATED_RATE = "10/m"
RATELIMIT_ANONYMOUS_RATE = "5/m"

# Caching  
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}

# Celery
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

## Monitoring & Alerts

- **Suspicious IP Detection:** Automatic flagging of high-volume IPs (100+ req/hour)
- **Sensitive Path Monitoring:** Tracks access to admin and authentication endpoints  
- **Geographic Anomalies:** Unusual request patterns from specific locations
- **Admin Notifications:** Django admin interface for reviewing flagged IPs

## Production Deployment

- **Database:** Configure PostgreSQL or MySQL for production
- **Cache:** Use Redis Cluster for high availability
- **Celery:** Deploy with supervisor or systemd for process management
- **Monitoring:** Integrate with Sentry, New Relic, or similar monitoring tools
- **Security:** Configure HTTPS, secure headers, and firewall rules

## License

This project is part of the ALX Backend Security curriculum.

---

**🎉 Project Status:** ✅ **COMPLETE** - All 4 tasks implemented and tested
**📁 Repository:** `alx-backend-security`  
**👨‍💻 Implementation:** Full-stack Django security system with real-time monitoring
