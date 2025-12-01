# WAF Tests

This directory contains all test files for the WAF application.

## Test Files

### 1. `mock_origin_server.py`
Mock HTTP server that acts as an origin server for testing reverse proxy functionality.

**Usage:**
```bash
python -m tests.mock_origin_server
```

**Features:**
- Runs on http://localhost:8001
- Returns HTML response showing request details
- Handles GET and POST requests
- Shows all headers received

### 2. `test_reverse_proxy.py`
Unit tests for reverse proxy functionality.

**Usage:**
```bash
python tests/test_reverse_proxy.py
```

**Tests:**
- URL building logic
- Header preparation
- Tenant configuration
- Request forwarding

### 3. `E2E_TESTING_GUIDE.md`
Comprehensive guide for end-to-end testing of the reverse proxy.

**Includes:**
- 6 test scenarios
- Setup instructions
- Expected results
- Troubleshooting tips

## Quick Start

1. **Run unit tests:**
   ```bash
   python tests/test_reverse_proxy.py
   ```

2. **Start mock origin server:**
   ```bash
   python -m tests.mock_origin_server
   ```

3. **Configure a tenant:**
   - Go to Django admin
   - Set origin_url to `http://localhost:8001`

4. **Test the proxy:**
   - Visit your tenant's domain
   - You should see the mock origin response

## Test Coverage

- ✅ URL building and path preservation
- ✅ Header forwarding (X-Forwarded-*)
- ✅ Request method handling (GET, POST, etc.)
- ✅ Query parameter preservation
- ✅ Error handling (timeout, connection errors)
- ✅ WAF integration (blocking still works)
- ✅ Django admin bypass (not proxied)

## Adding New Tests

To add new tests:
1. Create a new file in this directory
2. Follow the naming convention: `test_*.py`
3. Import Django setup if needed
4. Document the test in this README
