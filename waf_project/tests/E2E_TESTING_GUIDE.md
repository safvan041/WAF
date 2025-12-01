"""
End-to-End Testing Guide for WAF Reverse Proxy

This guide provides step-by-step instructions for testing the complete
reverse proxy functionality.
"""

# WAF Reverse Proxy - End-to-End Testing Guide

## Prerequisites

1. **Django development server running**
   ```bash
   python manage.py runserver
   ```

2. **Mock origin server running** (in a separate terminal)
   ```bash
   python -m tests.mock_origin_server
   ```

## Test Scenarios

### Scenario 1: Basic Reverse Proxy Test

**Setup:**
1. Go to Django Admin: http://localhost:8000/admin/
2. Navigate to Tenants
3. Edit or create a tenant (e.g., "test east 1")
4. Set the following:
   - **origin_url**: `http://localhost:8001`
   - **waf_host**: `testeast1.waf-app.site` (or any subdomain)
   - **domain**: `www.testeast.com` (your actual domain)

**Test:**
1. Add to your hosts file (`C:\Windows\System32\drivers\etc\hosts`):
   ```
   127.0.0.1  www.testeast.com
   ```

2. Visit: http://www.testeast.com:8000/

3. **Expected Result:**
   - You should see the mock origin server's response
   - The page should say "✅ Reverse Proxy Working!"
   - Headers should show X-Forwarded-* headers

**Verification:**
- Check Django logs for: "Proxying request to origin: http://localhost:8001"
- Check mock origin logs for incoming requests
- Verify response headers include `X-Origin-Server: MockOrigin`

---

### Scenario 2: WAF Blocking Test

**Setup:**
1. Create a WAF rule that blocks SQL injection
2. Ensure the rule is enabled for your tenant

**Test:**
1. Try accessing: http://www.testeast.com:8000/?id=1' OR '1'='1

2. **Expected Result:**
   - Request should be BLOCKED by WAF
   - You should see "403 Forbidden" page
   - Request should NOT reach the origin server

**Verification:**
- Check Django logs for WAF block message
- Mock origin server should NOT log this request
- Security event should be logged in database

---

### Scenario 3: Header Preservation Test

**Setup:**
- Same as Scenario 1

**Test:**
1. Use curl or Postman to send a request with custom headers:
   ```bash
   curl -H "X-Custom-Header: TestValue" http://www.testeast.com:8000/
   ```

2. **Expected Result:**
   - Origin server receives the custom header
   - Response shows X-Custom-Header in the headers list

**Verification:**
- Check mock origin server's HTML response
- Custom header should be listed in "Headers Received by Origin"

---

### Scenario 4: POST Request Test

**Setup:**
- Same as Scenario 1

**Test:**
1. Send a POST request:
   ```bash
   curl -X POST -d "test=data" http://www.testeast.com:8000/api/test
   ```

2. **Expected Result:**
   - Origin server receives POST data
   - Response shows the data that was sent

**Verification:**
- Mock origin server logs should show POST request
- Response JSON should include `data_received` field

---

### Scenario 5: Error Handling Test

**Test 1: Origin Server Down**
1. Stop the mock origin server
2. Try accessing: http://www.testeast.com:8000/
3. **Expected:** "502 Bad Gateway" error

**Test 2: Origin Server Timeout**
1. Configure origin_url to a slow/unresponsive server
2. **Expected:** "504 Gateway Timeout" after 30 seconds

---

### Scenario 6: Django Admin Access (No Proxy)

**Test:**
1. Visit: http://www.testeast.com:8000/admin/

2. **Expected Result:**
   - Django admin should load normally
   - Request should NOT be proxied to origin
   - You should see the Django admin login page

**Verification:**
- Mock origin server should NOT log this request
- Django logs should NOT show "Proxying request to origin"

---

## Automated Test Script

Run the automated tests:
```bash
python tests/test_reverse_proxy.py
```

This will verify:
- URL building logic
- Header preparation
- Tenant configuration

---

## Troubleshooting

### Issue: "No tenant found"
**Solution:** Check that:
- Tenant exists in database
- Domain matches exactly
- Tenant is active

### Issue: "502 Bad Gateway"
**Solution:** Check that:
- Mock origin server is running
- origin_url is correct (http://localhost:8001)
- No firewall blocking localhost connections

### Issue: Request not being proxied
**Solution:** Check that:
- origin_url is set in tenant configuration
- Request path doesn't start with /admin/, /static/, /dashboard/
- WAF is not blocking the request

---

## Success Criteria

✅ All scenarios pass
✅ Headers are preserved correctly
✅ WAF blocking still works
✅ Django admin remains accessible
✅ Error handling works properly

---

## Next Steps

After successful testing:
1. Deploy to production
2. Configure real origin servers
3. Set up DNS CNAME records
4. Enable SSL/TLS
5. Monitor logs for issues
