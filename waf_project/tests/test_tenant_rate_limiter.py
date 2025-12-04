"""
Tests for TenantRateLimiter - Per-tenant rate limiting functionality
"""
import time
from django.test import TestCase, override_settings
from django.core.cache import cache
from django.contrib.auth import get_user_model
from waf_project.waf_core.models import Tenant, RateLimitConfig, IPWhitelist
from waf_project.waf_security.tenant_rate_limiter import TenantRateLimiter
from waf_project.waf_security.models import RateLimitViolation

User = get_user_model()


class TenantRateLimiterTestCase(TestCase):
    """Test cases for tenant-isolated rate limiting"""
    
    def setUp(self):
        """Set up test tenants and configurations"""
        # Clear cache before each test
        cache.clear()
        
        # Create test tenants
        self.tenant1 = Tenant.objects.create(
            name="Test Tenant 1",
            domain="tenant1.example.com",
            contact_email="admin@tenant1.com",
            contact_name="Admin 1"
        )
        
        self.tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            domain="tenant2.example.com",
            contact_email="admin@tenant2.com",
            contact_name="Admin 2"
        )
        
        # Create rate limit configs
        self.config1 = RateLimitConfig.objects.create(
            tenant=self.tenant1,
            requests_per_minute=10,
            requests_per_hour=100,
            per_ip_requests_per_minute=5
        )
        
        self.config2 = RateLimitConfig.objects.create(
            tenant=self.tenant2,
            requests_per_minute=20,
            requests_per_hour=200,
            per_ip_requests_per_minute=10
        )
        
        self.test_ip = "192.168.1.100"
    
    def tearDown(self):
        """Clean up after each test"""
        cache.clear()
    
    def test_rate_limit_allows_within_limit(self):
        """Test that requests within limit are allowed"""
        # Make 5 requests (within limit of 10)
        for i in range(5):
            is_allowed, limit_type, count, limit = TenantRateLimiter.check_rate_limit(
                self.tenant1, self.test_ip
            )
            self.assertTrue(is_allowed, f"Request {i+1} should be allowed")
    
    def test_rate_limit_blocks_over_limit(self):
        """Test that requests exceeding limit are blocked"""
        # Make requests up to the limit (10 per minute for tenant)
        for i in range(10):
            TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        
        # Next request should be blocked
        is_allowed, limit_type, count, limit = TenantRateLimiter.check_rate_limit(
            self.tenant1, self.test_ip
        )
        self.assertFalse(is_allowed, "Request over limit should be blocked")
        # Could be either per_minute or per_ip_minute depending on which limit is hit first
        self.assertIn(limit_type, ['per_minute', 'per_ip_minute'])
    
    def test_tenant_isolation(self):
        """Test that rate limits are isolated per tenant"""
        # Exhaust tenant1's limit
        for i in range(10):
            TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        
        # Tenant1 should be blocked
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        self.assertFalse(is_allowed, "Tenant1 should be blocked")
        
        # Tenant2 should still be allowed (different limit)
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant2, self.test_ip)
        self.assertTrue(is_allowed, "Tenant2 should still be allowed")
    
    def test_per_ip_rate_limiting(self):
        """Test per-IP rate limiting within a tenant"""
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"
        
        # Exhaust limit for IP1
        for i in range(5):
            TenantRateLimiter.check_rate_limit(self.tenant1, ip1)
        
        # IP1 should be blocked (per_ip_requests_per_minute = 5)
        is_allowed, limit_type, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, ip1)
        self.assertFalse(is_allowed, "IP1 should be blocked")
        self.assertEqual(limit_type, 'per_ip_minute')
        
        # IP2 should still be allowed
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, ip2)
        self.assertTrue(is_allowed, "IP2 should still be allowed")
    
    def test_whitelist_bypass(self):
        """Test that whitelisted IPs bypass rate limits"""
        # Add IP to whitelist
        IPWhitelist.objects.create(
            tenant=self.tenant1,
            ip_address=self.test_ip,
            is_active=True
        )
        
        # Make many requests (way over limit)
        for i in range(50):
            is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
            self.assertTrue(is_allowed, f"Whitelisted IP should always be allowed (request {i+1})")
    
    def test_violation_logging(self):
        """Test that rate limit violations are logged"""
        # Clear any existing violations
        RateLimitViolation.objects.all().delete()
        
        # Exhaust limit
        for i in range(10):
            TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        
        # Trigger violation
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/test/')
        
        TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip, request)
        
        # Check violation was logged
        violations = RateLimitViolation.objects.filter(
            tenant=self.tenant1,
            ip_address=self.test_ip
        )
        self.assertGreater(violations.count(), 0, "Violation should be logged")
    
    def test_reset_limits(self):
        """Test resetting rate limits"""
        # Exhaust limit
        for i in range(10):
            TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        
        # Should be blocked
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        self.assertFalse(is_allowed)
        
        # Reset limits for this IP
        TenantRateLimiter.reset_limits(self.tenant1, self.test_ip)
        
        # Should be allowed again
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        self.assertTrue(is_allowed, "Should be allowed after reset")
    
    def test_get_current_usage(self):
        """Test getting current rate limit usage"""
        # Make some requests
        for i in range(3):
            TenantRateLimiter.check_rate_limit(self.tenant1, self.test_ip)
        
        # Get usage
        usage = TenantRateLimiter.get_current_usage(self.tenant1, self.test_ip)
        
        # Verify structure
        self.assertIn('per_minute', usage)
        self.assertIn('per_hour', usage)
        self.assertIn('per_ip_minute', usage)
        
        # Verify counts
        self.assertEqual(usage['per_minute']['current'], 3)
        self.assertEqual(usage['per_minute']['limit'], 10)
    
    def test_default_limits_when_no_config(self):
        """Test that default limits are used when no config exists"""
        # Create tenant without config
        tenant3 = Tenant.objects.create(
            name="Test Tenant 3",
            domain="tenant3.example.com",
            contact_email="admin@tenant3.com",
            contact_name="Admin 3"
        )
        
        # Should use default limits
        is_allowed, _, _, _ = TenantRateLimiter.check_rate_limit(tenant3, self.test_ip)
        self.assertTrue(is_allowed, "Should use default limits")
        
        # Get usage to verify defaults
        usage = TenantRateLimiter.get_current_usage(tenant3, self.test_ip)
        self.assertEqual(usage['per_minute']['limit'], 60)  # Default from TenantRateLimiter.DEFAULT_LIMITS
