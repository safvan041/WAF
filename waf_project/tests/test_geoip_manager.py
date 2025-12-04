"""
Tests for GeoIPManager - Optimized GeoIP lookups with caching
"""
from django.test import TestCase, override_settings
from django.core.cache import cache
from unittest.mock import patch, MagicMock
from waf_project.waf_core.models import Tenant, GeographicRule
from waf_project.waf_security.geoip_manager import GeoIPManager


class GeoIPManagerTestCase(TestCase):
    """Test cases for optimized GeoIP lookups"""
    
    def setUp(self):
        """Set up test data"""
        cache.clear()
        
        # Reset singleton instance for testing
        GeoIPManager._instance = None
        GeoIPManager._initialized = False
        
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.example.com",
            contact_email="admin@test.com",
            contact_name="Admin"
        )
        
        self.test_ip = "8.8.8.8"  # Google DNS (US)
    
    def tearDown(self):
        """Clean up"""
        cache.clear()
        GeoIPManager._instance = None
        GeoIPManager._initialized = False
    
    def test_singleton_pattern(self):
        """Test that GeoIPManager uses singleton pattern"""
        manager1 = GeoIPManager.get_instance()
        manager2 = GeoIPManager.get_instance()
        
        self.assertIs(manager1, manager2, "Should return same instance")
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_get_country_code_with_mock(self, mock_geoip2):
        """Test getting country code with mocked GeoIP"""
        # Mock GeoIP2 response
        mock_instance = MagicMock()
        mock_instance.country.return_value = {'country_code': 'US'}
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        country_code = manager.get_country_code(self.test_ip)
        
        self.assertEqual(country_code, 'US')
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_country_code_caching(self, mock_geoip2):
        """Test that country codes are cached"""
        # Mock GeoIP2
        mock_instance = MagicMock()
        mock_instance.country.return_value = {'country_code': 'US'}
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        
        # First call - should hit GeoIP
        code1 = manager.get_country_code(self.test_ip)
        
        # Second call - should hit cache
        code2 = manager.get_country_code(self.test_ip)
        
        # Both should return same result
        self.assertEqual(code1, 'US')
        self.assertEqual(code2, 'US')
        
        # GeoIP should only be called once (second call from cache)
        self.assertEqual(mock_instance.country.call_count, 1)
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_get_country_info(self, mock_geoip2):
        """Test getting detailed country information"""
        # Mock response
        mock_instance = MagicMock()
        mock_instance.country.return_value = {
            'country_code': 'US',
            'country_name': 'United States',
            'continent_code': 'NA',
            'continent_name': 'North America'
        }
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        info = manager.get_country_info(self.test_ip)
        
        self.assertEqual(info['country_code'], 'US')
        self.assertEqual(info['country_name'], 'United States')
        self.assertEqual(info['continent_code'], 'NA')
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_is_country_blocked(self, mock_geoip2):
        """Test checking if country is blocked"""
        # Mock GeoIP
        mock_instance = MagicMock()
        mock_instance.country.return_value = {'country_code': 'CN'}
        mock_geoip2.return_value = mock_instance
        
        # Create blocking rule for China
        GeographicRule.objects.create(
            tenant=self.tenant,
            country_code='CN',
            country_name='China',
            action='block',
            is_active=True
        )
        
        manager = GeoIPManager()
        is_blocked, country_code, country_name = manager.is_country_blocked(
            self.tenant, "1.2.3.4"
        )
        
        self.assertTrue(is_blocked)
        self.assertEqual(country_code, 'CN')
        self.assertEqual(country_name, 'China')
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_is_country_not_blocked(self, mock_geoip2):
        """Test that non-blocked countries are allowed"""
        # Mock GeoIP
        mock_instance = MagicMock()
        mock_instance.country.return_value = {'country_code': 'US'}
        mock_geoip2.return_value = mock_instance
        
        # Create blocking rule for China (not US)
        GeographicRule.objects.create(
            tenant=self.tenant,
            country_code='CN',
            country_name='China',
            action='block',
            is_active=True
        )
        
        manager = GeoIPManager()
        is_blocked, country_code, _ = manager.is_country_blocked(
            self.tenant, self.test_ip
        )
        
        self.assertFalse(is_blocked)
        self.assertEqual(country_code, 'US')
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    @override_settings(WAF_GEOIP_ALLOW_UNKNOWN=True)
    def test_unknown_country_allowed_by_default(self, mock_geoip2):
        """Test that unknown countries are allowed when configured"""
        # Mock GeoIP to return None
        mock_instance = MagicMock()
        mock_instance.country.side_effect = Exception("Lookup failed")
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        is_blocked, country_code, _ = manager.is_country_blocked(
            self.tenant, "invalid.ip"
        )
        
        self.assertFalse(is_blocked)
        self.assertIsNone(country_code)
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    @override_settings(WAF_GEOIP_ALLOW_UNKNOWN=False)
    def test_unknown_country_blocked_when_configured(self, mock_geoip2):
        """Test that unknown countries can be blocked"""
        # Mock GeoIP to return None
        mock_instance = MagicMock()
        mock_instance.country.side_effect = Exception("Lookup failed")
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        is_blocked, country_code, _ = manager.is_country_blocked(
            self.tenant, "invalid.ip"
        )
        
        self.assertTrue(is_blocked)
        self.assertIsNone(country_code)
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_clear_cache_for_specific_ip(self, mock_geoip2):
        """Test clearing cache for specific IP"""
        # Mock GeoIP
        mock_instance = MagicMock()
        mock_instance.country.return_value = {'country_code': 'US'}
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        
        # Cache the IP
        manager.get_country_code(self.test_ip)
        
        # Clear cache for this IP
        manager.clear_cache(self.test_ip)
        
        # Next call should hit GeoIP again
        manager.get_country_code(self.test_ip)
        
        # Should have been called twice (once before clear, once after)
        self.assertEqual(mock_instance.country.call_count, 2)
    
    @patch('waf_project.waf_security.geoip_manager.GeoIP2')
    def test_get_stats(self, mock_geoip2):
        """Test getting GeoIP manager statistics"""
        mock_instance = MagicMock()
        mock_geoip2.return_value = mock_instance
        
        manager = GeoIPManager()
        stats = manager.get_stats()
        
        self.assertIn('initialized', stats)
        self.assertIn('database_available', stats)
        self.assertIn('cache_ttl', stats)
        
        self.assertTrue(stats['initialized'])
        self.assertTrue(stats['database_available'])
    
    def test_graceful_failure_when_geoip_unavailable(self):
        """Test that system handles missing GeoIP database gracefully"""
        # This will fail to load GeoIP database
        manager = GeoIPManager()
        
        # Should return None instead of crashing
        country_code = manager.get_country_code(self.test_ip)
        
        # Depending on whether GeoLite2 is installed, this might be None or a valid code
        # The important thing is it doesn't crash
        self.assertIsInstance(country_code, (str, type(None)))
