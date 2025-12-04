"""
Tests for TenantCacheManager - Cached rule loading and automatic invalidation
"""
from django.test import TestCase
from django.core.cache import cache
from waf_project.waf_core.models import (
    Tenant, FirewallRule, TenantFirewallConfig,
    WAFConfiguration, GeographicRule
)
from waf_project.waf_security.tenant_cache_manager import TenantCacheManager


class TenantCacheManagerTestCase(TestCase):
    """Test cases for tenant-scoped caching"""
    
    def setUp(self):
        """Set up test data"""
        cache.clear()
        
        # Create tenant
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.example.com",
            contact_email="admin@test.com",
            contact_name="Admin"
        )
        
        # Create WAF configuration
        self.waf_config = WAFConfiguration.objects.create(
            tenant=self.tenant,
            is_enabled=True,
            protection_level='medium'
        )
        
        # Create firewall rules
        self.rule1 = FirewallRule.objects.create(
            name="SQL Injection Rule",
            rule_type="sql_injection",
            pattern=r"(union|select|insert|drop)",
            action="block",
            is_active=True
        )
        
        self.rule2 = FirewallRule.objects.create(
            name="XSS Rule",
            rule_type="xss",
            pattern=r"(<script|javascript:)",
            action="block",
            is_active=True
        )
        
        # Link rules to tenant
        self.config1 = TenantFirewallConfig.objects.create(
            tenant=self.tenant,
            rule=self.rule1,
            is_enabled=True
        )
        
        self.config2 = TenantFirewallConfig.objects.create(
            tenant=self.tenant,
            rule=self.rule2,
            is_enabled=True
        )
    
    def tearDown(self):
        """Clean up cache"""
        cache.clear()
    
    def test_get_tenant_rules_caches_result(self):
        """Test that tenant rules are cached"""
        # First call - should hit database
        rules1 = TenantCacheManager.get_tenant_rules(self.tenant)
        
        # Second call - should hit cache
        rules2 = TenantCacheManager.get_tenant_rules(self.tenant)
        
        # Should return same data
        self.assertEqual(len(rules1), 2)
        self.assertEqual(len(rules2), 2)
        
        # Verify cache key exists
        cache_key = f"tenant_rules:{self.tenant.id}"
        cached_data = cache.get(cache_key)
        self.assertIsNotNone(cached_data, "Rules should be cached")
    
    def test_get_waf_config_caches_result(self):
        """Test that WAF configuration is cached"""
        # First call
        config1 = TenantCacheManager.get_waf_config(self.tenant)
        
        # Second call
        config2 = TenantCacheManager.get_waf_config(self.tenant)
        
        # Should return same config
        self.assertEqual(config1.id, self.waf_config.id)
        self.assertEqual(config2.id, self.waf_config.id)
        
        # Verify cache
        cache_key = f"tenant_config:{self.tenant.id}"
        cached_data = cache.get(cache_key)
        self.assertIsNotNone(cached_data)
    
    def test_cache_invalidation_on_rule_update(self):
        """Test that cache is invalidated when rules are updated"""
        # Cache the rules
        rules1 = TenantCacheManager.get_tenant_rules(self.tenant)
        self.assertEqual(len(rules1), 2)
        
        # Update a rule (should trigger signal)
        self.config1.is_enabled = False
        self.config1.save()
        
        # Cache should be invalidated
        cache_key = f"tenant_rules:{self.tenant.id}"
        cached_data = cache.get(cache_key)
        self.assertIsNone(cached_data, "Cache should be invalidated after update")
        
        # Next call should fetch fresh data
        rules2 = TenantCacheManager.get_tenant_rules(self.tenant)
        # Should only have 1 enabled rule now
        enabled_rules = [r for r in rules2 if r.is_enabled]
        self.assertEqual(len(enabled_rules), 1)
    
    def test_cache_invalidation_on_config_update(self):
        """Test that cache is invalidated when WAF config is updated"""
        # Cache the config
        config1 = TenantCacheManager.get_waf_config(self.tenant)
        self.assertTrue(config1.is_enabled)
        
        # Update config
        self.waf_config.is_enabled = False
        self.waf_config.save()
        
        # Cache should be invalidated
        cache_key = f"tenant_config:{self.tenant.id}"
        cached_data = cache.get(cache_key)
        self.assertIsNone(cached_data)
        
        # Next call should fetch fresh data
        config2 = TenantCacheManager.get_waf_config(self.tenant)
        self.assertFalse(config2.is_enabled)
    
    def test_manual_cache_invalidation(self):
        """Test manually invalidating cache"""
        # Cache data
        TenantCacheManager.get_tenant_rules(self.tenant)
        TenantCacheManager.get_waf_config(self.tenant)
        
        # Manually invalidate
        TenantCacheManager.invalidate_all(self.tenant)
        
        # Verify all caches are cleared
        rules_key = f"tenant_rules:{self.tenant.id}"
        config_key = f"tenant_config:{self.tenant.id}"
        
        self.assertIsNone(cache.get(rules_key))
        self.assertIsNone(cache.get(config_key))
    
    def test_get_cache_stats(self):
        """Test getting cache statistics"""
        # Initially nothing cached
        stats1 = TenantCacheManager.get_cache_stats(self.tenant)
        self.assertFalse(stats1['rules_cached'])
        self.assertFalse(stats1['config_cached'])
        
        # Cache some data
        TenantCacheManager.get_tenant_rules(self.tenant)
        TenantCacheManager.get_waf_config(self.tenant)
        
        # Now should show cached
        stats2 = TenantCacheManager.get_cache_stats(self.tenant)
        self.assertTrue(stats2['rules_cached'])
        self.assertTrue(stats2['config_cached'])
    
    def test_geo_rules_caching(self):
        """Test that geographic rules are cached"""
        # Create geo rule
        geo_rule = GeographicRule.objects.create(
            tenant=self.tenant,
            country_code="CN",
            country_name="China",
            action="block",
            is_active=True
        )
        
        # First call - should cache
        rules1 = TenantCacheManager.get_geo_rules(self.tenant)
        self.assertEqual(len(rules1), 1)
        
        # Second call - should hit cache
        rules2 = TenantCacheManager.get_geo_rules(self.tenant)
        self.assertEqual(len(rules2), 1)
        
        # Verify cache
        cache_key = f"tenant_geo_rules:{self.tenant.id}"
        self.assertIsNotNone(cache.get(cache_key))
    
    def test_tenant_isolation_in_cache(self):
        """Test that cache is isolated per tenant"""
        # Create second tenant
        tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            domain="test2.example.com",
            contact_email="admin@test2.com",
            contact_name="Admin 2"
        )
        
        # Create config for tenant2
        WAFConfiguration.objects.create(
            tenant=tenant2,
            is_enabled=False,
            protection_level='low'
        )
        
        # Cache both tenants
        config1 = TenantCacheManager.get_waf_config(self.tenant)
        config2 = TenantCacheManager.get_waf_config(tenant2)
        
        # Should have different configs
        self.assertTrue(config1.is_enabled)
        self.assertFalse(config2.is_enabled)
        
        # Invalidating tenant1 shouldn't affect tenant2
        TenantCacheManager.invalidate_waf_config(self.tenant)
        
        cache_key2 = f"tenant_config:{tenant2.id}"
        self.assertIsNotNone(cache.get(cache_key2), "Tenant2 cache should still exist")
    
    def test_cache_returns_none_for_missing_config(self):
        """Test that cache properly handles missing configurations"""
        # Create tenant without config
        tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            domain="test2.example.com",
            contact_email="admin@test2.com",
            contact_name="Admin 2"
        )
        
        # Should return None
        config = TenantCacheManager.get_waf_config(tenant2)
        self.assertIsNone(config)
        
        # Should cache the None result to prevent repeated lookups
        cache_key = f"tenant_config:{tenant2.id}"
        cached_result = cache.get(cache_key)
        self.assertIsNone(cached_result)
