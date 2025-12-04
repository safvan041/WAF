"""
Tenant-scoped caching for WAF rules and configurations.
Reduces database queries and improves performance.
"""
import logging
from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from waf_project.waf_core.models import (
    TenantFirewallConfig,
    WAFConfiguration,
    FirewallRule,
    GeographicRule,
)

logger = logging.getLogger('waf_security')


class TenantCacheManager:
    """
    Manages tenant-scoped caching for WAF rules and configurations.
    Automatically invalidates cache when models are updated.
    """
    
    # Cache key prefixes
    RULES_PREFIX = 'tenant_rules'
    CONFIG_PREFIX = 'tenant_config'
    GEO_RULES_PREFIX = 'tenant_geo_rules'
    
    # Cache TTL (in seconds)
    CACHE_TTL = 300  # 5 minutes
    
    @classmethod
    def get_tenant_rules(cls, tenant):
        """
        Get active WAF rules for tenant (cached).
        
        Returns:
            QuerySet of TenantFirewallConfig objects
        """
        cache_key = f"{cls.RULES_PREFIX}:{tenant.id}"
        
        # Try to get from cache
        cached_rules = cache.get(cache_key)
        if cached_rules is not None:
            logger.debug(f"Cache HIT for tenant rules: {tenant.name}")
            return cached_rules
        
        # Cache miss - fetch from database
        logger.debug(f"Cache MISS for tenant rules: {tenant.name}")
        rules = list(
            TenantFirewallConfig.objects.filter(
                tenant=tenant,
                is_enabled=True
            ).select_related('rule').order_by('rule__severity', 'rule__name')
        )
        
        # Store in cache
        cache.set(cache_key, rules, cls.CACHE_TTL)
        
        return rules
    
    @classmethod
    def get_waf_config(cls, tenant):
        """
        Get WAF configuration for tenant (cached).
        
        Returns:
            WAFConfiguration object or None
        """
        cache_key = f"{cls.CONFIG_PREFIX}:{tenant.id}"
        
        # Try to get from cache
        cached_config = cache.get(cache_key)
        if cached_config is not None:
            logger.debug(f"Cache HIT for WAF config: {tenant.name}")
            return cached_config
        
        # Cache miss - fetch from database
        logger.debug(f"Cache MISS for WAF config: {tenant.name}")
        try:
            config = WAFConfiguration.objects.get(tenant=tenant)
        except WAFConfiguration.DoesNotExist:
            config = None
        
        # Store in cache (even if None to prevent repeated lookups)
        cache.set(cache_key, config, cls.CACHE_TTL)
        
        return config
    
    @classmethod
    def get_geo_rules(cls, tenant):
        """
        Get geographic rules for tenant (cached).
        
        Returns:
            List of GeographicRule objects
        """
        cache_key = f"{cls.GEO_RULES_PREFIX}:{tenant.id}"
        
        # Try to get from cache
        cached_rules = cache.get(cache_key)
        if cached_rules is not None:
            logger.debug(f"Cache HIT for geo rules: {tenant.name}")
            return cached_rules
        
        # Cache miss - fetch from database
        logger.debug(f"Cache MISS for geo rules: {tenant.name}")
        rules = list(
            GeographicRule.objects.filter(
                tenant=tenant,
                is_active=True
            )
        )
        
        # Store in cache
        cache.set(cache_key, rules, cls.CACHE_TTL)
        
        return rules
    
    @classmethod
    def invalidate_tenant_rules(cls, tenant):
        """Invalidate cached rules for tenant"""
        cache_key = f"{cls.RULES_PREFIX}:{tenant.id}"
        cache.delete(cache_key)
        logger.info(f"Invalidated rule cache for tenant: {tenant.name}")
    
    @classmethod
    def invalidate_waf_config(cls, tenant):
        """Invalidate cached WAF config for tenant"""
        cache_key = f"{cls.CONFIG_PREFIX}:{tenant.id}"
        cache.delete(cache_key)
        logger.info(f"Invalidated config cache for tenant: {tenant.name}")
    
    @classmethod
    def invalidate_geo_rules(cls, tenant):
        """Invalidate cached geo rules for tenant"""
        cache_key = f"{cls.GEO_RULES_PREFIX}:{tenant.id}"
        cache.delete(cache_key)
        logger.info(f"Invalidated geo rules cache for tenant: {tenant.name}")
    
    @classmethod
    def invalidate_all(cls, tenant):
        """Invalidate all caches for tenant"""
        cls.invalidate_tenant_rules(tenant)
        cls.invalidate_waf_config(tenant)
        cls.invalidate_geo_rules(tenant)
        logger.info(f"Invalidated all caches for tenant: {tenant.name}")
    
    @classmethod
    def clear_all_caches(cls):
        """Clear all tenant caches (useful for maintenance)"""
        # This is a nuclear option - use sparingly
        from waf_project.waf_core.models import Tenant
        for tenant in Tenant.objects.all():
            cls.invalidate_all(tenant)
        logger.warning("Cleared all tenant caches")
    
    @classmethod
    def get_cache_stats(cls, tenant):
        """Get cache statistics for monitoring"""
        stats = {
            'rules_cached': cache.get(f"{cls.RULES_PREFIX}:{tenant.id}") is not None,
            'config_cached': cache.get(f"{cls.CONFIG_PREFIX}:{tenant.id}") is not None,
            'geo_rules_cached': cache.get(f"{cls.GEO_RULES_PREFIX}:{tenant.id}") is not None,
        }
        return stats


# Signal handlers for automatic cache invalidation

@receiver(post_save, sender=TenantFirewallConfig)
@receiver(post_delete, sender=TenantFirewallConfig)
def invalidate_rules_cache(sender, instance, **kwargs):
    """Invalidate rules cache when TenantFirewallConfig changes"""
    TenantCacheManager.invalidate_tenant_rules(instance.tenant)


@receiver(post_save, sender=FirewallRule)
@receiver(post_delete, sender=FirewallRule)
def invalidate_rules_on_rule_change(sender, instance, **kwargs):
    """Invalidate all tenant caches when a FirewallRule changes"""
    # Since a rule can affect multiple tenants, invalidate all
    from waf_project.waf_core.models import Tenant
    for config in TenantFirewallConfig.objects.filter(rule=instance):
        TenantCacheManager.invalidate_tenant_rules(config.tenant)


@receiver(post_save, sender=WAFConfiguration)
@receiver(post_delete, sender=WAFConfiguration)
def invalidate_config_cache(sender, instance, **kwargs):
    """Invalidate config cache when WAFConfiguration changes"""
    TenantCacheManager.invalidate_waf_config(instance.tenant)


@receiver(post_save, sender=GeographicRule)
@receiver(post_delete, sender=GeographicRule)
def invalidate_geo_cache(sender, instance, **kwargs):
    """Invalidate geo rules cache when GeographicRule changes"""
    TenantCacheManager.invalidate_geo_rules(instance.tenant)
