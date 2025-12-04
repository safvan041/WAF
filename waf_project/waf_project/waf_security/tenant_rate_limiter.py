"""
Tenant-isolated rate limiting system.
Each tenant has independent rate limits tracked via Django cache.
"""
import logging
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import RateLimitConfig, IPWhitelist
from .models import RateLimitViolation

logger = logging.getLogger('waf_security')


class TenantRateLimiter:
    """
    Implements per-tenant rate limiting with multiple time windows.
    Uses sliding window algorithm for accurate rate limiting.
    """
    
    # Cache key prefixes for tenant isolation
    CACHE_PREFIX = 'rate_limit'
    
    # Default rate limits (can be overridden per tenant)
    DEFAULT_LIMITS = {
        'requests_per_minute': 60,
        'requests_per_hour': 1000,
        'requests_per_day': 10000,
        'per_ip_requests_per_minute': 10,
        'per_ip_requests_per_hour': 100,
    }
    
    @classmethod
    def check_rate_limit(cls, tenant, ip_address, request=None):
        """
        Check if request should be rate limited.
        
        Args:
            tenant: Tenant object
            ip_address: Client IP address
            request: Django request object (optional, for logging)
        
        Returns:
            tuple: (is_allowed, limit_type, current_count, limit_value)
        """
        # Check if IP is whitelisted (bypass rate limits)
        if cls._is_whitelisted(tenant, ip_address):
            logger.debug(f"IP {ip_address} is whitelisted for tenant {tenant.name}, bypassing rate limits")
            return True, None, 0, 0
        
        # Get tenant-specific rate limit config
        config = cls._get_rate_limit_config(tenant)
        
        # Check each rate limit window
        checks = [
            ('per_minute', config['requests_per_minute'], 60),
            ('per_hour', config['requests_per_hour'], 3600),
            ('per_day', config['requests_per_day'], 86400),
            ('per_ip_minute', config['per_ip_requests_per_minute'], 60, ip_address),
            ('per_ip_hour', config['per_ip_requests_per_hour'], 3600, ip_address),
        ]
        
        for check in checks:
            limit_type = check[0]
            limit_value = check[1]
            window_seconds = check[2]
            check_ip = check[3] if len(check) > 3 else None
            
            current_count = cls._get_request_count(tenant, limit_type, window_seconds, check_ip)
            
            if current_count >= limit_value:
                # Rate limit exceeded
                logger.warning(
                    f"Rate limit exceeded for tenant {tenant.name}, "
                    f"IP {ip_address}, type {limit_type}: {current_count}/{limit_value}"
                )
                
                # Log violation
                cls._log_violation(tenant, ip_address, limit_type, limit_value, current_count, request)
                
                return False, limit_type, current_count, limit_value
        
        # All checks passed, increment counters
        cls._increment_counters(tenant, ip_address)
        
        return True, None, 0, 0
    
    @classmethod
    def _get_rate_limit_config(cls, tenant):
        """Get rate limit configuration for tenant"""
        try:
            config = RateLimitConfig.objects.get(tenant=tenant)
            return {
                'requests_per_minute': config.requests_per_minute,
                'requests_per_hour': config.requests_per_hour,
                'requests_per_day': config.requests_per_day,
                'per_ip_requests_per_minute': config.per_ip_requests_per_minute,
                'per_ip_requests_per_hour': config.per_ip_requests_per_hour,
            }
        except RateLimitConfig.DoesNotExist:
            logger.debug(f"No rate limit config for tenant {tenant.name}, using defaults")
            return cls.DEFAULT_LIMITS
    
    @classmethod
    def _is_whitelisted(cls, tenant, ip_address):
        """Check if IP is whitelisted for this tenant"""
        try:
            config = RateLimitConfig.objects.get(tenant=tenant)
            if not config.whitelist_bypass:
                return False
        except RateLimitConfig.DoesNotExist:
            pass
        
        return IPWhitelist.objects.filter(
            tenant=tenant,
            ip_address=ip_address,
            is_active=True
        ).exists()
    
    @classmethod
    def _get_cache_key(cls, tenant, limit_type, ip_address=None):
        """Generate cache key for rate limit tracking"""
        if ip_address:
            return f"{cls.CACHE_PREFIX}:{tenant.id}:{limit_type}:{ip_address}"
        return f"{cls.CACHE_PREFIX}:{tenant.id}:{limit_type}"
    
    @classmethod
    def _get_request_count(cls, tenant, limit_type, window_seconds, ip_address=None):
        """Get current request count for the time window"""
        cache_key = cls._get_cache_key(tenant, limit_type, ip_address)
        count = cache.get(cache_key, 0)
        return count
    
    @classmethod
    def _increment_counters(cls, tenant, ip_address):
        """Increment all rate limit counters"""
        counters = [
            ('per_minute', 60, None),
            ('per_hour', 3600, None),
            ('per_day', 86400, None),
            ('per_ip_minute', 60, ip_address),
            ('per_ip_hour', 3600, ip_address),
        ]
        
        for limit_type, window_seconds, check_ip in counters:
            cache_key = cls._get_cache_key(tenant, limit_type, check_ip)
            
            # Get current count
            current = cache.get(cache_key, 0)
            
            # Increment and set with TTL
            cache.set(cache_key, current + 1, window_seconds)
    
    @classmethod
    def _log_violation(cls, tenant, ip_address, limit_type, limit_value, current_count, request):
        """Log rate limit violation"""
        try:
            RateLimitViolation.objects.create(
                tenant=tenant,
                ip_address=ip_address,
                request_path=request.path if request else '/',
                request_method=request.method if request else 'UNKNOWN',
                user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
                limit_type=limit_type,
                limit_value=limit_value,
                current_count=current_count,
            )
        except Exception as e:
            logger.error(f"Failed to log rate limit violation: {e}")
    
    @classmethod
    def reset_limits(cls, tenant, ip_address=None):
        """Reset rate limits for tenant or specific IP (useful for testing)"""
        if ip_address:
            # Reset for specific IP
            for limit_type in ['per_ip_minute', 'per_ip_hour']:
                cache_key = cls._get_cache_key(tenant, limit_type, ip_address)
                cache.delete(cache_key)
            logger.info(f"Reset rate limits for IP {ip_address} on tenant {tenant.name}")
        else:
            # Reset all tenant limits
            for limit_type in ['per_minute', 'per_hour', 'per_day']:
                cache_key = cls._get_cache_key(tenant, limit_type)
                cache.delete(cache_key)
            logger.info(f"Reset all rate limits for tenant {tenant.name}")
    
    @classmethod
    def get_current_usage(cls, tenant, ip_address=None):
        """Get current rate limit usage for monitoring/dashboard"""
        config = cls._get_rate_limit_config(tenant)
        
        usage = {
            'per_minute': {
                'current': cls._get_request_count(tenant, 'per_minute', 60),
                'limit': config['requests_per_minute'],
            },
            'per_hour': {
                'current': cls._get_request_count(tenant, 'per_hour', 3600),
                'limit': config['requests_per_hour'],
            },
            'per_day': {
                'current': cls._get_request_count(tenant, 'per_day', 86400),
                'limit': config['requests_per_day'],
            },
        }
        
        if ip_address:
            usage['per_ip_minute'] = {
                'current': cls._get_request_count(tenant, 'per_ip_minute', 60, ip_address),
                'limit': config['per_ip_requests_per_minute'],
            }
            usage['per_ip_hour'] = {
                'current': cls._get_request_count(tenant, 'per_ip_hour', 3600, ip_address),
                'limit': config['per_ip_requests_per_hour'],
            }
        
        return usage
