"""
Optimized GeoIP management with in-memory database and caching.
Provides fast IP-to-country lookups for geo-blocking enforcement.
"""
import logging
import threading
from django.contrib.gis.geoip2 import GeoIP2, GeoIP2Exception
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger('waf_security')


class GeoIPManager:
    """
    Singleton manager for GeoIP lookups with in-memory database and caching.
    Thread-safe implementation for concurrent request handling.
    """
    
    _instance = None
    _lock = threading.Lock()
    _geoip = None
    _initialized = False
    
    # Cache settings
    CACHE_PREFIX = 'geoip'
    CACHE_TTL = getattr(settings, 'WAF_GEOIP_CACHE_TTL', 3600)  # 1 hour default
    
    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize GeoIP database (only once)"""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._initialize_geoip()
                    self._initialized = True
    
    def _initialize_geoip(self):
        """Load GeoIP database into memory"""
        try:
            self._geoip = GeoIP2()
            logger.info("GeoIP database loaded successfully into memory")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
            logger.warning("GeoIP lookups will fail until database is available")
            self._geoip = None
    
    @classmethod
    def get_instance(cls):
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def get_country_code(self, ip_address):
        """
        Get ISO country code for an IP address.
        Uses cache to reduce lookup overhead.
        
        Args:
            ip_address: IP address string
        
        Returns:
            str: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB') or None
        """
        if not ip_address:
            return None
        
        # Check cache first
        cache_key = f"{self.CACHE_PREFIX}:country:{ip_address}"
        cached_country = cache.get(cache_key)
        
        if cached_country is not None:
            logger.debug(f"GeoIP cache HIT for {ip_address}: {cached_country}")
            return cached_country if cached_country != 'UNKNOWN' else None
        
        # Cache miss - perform lookup
        logger.debug(f"GeoIP cache MISS for {ip_address}")
        country_code = self._lookup_country(ip_address)
        
        # Cache the result (cache 'UNKNOWN' to prevent repeated failed lookups)
        cache_value = country_code if country_code else 'UNKNOWN'
        cache.set(cache_key, cache_value, self.CACHE_TTL)
        
        return country_code
    
    def get_country_info(self, ip_address):
        """
        Get detailed country information for an IP address.
        
        Args:
            ip_address: IP address string
        
        Returns:
            dict: {
                'country_code': str,
                'country_name': str,
                'continent_code': str,
                'continent_name': str
            } or None
        """
        if not ip_address:
            return None
        
        # Check cache
        cache_key = f"{self.CACHE_PREFIX}:info:{ip_address}"
        cached_info = cache.get(cache_key)
        
        if cached_info is not None:
            logger.debug(f"GeoIP info cache HIT for {ip_address}")
            return cached_info if cached_info != 'UNKNOWN' else None
        
        # Cache miss - perform lookup
        logger.debug(f"GeoIP info cache MISS for {ip_address}")
        info = self._lookup_country_info(ip_address)
        
        # Cache the result
        cache_value = info if info else 'UNKNOWN'
        cache.set(cache_key, cache_value, self.CACHE_TTL)
        
        return info
    
    def _lookup_country(self, ip_address):
        """Perform actual GeoIP country lookup"""
        if not self._geoip:
            logger.warning("GeoIP database not available")
            return None
        
        try:
            result = self._geoip.country(ip_address)
            country_code = result.get('country_code')
            
            if country_code:
                logger.debug(f"GeoIP lookup: {ip_address} -> {country_code}")
            else:
                logger.debug(f"GeoIP lookup: {ip_address} -> No country found")
            
            return country_code
        except GeoIP2Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in GeoIP lookup for {ip_address}: {e}")
            return None
    
    def _lookup_country_info(self, ip_address):
        """Perform actual GeoIP country info lookup"""
        if not self._geoip:
            logger.warning("GeoIP database not available")
            return None
        
        try:
            result = self._geoip.country(ip_address)
            
            if result:
                info = {
                    'country_code': result.get('country_code'),
                    'country_name': result.get('country_name'),
                    'continent_code': result.get('continent_code'),
                    'continent_name': result.get('continent_name'),
                }
                logger.debug(f"GeoIP info lookup: {ip_address} -> {info}")
                return info
            
            return None
        except GeoIP2Exception as e:
            logger.debug(f"GeoIP info lookup failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in GeoIP info lookup for {ip_address}: {e}")
            return None
    
    def is_country_blocked(self, tenant, ip_address):
        """
        Check if IP's country is blocked for tenant.
        
        Args:
            tenant: Tenant object
            ip_address: IP address string
        
        Returns:
            tuple: (is_blocked, country_code, country_name)
        """
        # Get country code
        country_code = self.get_country_code(ip_address)
        
        if not country_code:
            # Can't determine country - allow by default (or configure to block)
            allow_unknown = getattr(settings, 'WAF_GEOIP_ALLOW_UNKNOWN', True)
            if not allow_unknown:
                logger.warning(f"Blocking unknown country for IP {ip_address}")
                return True, None, 'Unknown'
            return False, None, 'Unknown'
        
        # Check if country is blocked for this tenant
        from waf_project.waf_core.models import GeographicRule
        
        blocked_rule = GeographicRule.objects.filter(
            tenant=tenant,
            country_code=country_code,
            action='block',
            is_active=True
        ).first()
        
        if blocked_rule:
            logger.info(
                f"Country {country_code} is blocked for tenant {tenant.name}, "
                f"IP {ip_address}"
            )
            return True, country_code, blocked_rule.country_name
        
        return False, country_code, None
    
    def clear_cache(self, ip_address=None):
        """
        Clear GeoIP cache.
        
        Args:
            ip_address: Specific IP to clear, or None to clear all
        """
        if ip_address:
            cache.delete(f"{self.CACHE_PREFIX}:country:{ip_address}")
            cache.delete(f"{self.CACHE_PREFIX}:info:{ip_address}")
            logger.info(f"Cleared GeoIP cache for {ip_address}")
        else:
            # Clear all GeoIP cache entries (requires cache backend support)
            logger.warning("Clearing all GeoIP cache entries")
            # This is a simplified approach - in production, use cache.delete_pattern
            # or implement a more sophisticated cache key tracking system
    
    def reload_database(self):
        """Reload GeoIP database (useful after updates)"""
        with self._lock:
            logger.info("Reloading GeoIP database...")
            self._initialize_geoip()
            self.clear_cache()
            logger.info("GeoIP database reloaded successfully")
    
    def get_stats(self):
        """Get GeoIP manager statistics"""
        return {
            'initialized': self._initialized,
            'database_available': self._geoip is not None,
            'cache_ttl': self.CACHE_TTL,
        }
    
    @classmethod
    def reset_instance(cls):
        """Reset singleton instance (useful for testing)"""
        with cls._lock:
            cls._instance = None
            cls._initialized = False
            cls._geoip = None
