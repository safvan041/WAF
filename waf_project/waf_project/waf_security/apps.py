from django.apps import AppConfig


class WafSecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'waf_project.waf_security'
    verbose_name = 'WAF Advanced Security'
    
    def ready(self):
        """Initialize app components when Django starts"""
        # Import signals to register cache invalidation handlers
        try:
            from . import signals
        except ImportError:
            pass
        
        # Initialize GeoIP manager on startup for in-memory database loading
        try:
            from .geoip_manager import GeoIPManager
            GeoIPManager.get_instance()
        except Exception as e:
            import logging
            logger = logging.getLogger('waf_security')
            logger.warning(f"Failed to initialize GeoIP manager: {e}")
