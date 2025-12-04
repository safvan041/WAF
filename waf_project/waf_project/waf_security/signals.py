# waf_security/signals.py
"""
Django signals for cache invalidation.
Imported by apps.py to register signal handlers.
"""

# Import signal handlers from cache manager
from .tenant_cache_manager import (
    invalidate_rules_cache,
    invalidate_rules_on_rule_change,
    invalidate_config_cache,
    invalidate_geo_cache,
)

# Signal handlers are automatically registered when imported
