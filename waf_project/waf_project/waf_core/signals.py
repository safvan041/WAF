"""
Signal handlers for automatic Nginx configuration regeneration.
"""

import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.conf import settings
from waf_project.waf_core.models import Tenant

logger = logging.getLogger(__name__)


def should_regenerate_nginx_config():
    """Check if automatic Nginx config regeneration is enabled."""
    return getattr(settings, 'NGINX_AUTO_RELOAD', True)


def regenerate_and_reload():
    """Regenerate Nginx config and reload if enabled."""
    if not should_regenerate_nginx_config():
        logger.info("Nginx auto-reload is disabled, skipping config regeneration")
        return
    
    try:
        from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator, NginxReloader
        
        # Generate new config
        generator = NginxConfigGenerator()
        result = generator.generate_and_write(validate=True)
        
        if result['success']:
            logger.info(
                f"Nginx config regenerated successfully with {result['tenant_count']} tenant(s)"
            )
            
            # Reload Nginx
            success, message = NginxReloader.reload()
            if success:
                logger.info(f"Nginx reloaded successfully: {message}")
            else:
                logger.error(f"Failed to reload Nginx: {message}")
        else:
            error = result.get('error', 'Unknown error')
            logger.error(f"Failed to regenerate Nginx config: {error}")
            
    except Exception as e:
        logger.error(f"Error in regenerate_and_reload: {e}", exc_info=True)


@receiver(post_save, sender=Tenant)
def tenant_saved(sender, instance, created, **kwargs):
    """
    Handle Tenant save events.
    Regenerate Nginx config when:
    - A tenant is verified (domain_verified changes to True)
    - waf_host or origin_url changes for a verified tenant
    """
    # Check if this is a verified tenant with required fields
    if not instance.domain_verified or not instance.is_active:
        logger.debug(f"Tenant {instance.name} not verified or inactive, skipping config regen")
        return
    
    if not instance.waf_host or not instance.origin_url:
        logger.debug(f"Tenant {instance.name} missing waf_host or origin_url, skipping config regen")
        return
    
    # For new tenants, always regenerate
    if created:
        logger.info(f"New verified tenant created: {instance.name}, regenerating Nginx config")
        regenerate_and_reload()
        return
    
    # For updates, check if relevant fields changed
    # We need to track previous values to detect changes
    # Django doesn't provide this by default, so we'll regenerate on any save of verified tenants
    logger.info(f"Verified tenant updated: {instance.name}, regenerating Nginx config")
    regenerate_and_reload()


@receiver(post_delete, sender=Tenant)
def tenant_deleted(sender, instance, **kwargs):
    """
    Handle Tenant deletion.
    Regenerate Nginx config to remove the deleted tenant's server block.
    """
    if instance.domain_verified and instance.waf_host:
        logger.info(f"Verified tenant deleted: {instance.name}, regenerating Nginx config")
        regenerate_and_reload()
