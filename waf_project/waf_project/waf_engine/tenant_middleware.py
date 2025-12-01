# waf_engine/tenant_middleware.py
from django.http import Http404
from django.db.models import Q
from waf_project.waf_core.models import Tenant
import logging

logger = logging.getLogger('waf_engine')

class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # First, try to get the host from the X-Forwarded-Host header
        host = request.META.get('HTTP_X_FORWARDED_HOST')
        if not host:
            host = request.get_host()
            
        logger.debug(f"Tenant lookup for host: '{host}'")
        
        tenant = None
        
        # 1. Try exact match on primary domain
        try:
            tenant = Tenant.objects.get(domain=host)
            logger.debug(f"Found tenant by exact match: {tenant.name}")
        except Tenant.DoesNotExist:
            pass
            
        # 2. Try match on additional_domains
        if not tenant:
            # We use Q objects to search if the host is IN the additional_domains text field
            # This is a bit loose (substring match), but we can refine it
            # Better approach: Iterate or use a more specific query if possible. 
            # Given the model structure, we'll fetch all tenants and check python-side for safety/accuracy 
            # or use a regex filter if DB supports it. For now, let's try a safe python-side check 
            # for robustness, assuming low tenant count. If high count, we need a better model structure.
            # Optimization: Filter potential candidates first.
            
            potential_tenants = Tenant.objects.filter(additional_domains__icontains=host)
            for t in potential_tenants:
                domains = t.get_all_domains()
                if host in domains:
                    tenant = t
                    logger.debug(f"Found tenant by additional_domain match: {tenant.name}")
                    break

        # 3. Try without port if present
        if not tenant and ':' in host:
            domain_only = host.split(':')[0]
            logger.debug(f"Retrying lookup with domain only: '{domain_only}'")
            
            try:
                tenant = Tenant.objects.get(domain=domain_only)
                logger.debug(f"Found tenant by domain-only match: {tenant.name}")
            except Tenant.DoesNotExist:
                # Check additional domains for domain_only
                potential_tenants = Tenant.objects.filter(additional_domains__icontains=domain_only)
                for t in potential_tenants:
                    domains = t.get_all_domains()
                    if domain_only in domains:
                        tenant = t
                        logger.debug(f"Found tenant by additional_domain (no port) match: {tenant.name}")
                        break

        if tenant:
            request.tenant = tenant
        else:
            logger.warning(f"No tenant found for host '{host}'")
            request.tenant = None
        
        response = self.get_response(request)
        return response