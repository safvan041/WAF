# waf_engine/tenant_middleware.py
from django.http import Http404
from waf_project.waf_core.models import Tenant

class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # First, try to get the host from the X-Forwarded-Host header, which is common in proxies.
        host = request.META.get('HTTP_X_FORWARDED_HOST')
        if not host:
            # If that's not available, fall back to the standard Host header.
            host = request.get_host().split(':')[0]
        
        try:
            request.tenant = Tenant.objects.get(domain=host)
        except Tenant.DoesNotExist:
            request.tenant = None # No tenant found for this domain
        
        response = self.get_response(request)
        return response