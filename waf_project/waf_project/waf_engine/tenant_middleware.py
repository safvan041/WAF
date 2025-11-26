# waf_engine/tenant_middleware.py
from django.http import Http404
from waf_project.waf_core.models import Tenant

class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # First, try to get the host from the X-Forwarded-Host header
        host = request.META.get('HTTP_X_FORWARDED_HOST')
        if not host:
            host = request.get_host()
            
        print(f"DEBUG: Tenant lookup for host: '{host}'")
        
        try:
            # Try exact match first
            request.tenant = Tenant.objects.get(domain=host)
            print(f"DEBUG: Found tenant by exact match: {request.tenant.name}")
        except Tenant.DoesNotExist:
            # Try without port if present
            if ':' in host:
                domain_only = host.split(':')[0]
                try:
                    request.tenant = Tenant.objects.get(domain=domain_only)
                    print(f"DEBUG: Found tenant by domain-only match: {request.tenant.name}")
                except Tenant.DoesNotExist:
                    print(f"DEBUG: No tenant found for domain '{domain_only}'")
                    request.tenant = None
            else:
                print(f"DEBUG: No tenant found for host '{host}'")
                request.tenant = None
        
        response = self.get_response(request)
        return response