# waf_engine/tenant_middleware.py
from django.http import Http404
from django.db.models import Q
from waf_project.waf_core.models import Tenant
import logging

logger = logging.getLogger('waf_engine')


class TenantMiddleware:
    """
    Resolve the current Tenant based on the incoming Host header.

    Entry hosts that can map to a tenant:
      - tenant.waf-app.site         (Tenant.waf_host)
      - tenant-domain.com           (Tenant.domain)
      - any additional_domains      (Tenant.additional_domains via get_all_domains())

    This middleware MUST run before WAFMiddleware in MIDDLEWARE.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Prefer X-Forwarded-Host if you are behind a reverse proxy (Nginx)
        host_header = request.META.get('HTTP_X_FORWARDED_HOST') or request.get_host()

        # X-Forwarded-Host can contain multiple values -> take the first
        if ',' in host_header:
            host_header = host_header.split(',')[0].strip()

        host_header = host_header.strip()

        # Strip port if present (e.g. "tenant.waf-app.site:443")
        if ':' in host_header:
            host_no_port = host_header.split(':', 1)[0]
        else:
            host_no_port = host_header

        logger.debug(
            f"Tenant lookup - raw host: '{host_header}', normalized host: '{host_no_port}'"
        )

        tenant = None

        # 1) Try exact match on waf_host OR primary domain (normalized, no port)
        try:
            tenant = Tenant.objects.get(
                Q(waf_host=host_no_port) | Q(domain=host_no_port)
            )
            logger.debug(
                f"Found tenant by waf_host/domain match: {tenant.name} "
                f"(waf_host={tenant.waf_host}, domain={tenant.domain})"
            )
        except Tenant.DoesNotExist:
            tenant = None
        except Tenant.MultipleObjectsReturned:
            # Shouldn't happen if waf_host/domain are unique, but be defensive
            tenant = (
                Tenant.objects.filter(
                    Q(waf_host=host_no_port) | Q(domain=host_no_port)
                )
                .order_by('created_at')
                .first()
            )
            logger.warning(
                f"Multiple tenants matched host '{host_no_port}', picked first: {tenant.name}"
            )

        # 2) If still not found, try additional_domains (Python-side check via get_all_domains)
        if not tenant:
            candidates = Tenant.objects.filter(additional_domains__icontains=host_no_port)
            for t in candidates:
                if host_no_port in t.get_all_domains():
                    tenant = t
                    logger.debug(
                        f"Found tenant by additional_domains match: {tenant.name}"
                    )
                    break

        if tenant:
            request.tenant = tenant
        else:
            logger.warning(
                f"No tenant resolved for host '{host_header}' (normalized '{host_no_port}')"
            )
            request.tenant = None

        return self.get_response(request)
