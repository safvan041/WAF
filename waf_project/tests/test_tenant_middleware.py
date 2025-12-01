# tests/test_tenant_middleware.py

from django.test import TestCase, RequestFactory
from django.http import HttpResponse

from waf_project.waf_core.models import Tenant
from waf_project.waf_engine.tenant_middleware import TenantMiddleware

class TenantMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = lambda r: HttpResponse("OK")

        self.tenant_main = Tenant.objects.create(
            name="MainTenant",
            domain="maintenant.com",
            origin_url="https://origin.maintenant.com",
            waf_host="main.waf-app.site",
            contact_email="main@example.com",
            contact_name="Main Owner",
        )

        self.tenant_alias = Tenant.objects.create(
            name="AliasTenant",
            domain="aliastenant.com",
            origin_url="https://origin.aliastenant.com",
            waf_host="alias.waf-app.site",
            contact_email="alias@example.com",
            contact_name="Alias Owner",
            additional_domains="alias.example.com\nother-alias.example.com",
        )

        self.middleware = TenantMiddleware(self.get_response)

    def _request(self, host):
        request = self.factory.get("/")
        # Simulate proxy headers and direct host
        request.META["HTTP_HOST"] = host
        request.META["HTTP_X_FORWARDED_HOST"] = host
        response = self.middleware(request)
        return request, response

    def test_resolves_by_waf_host(self):
        request, _ = self._request("main.waf-app.site")
        self.assertIsNotNone(getattr(request, "tenant", None))
        self.assertEqual(request.tenant, self.tenant_main)

    def test_resolves_by_waf_host_with_port(self):
        request, _ = self._request("main.waf-app.site:443")
        self.assertIsNotNone(getattr(request, "tenant", None))
        self.assertEqual(request.tenant, self.tenant_main)

    def test_resolves_by_primary_domain(self):
        request, _ = self._request("maintenant.com")
        self.assertEqual(request.tenant, self.tenant_main)

    def test_resolves_by_additional_domain(self):
        request, _ = self._request("alias.example.com")
        self.assertEqual(request.tenant, self.tenant_alias)

    def test_no_tenant_found_sets_tenant_none(self):
        request, _ = self._request("unknown-domain.com")
        self.assertIsNone(getattr(request, "tenant", None))
