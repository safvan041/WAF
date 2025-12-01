# tests/test_middleware_order.py

from django.test import SimpleTestCase
from django.conf import settings


class MiddlewareOrderTests(SimpleTestCase):
    def test_tenant_before_waf_middleware(self):
        mw = list(settings.MIDDLEWARE)
        tenant_mw = "waf_project.waf_engine.tenant_middleware.TenantMiddleware"
        waf_mw = "waf_project.waf_engine.middleware.WAFMiddleware"

        self.assertIn(tenant_mw, mw)
        self.assertIn(waf_mw, mw)
        self.assertLess(mw.index(tenant_mw), mw.index(waf_mw))
