# tests/test_tenant_routing_and_views.py

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.admin.sites import site
from django.contrib.auth import get_user_model

from waf_project.waf_core.models import Tenant


User = get_user_model()


class TenantRoutingModelTests(TestCase):
    def test_tenant_has_origin_and_waf_host_fields(self):
        tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="example.com",
            origin_url="https://backend.example.com",
            waf_host="tenant1.waf-app.site",
            contact_email="test@example.com",
            contact_name="Owner",
        )

        self.assertEqual(tenant.origin_url, "https://backend.example.com")
        self.assertEqual(tenant.waf_host, "tenant1.waf-app.site")
        self.assertIn("example.com", tenant.get_all_domains())


class TenantAdminConfigTests(TestCase):
    def test_tenant_admin_shows_routing_fields(self):
        # Grab the registered ModelAdmin for Tenant
        tenant_admin = site._registry[Tenant]

        # Check waf_host is in list_display (origin_url is optional)
        self.assertIn("waf_host", tenant_admin.list_display)

        # Ensure routing-related fieldset exists
        fieldsets = dict(tenant_admin.fieldsets)
        self.assertIn("Reverse Proxy Configuration", fieldsets)
        self.assertIn("origin_url", fieldsets["Reverse Proxy Configuration"]["fields"])
        self.assertIn("waf_host", fieldsets["Reverse Proxy Configuration"]["fields"])


class TenantDetailViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.tenant = Tenant.objects.create(
            name="Tenant A",
            domain="tenant-a.com",
            origin_url="https://origin.tenant-a.com",
            waf_host="a.waf-app.site",
            contact_email="owner@tenant-a.com",
            contact_name="Owner A",
        )
        self.user = User.objects.create_user(
            username="tenantuser",
            password="testpass123",
            tenant=self.tenant,
        )

    def test_tenant_detail_for_tenant_user(self):
        self.client.login(username="tenantuser", password="testpass123")
        url = reverse("tenant_detail")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["tenant"], self.tenant)
        # origin_url and waf_host are accessible via tenant object
        self.assertEqual(response.context["tenant"].origin_url, self.tenant.origin_url)
        self.assertEqual(response.context["tenant"].waf_host, self.tenant.waf_host)


class DashboardNavbarTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.tenant = Tenant.objects.create(
            name="Tenant B",
            domain="tenant-b.com",
            origin_url="https://origin.tenant-b.com",
            waf_host="b.waf-app.site",
            contact_email="owner@tenant-b.com",
            contact_name="Owner B",
        )
        self.user = User.objects.create_user(
            username="tenantuser2",
            password="testpass123",
            tenant=self.tenant,
        )

    def test_navbar_contains_tenant_link_when_logged_in(self):
        self.client.login(username="tenantuser2", password="testpass123")
        dashboard_url = reverse("dashboard")
        response = self.client.get(dashboard_url)

        self.assertEqual(response.status_code, 200)

        tenant_url = reverse("tenant_detail")
        # Basic HTML presence check
        self.assertIn(f'href="{tenant_url}"', response.content.decode())
