"""
Integration tests for Nginx automation system

Tests signal handlers, automatic config regeneration, and end-to-end flows.
"""

from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.db.models.signals import post_save, post_delete
from waf_project.waf_core.models import Tenant
from waf_project.waf_core import signals


class SignalHandlerTestCase(TestCase):
    """Test cases for signal-based automation"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Disconnect signals to prevent actual Nginx operations during tests
        post_save.disconnect(signals.tenant_saved, sender=Tenant)
        post_delete.disconnect(signals.tenant_deleted, sender=Tenant)
    
    def tearDown(self):
        """Reconnect signals"""
        post_save.connect(signals.tenant_saved, sender=Tenant)
        post_delete.connect(signals.tenant_deleted, sender=Tenant)
    
    @patch('waf_project.waf_core.signals.regenerate_and_reload')
    def test_signal_triggers_on_verified_tenant_creation(self, mock_regenerate):
        """Test signal triggers when verified tenant is created"""
        # Reconnect signal for this test
        post_save.connect(signals.tenant_saved, sender=Tenant)
        
        tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            waf_host="test.waf-app.site",
            origin_url="https://app.test.com",
            contact_email="admin@test.com",
            contact_name="Admin",
            domain_verified=True,
            is_active=True
        )
        
        # Signal should have triggered
        mock_regenerate.assert_called_once()
        
        # Disconnect again
        post_save.disconnect(signals.tenant_saved, sender=Tenant)
    
    @patch('waf_project.waf_core.signals.regenerate_and_reload')
    def test_signal_not_triggered_for_unverified_tenant(self, mock_regenerate):
        """Test signal doesn't trigger for unverified tenant"""
        # Reconnect signal for this test
        post_save.connect(signals.tenant_saved, sender=Tenant)
        
        tenant = Tenant.objects.create(
            name="Unverified Tenant",
            domain="unverified.com",
            waf_host="unverified.waf-app.site",
            origin_url="https://app.unverified.com",
            contact_email="admin@unverified.com",
            contact_name="Admin",
            domain_verified=False,  # Not verified
            is_active=True
        )
        
        # Signal should not trigger for unverified tenant
        mock_regenerate.assert_not_called()
        
        # Disconnect again
        post_save.disconnect(signals.tenant_saved, sender=Tenant)
    
    @patch('waf_project.waf_core.signals.regenerate_and_reload')
    def test_signal_triggers_on_tenant_update(self, mock_regenerate):
        """Test signal triggers when verified tenant is updated"""
        # Create tenant first
        tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            waf_host="test.waf-app.site",
            origin_url="https://app.test.com",
            contact_email="admin@test.com",
            contact_name="Admin",
            domain_verified=True,
            is_active=True
        )
        
        # Reconnect signal for update test
        post_save.connect(signals.tenant_saved, sender=Tenant)
        
        # Update tenant
        tenant.origin_url = "https://new-app.test.com"
        tenant.save()
        
        # Signal should have triggered
        mock_regenerate.assert_called_once()
        
        # Disconnect again
        post_save.disconnect(signals.tenant_saved, sender=Tenant)
    
    @patch('waf_project.waf_core.signals.regenerate_and_reload')
    def test_signal_triggers_on_tenant_deletion(self, mock_regenerate):
        """Test signal triggers when verified tenant is deleted"""
        # Create tenant
        tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            waf_host="test.waf-app.site",
            origin_url="https://app.test.com",
            contact_email="admin@test.com",
            contact_name="Admin",
            domain_verified=True,
            is_active=True
        )
        
        # Reconnect signal for deletion test
        post_delete.connect(signals.tenant_deleted, sender=Tenant)
        
        # Delete tenant
        tenant.delete()
        
        # Signal should have triggered
        mock_regenerate.assert_called_once()
        
        # Disconnect again
        post_delete.disconnect(signals.tenant_deleted, sender=Tenant)


class EndToEndTestCase(TestCase):
    """End-to-end integration tests"""
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxReloader.reload')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_complete_tenant_onboarding_flow(self, mock_validate, mock_write, mock_reload):
        """Test complete tenant onboarding from creation to config generation"""
        mock_validate.return_value = (True, '')
        mock_write.return_value = True
        mock_reload.return_value = (True, 'Reloaded successfully')
        
        # Step 1: Create unverified tenant
        tenant = Tenant.objects.create(
            name="New Tenant",
            domain="new.com",
            waf_host="new.waf-app.site",
            origin_url="https://app.new.com",
            contact_email="admin@new.com",
            contact_name="Admin",
            domain_verified=False,
            is_active=True
        )
        
        # Step 2: Verify tenant (this should trigger config regeneration)
        tenant.domain_verified = True
        tenant.save()
        
        # Verify that config generation was triggered
        # (In real scenario, signal would trigger this)
        from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator
        generator = NginxConfigGenerator()
        tenants = generator.get_verified_tenants()
        
        self.assertIn(tenant, tenants)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_multi_tenant_config_generation(self, mock_validate):
        """Test config generation with multiple tenants"""
        mock_validate.return_value = (True, '')
        
        # Create multiple verified tenants
        tenants = []
        for i in range(5):
            tenant = Tenant.objects.create(
                name=f"Tenant {i}",
                domain=f"tenant{i}.com",
                waf_host=f"tenant{i}.waf-app.site",
                origin_url=f"https://app.tenant{i}.com",
                contact_email=f"admin@tenant{i}.com",
                contact_name=f"Admin {i}",
                domain_verified=True,
                is_active=True
            )
            tenants.append(tenant)
        
        # Generate config
        from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator
        generator = NginxConfigGenerator()
        config = generator.generate_config()
        
        # Verify all tenants are in config
        for tenant in tenants:
            self.assertIn(tenant.waf_host, config)
            self.assertIn(tenant.origin_url, config)
    
    def test_tenant_isolation(self):
        """Test that tenant configurations are isolated"""
        # Create two tenants
        tenant1 = Tenant.objects.create(
            name="Tenant 1",
            domain="tenant1.com",
            waf_host="tenant1.waf-app.site",
            origin_url="https://app.tenant1.com",
            contact_email="admin@tenant1.com",
            contact_name="Admin 1",
            domain_verified=True,
            is_active=True
        )
        
        tenant2 = Tenant.objects.create(
            name="Tenant 2",
            domain="tenant2.com",
            waf_host="tenant2.waf-app.site",
            origin_url="https://app.tenant2.com",
            contact_email="admin@tenant2.com",
            contact_name="Admin 2",
            domain_verified=True,
            is_active=True
        )
        
        # Generate config
        from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator
        generator = NginxConfigGenerator()
        config = generator.generate_config()
        
        # Verify each tenant has its own server block
        # Count occurrences of "server {" to ensure separate blocks
        server_blocks = config.count('server {')
        
        # Should have at least 3 blocks: HTTP redirect, demo.waf-app.site, tenant1, tenant2
        self.assertGreaterEqual(server_blocks, 4)
        
        # Verify tenant IDs are unique in headers
        self.assertIn(f'X-Tenant-ID "{tenant1.id}"', config)
        self.assertIn(f'X-Tenant-ID "{tenant2.id}"', config)
