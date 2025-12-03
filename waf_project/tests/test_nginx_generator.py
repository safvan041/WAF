"""
Unit tests for Nginx Config Generator

Tests the NginxConfigGenerator and NginxReloader classes.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.conf import settings
from waf_project.waf_core.models import Tenant
from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator, NginxReloader


class NginxConfigGeneratorTestCase(TestCase):
    """Test cases for NginxConfigGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create test tenants
        self.tenant1 = Tenant.objects.create(
            name="Test Tenant 1",
            domain="test1.com",
            waf_host="test1.waf-app.site",
            origin_url="https://app.test1.com",
            contact_email="admin@test1.com",
            contact_name="Admin 1",
            domain_verified=True,
            is_active=True
        )
        
        self.tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            domain="test2.com",
            waf_host="test2.waf-app.site",
            origin_url="https://app.test2.com",
            contact_email="admin@test2.com",
            contact_name="Admin 2",
            domain_verified=True,
            is_active=True
        )
        
        # Create unverified tenant (should be excluded)
        self.unverified_tenant = Tenant.objects.create(
            name="Unverified Tenant",
            domain="unverified.com",
            waf_host="unverified.waf-app.site",
            origin_url="https://app.unverified.com",
            contact_email="admin@unverified.com",
            contact_name="Admin Unverified",
            domain_verified=False,
            is_active=True
        )
        
        # Create tenant without waf_host (should be excluded)
        self.incomplete_tenant = Tenant.objects.create(
            name="Incomplete Tenant",
            domain="incomplete.com",
            waf_host="",
            origin_url="https://app.incomplete.com",
            contact_email="admin@incomplete.com",
            contact_name="Admin Incomplete",
            domain_verified=True,
            is_active=True
        )
        
        # Use temp directory for test output
        self.temp_dir = tempfile.mkdtemp()
        self.test_output_path = os.path.join(self.temp_dir, 'test_nginx.conf')
        
    def tearDown(self):
        """Clean up test fixtures"""
        # Clean up temp files
        if os.path.exists(self.test_output_path):
            os.remove(self.test_output_path)
        os.rmdir(self.temp_dir)
    
    def test_get_verified_tenants(self):
        """Test fetching verified tenants"""
        generator = NginxConfigGenerator()
        tenants = generator.get_verified_tenants()
        
        # Should return only verified, active tenants with waf_host and origin_url
        self.assertEqual(len(tenants), 2)
        self.assertIn(self.tenant1, tenants)
        self.assertIn(self.tenant2, tenants)
        self.assertNotIn(self.unverified_tenant, tenants)
        self.assertNotIn(self.incomplete_tenant, tenants)
    
    def test_generate_config(self):
        """Test config generation"""
        generator = NginxConfigGenerator()
        config = generator.generate_config()
        
        # Check that config contains expected content
        self.assertIn('upstream waf_app', config)
        self.assertIn('server_name test1.waf-app.site', config)
        self.assertIn('server_name test2.waf-app.site', config)
        self.assertIn('proxy_pass https://app.test1.com', config)
        self.assertIn('proxy_pass https://app.test2.com', config)
        self.assertIn('ssl_certificate /etc/letsencrypt/live/waf-app.site/fullchain.pem', config)
        
        # Check that unverified tenant is not included
        self.assertNotIn('unverified.waf-app.site', config)
    
    def test_generate_config_with_specific_tenants(self):
        """Test config generation with specific tenant list"""
        generator = NginxConfigGenerator()
        config = generator.generate_config(tenants=[self.tenant1])
        
        # Should only include tenant1
        self.assertIn('test1.waf-app.site', config)
        self.assertNotIn('test2.waf-app.site', config)
    
    def test_generate_config_empty_tenants(self):
        """Test config generation with no tenants"""
        generator = NginxConfigGenerator()
        config = generator.generate_config(tenants=[])
        
        # Should still have base config
        self.assertIn('upstream waf_app', config)
        self.assertIn('server_name demo.waf-app.site', config)
    
    @patch('subprocess.run')
    def test_validate_config_success(self, mock_run):
        """Test successful config validation"""
        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='syntax is ok')
        
        generator = NginxConfigGenerator(output_path=self.test_output_path)
        is_valid, error_msg = generator.validate_config()
        
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, '')
    
    @patch('subprocess.run')
    def test_validate_config_failure(self, mock_run):
        """Test failed config validation"""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr='nginx: [emerg] invalid syntax',
            stdout=''
        )
        
        generator = NginxConfigGenerator(output_path=self.test_output_path)
        is_valid, error_msg = generator.validate_config()
        
        self.assertFalse(is_valid)
        self.assertIn('invalid syntax', error_msg)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_write_config(self, mock_validate):
        """Test writing config to file"""
        mock_validate.return_value = (True, '')
        
        generator = NginxConfigGenerator(output_path=self.test_output_path)
        config_content = "# Test config\nupstream waf_app { server web:8000; }"
        
        success = generator.write_config(config_content, validate=True)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.test_output_path))
        
        # Verify content
        with open(self.test_output_path, 'r') as f:
            written_content = f.read()
        self.assertEqual(written_content, config_content)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_write_config_validation_failure(self, mock_validate):
        """Test write config fails when validation fails"""
        mock_validate.return_value = (False, 'Validation error')
        
        generator = NginxConfigGenerator(output_path=self.test_output_path)
        config_content = "# Invalid config"
        
        success = generator.write_config(config_content, validate=True)
        
        self.assertFalse(success)
        self.assertFalse(os.path.exists(self.test_output_path))
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    def test_generate_and_write(self, mock_write, mock_validate):
        """Test complete generate and write workflow"""
        mock_validate.return_value = (True, '')
        mock_write.return_value = True
        
        generator = NginxConfigGenerator(output_path=self.test_output_path)
        result = generator.generate_and_write(validate=True)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['tenant_count'], 2)
        self.assertEqual(result['output_path'], self.test_output_path)
        self.assertTrue(result['validated'])


class NginxReloaderTestCase(TestCase):
    """Test cases for NginxReloader"""
    
    @patch('subprocess.run')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_reload_success(self, mock_validate, mock_run):
        """Test successful Nginx reload"""
        mock_validate.return_value = (True, '')
        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='')
        
        success, message = NginxReloader.reload()
        
        self.assertTrue(success)
        self.assertIn('successfully', message)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_reload_validation_failure(self, mock_validate):
        """Test reload fails when validation fails"""
        mock_validate.return_value = (False, 'Invalid config')
        
        success, message = NginxReloader.reload()
        
        self.assertFalse(success)
        self.assertIn('validation failed', message)
    
    @patch('subprocess.run')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_reload_command_failure(self, mock_validate, mock_run):
        """Test reload fails when command fails"""
        mock_validate.return_value = (True, '')
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr='reload failed',
            stdout=''
        )
        
        success, message = NginxReloader.reload()
        
        self.assertFalse(success)
        self.assertIn('failed', message)
