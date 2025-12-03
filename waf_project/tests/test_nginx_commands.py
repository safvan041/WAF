"""
Management command tests for Nginx automation

Tests the generate_nginx_config and reload_nginx management commands.
"""

from io import StringIO
from unittest.mock import patch, MagicMock
from django.core.management import call_command
from django.test import TestCase
from waf_project.waf_core.models import Tenant


class GenerateNginxConfigCommandTestCase(TestCase):
    """Test cases for generate_nginx_config management command"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            waf_host="test.waf-app.site",
            origin_url="https://app.test.com",
            contact_email="admin@test.com",
            contact_name="Admin",
            domain_verified=True,
            is_active=True
        )
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_generate_config_command(self, mock_validate, mock_write):
        """Test basic config generation command"""
        mock_validate.return_value = (True, '')
        mock_write.return_value = True
        
        out = StringIO()
        call_command('generate_nginx_config', stdout=out)
        
        output = out.getvalue()
        self.assertIn('Found 1 verified tenant', output)
        self.assertIn('Test Tenant', output)
        self.assertIn('Successfully wrote Nginx config', output)
    
    def test_generate_config_dry_run(self):
        """Test dry-run mode"""
        out = StringIO()
        call_command('generate_nginx_config', '--dry-run', stdout=out)
        
        output = out.getvalue()
        self.assertIn('DRY RUN MODE', output)
        self.assertIn('Found 1 verified tenant', output)
        self.assertIn('upstream waf_app', output)
        self.assertIn('test.waf-app.site', output)
    
    def test_generate_config_no_tenants(self):
        """Test command with no verified tenants"""
        # Delete the tenant
        self.tenant.delete()
        
        out = StringIO()
        call_command('generate_nginx_config', '--dry-run', stdout=out)
        
        output = out.getvalue()
        self.assertIn('No verified tenants found', output)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxReloader.reload')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_generate_config_with_reload(self, mock_validate, mock_write, mock_reload):
        """Test config generation with automatic reload"""
        mock_validate.return_value = (True, '')
        mock_write.return_value = True
        mock_reload.return_value = (True, 'Nginx reloaded successfully')
        
        out = StringIO()
        call_command('generate_nginx_config', '--reload', stdout=out)
        
        output = out.getvalue()
        self.assertIn('Successfully wrote Nginx config', output)
        self.assertIn('Nginx reloaded successfully', output)
        mock_reload.assert_called_once()
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_generate_config_custom_output(self, mock_validate, mock_write):
        """Test config generation with custom output path"""
        mock_validate.return_value = (True, '')
        mock_write.return_value = True
        
        out = StringIO()
        call_command('generate_nginx_config', '--output', '/tmp/test_nginx.conf', stdout=out)
        
        output = out.getvalue()
        self.assertIn('/tmp/test_nginx.conf', output)
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.write_config')
    def test_generate_config_no_validate(self, mock_write):
        """Test config generation without validation"""
        mock_write.return_value = True
        
        out = StringIO()
        call_command('generate_nginx_config', '--no-validate', stdout=out)
        
        # Command should succeed without validation
        output = out.getvalue()
        self.assertIn('Successfully wrote Nginx config', output)


class ReloadNginxCommandTestCase(TestCase):
    """Test cases for reload_nginx management command"""
    
    @patch('subprocess.run')
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_reload_command_success(self, mock_validate, mock_run):
        """Test successful Nginx reload"""
        mock_validate.return_value = (True, '')
        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='')
        
        out = StringIO()
        call_command('reload_nginx', stdout=out)
        
        output = out.getvalue()
        self.assertIn('successfully', output.lower())
    
    @patch('waf_project.waf_core.nginx_config_generator.NginxConfigGenerator.validate_config')
    def test_reload_command_validation_failure(self, mock_validate):
        """Test reload fails when validation fails"""
        mock_validate.return_value = (False, 'Invalid config')
        
        with self.assertRaises(SystemExit):
            # Command should exit with error
            call_command('reload_nginx')
