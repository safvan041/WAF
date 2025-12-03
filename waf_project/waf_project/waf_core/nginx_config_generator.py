"""
Nginx Configuration Generator Service

This module provides functionality to dynamically generate Nginx configuration
files based on verified tenants in the database.
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Any
from django.conf import settings
from django.template.loader import render_to_string
from jinja2 import Environment, FileSystemLoader, select_autoescape
from waf_project.waf_core.models import Tenant

logger = logging.getLogger(__name__)


class NginxConfigGenerator:
    """
    Service class for generating Nginx configuration files from tenant data.
    """
    
    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize the config generator.
        
        Args:
            output_path: Custom path for generated config. Defaults to settings.NGINX_CONFIG_PATH
        """
        self.output_path = output_path or getattr(
            settings, 
            'NGINX_CONFIG_PATH', 
            '/etc/nginx/nginx.conf'
        )
        self.template_dir = getattr(
            settings,
            'NGINX_TEMPLATE_DIR',
            os.path.join(settings.BASE_DIR, 'waf_core/templates/nginx')
        )
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
    def get_verified_tenants(self) -> List[Tenant]:
        """
        Fetch all verified tenants from the database.
        
        Returns:
            List of verified Tenant objects
        """
        tenants = Tenant.objects.filter(
            domain_verified=True,
            is_active=True
        ).exclude(
            waf_host__isnull=True
        ).exclude(
            waf_host=''
        ).exclude(
            origin_url__isnull=True
        ).exclude(
            origin_url=''
        ).order_by('waf_host')
        
        logger.info(f"Found {tenants.count()} verified tenants for Nginx config generation")
        return list(tenants)
    
    def generate_config(self, tenants: Optional[List[Tenant]] = None) -> str:
        """
        Generate complete Nginx configuration.
        
        Args:
            tenants: Optional list of tenants. If None, fetches from database.
            
        Returns:
            Generated configuration as string
        """
        if tenants is None:
            tenants = self.get_verified_tenants()
        
        try:
            # Load base template
            template = self.jinja_env.get_template('base.conf.j2')
            
            # Render configuration
            config_content = template.render(
                tenants=tenants,
                settings=settings
            )
            
            logger.info(f"Generated Nginx config with {len(tenants)} tenant blocks")
            return config_content
            
        except Exception as e:
            logger.error(f"Error generating Nginx config: {e}", exc_info=True)
            raise
    
    def validate_config(self, config_path: Optional[str] = None) -> tuple[bool, str]:
        """
        Validate Nginx configuration syntax.
        
        Args:
            config_path: Path to config file to validate. Defaults to self.output_path
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        config_path = config_path or self.output_path
        
        # Get test command from settings
        test_command = getattr(
            settings,
            'NGINX_TEST_COMMAND',
            'nginx -t'
        )
        
        try:
            # Run nginx -t to validate config
            result = subprocess.run(
                test_command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("Nginx configuration validation passed")
                return True, ""
            else:
                error_msg = result.stderr or result.stdout
                logger.error(f"Nginx configuration validation failed: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "Nginx validation timed out"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = "Nginx command not found. Skipping validation."
            logger.warning(error_msg)
            # In development, we might not have nginx installed
            return True, error_msg
        except Exception as e:
            error_msg = f"Error validating Nginx config: {e}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg
    
    def write_config(self, config_content: str, validate: bool = True) -> bool:
        """
        Write configuration to file atomically.
        
        Args:
            config_content: Configuration content to write
            validate: Whether to validate before writing
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(self.output_path)
            temp_path = output_path.with_suffix('.tmp')
            backup_path = output_path.with_suffix('.backup')
            
            # Ensure directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file
            temp_path.write_text(config_content, encoding='utf-8')
            logger.info(f"Wrote temporary config to {temp_path}")
            
            # Validate if requested
            if validate:
                is_valid, error_msg = self.validate_config(str(temp_path))
                if not is_valid:
                    logger.error(f"Generated config is invalid: {error_msg}")
                    temp_path.unlink(missing_ok=True)
                    return False
            
            # Backup existing config
            if output_path.exists():
                output_path.replace(backup_path)
                logger.info(f"Backed up existing config to {backup_path}")
            
            # Move temp file to final location
            temp_path.replace(output_path)
            logger.info(f"Successfully wrote Nginx config to {output_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error writing Nginx config: {e}", exc_info=True)
            return False
    
    def generate_and_write(self, validate: bool = True) -> Dict[str, Any]:
        """
        Generate configuration and write to file.
        
        Args:
            validate: Whether to validate before writing
            
        Returns:
            Dictionary with status information
        """
        try:
            # Get tenants
            tenants = self.get_verified_tenants()
            
            # Generate config
            config_content = self.generate_config(tenants)
            
            # Write config
            success = self.write_config(config_content, validate=validate)
            
            return {
                'success': success,
                'tenant_count': len(tenants),
                'output_path': self.output_path,
                'validated': validate
            }
            
        except Exception as e:
            logger.error(f"Error in generate_and_write: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'tenant_count': 0,
                'output_path': self.output_path
            }


class NginxReloader:
    """
    Service class for safely reloading Nginx.
    """
    
    @staticmethod
    def reload() -> tuple[bool, str]:
        """
        Reload Nginx configuration.
        
        Returns:
            Tuple of (success, message)
        """
        reload_command = getattr(
            settings,
            'NGINX_RELOAD_COMMAND',
            'nginx -s reload'
        )
        
        try:
            # First validate the config
            generator = NginxConfigGenerator()
            is_valid, error_msg = generator.validate_config()
            
            if not is_valid:
                return False, f"Cannot reload: config validation failed - {error_msg}"
            
            # Reload Nginx
            result = subprocess.run(
                reload_command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("Nginx reloaded successfully")
                return True, "Nginx reloaded successfully"
            else:
                error_msg = result.stderr or result.stdout
                logger.error(f"Nginx reload failed: {error_msg}")
                return False, f"Reload failed: {error_msg}"
                
        except subprocess.TimeoutExpired:
            error_msg = "Nginx reload timed out"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = "Nginx command not found"
            logger.warning(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error reloading Nginx: {e}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg
