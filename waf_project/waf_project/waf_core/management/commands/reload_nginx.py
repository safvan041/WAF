"""
Django management command to safely reload Nginx.

Usage:
    python manage.py reload_nginx
"""

from django.core.management.base import BaseCommand, CommandError
from waf_project.waf_core.nginx_config_generator import NginxReloader


class Command(BaseCommand):
    help = 'Safely reload Nginx after validating configuration'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE('Reloading Nginx...'))
        
        try:
            success, message = NginxReloader.reload()
            
            if success:
                self.stdout.write(self.style.SUCCESS(f'✓ {message}'))
            else:
                raise CommandError(f'Failed to reload Nginx: {message}')
                
        except Exception as e:
            raise CommandError(f'Error reloading Nginx: {e}')
