"""
Django management command to generate Nginx configuration from verified tenants.

Usage:
    python manage.py generate_nginx_config
    python manage.py generate_nginx_config --reload
    python manage.py generate_nginx_config --dry-run
    python manage.py generate_nginx_config --output /tmp/nginx.conf
"""

from django.core.management.base import BaseCommand, CommandError
from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator, NginxReloader


class Command(BaseCommand):
    help = 'Generate Nginx configuration from verified tenants'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reload',
            action='store_true',
            help='Reload Nginx after generating config',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be generated without writing to file',
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Custom output path for generated config',
        )
        parser.add_argument(
            '--no-validate',
            action='store_true',
            help='Skip config validation before writing',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        reload_nginx = options['reload']
        output_path = options.get('output')
        validate = not options['no_validate']

        # Initialize generator
        generator = NginxConfigGenerator(output_path=output_path)

        self.stdout.write(self.style.NOTICE('Fetching verified tenants...'))
        
        # Get tenants
        tenants = generator.get_verified_tenants()
        
        if not tenants:
            self.stdout.write(self.style.WARNING('No verified tenants found'))
            return

        self.stdout.write(
            self.style.SUCCESS(f'Found {len(tenants)} verified tenant(s):')
        )
        for tenant in tenants:
            self.stdout.write(f'  - {tenant.name}: {tenant.waf_host} → {tenant.origin_url}')

        # Generate config
        self.stdout.write(self.style.NOTICE('\nGenerating Nginx configuration...'))
        
        try:
            config_content = generator.generate_config(tenants)
            
            if dry_run:
                self.stdout.write(self.style.WARNING('\n--- DRY RUN MODE ---'))
                self.stdout.write(self.style.NOTICE('Generated configuration:'))
                self.stdout.write('-' * 80)
                self.stdout.write(config_content)
                self.stdout.write('-' * 80)
                self.stdout.write(self.style.SUCCESS('\nDry run completed successfully'))
                return
            
            # Write config
            self.stdout.write(self.style.NOTICE(f'Writing configuration to {generator.output_path}...'))
            success = generator.write_config(config_content, validate=validate)
            
            if not success:
                raise CommandError('Failed to write Nginx configuration')
            
            self.stdout.write(
                self.style.SUCCESS(f'✓ Successfully wrote Nginx config to {generator.output_path}')
            )
            
            # Reload if requested
            if reload_nginx:
                self.stdout.write(self.style.NOTICE('\nReloading Nginx...'))
                success, message = NginxReloader.reload()
                
                if success:
                    self.stdout.write(self.style.SUCCESS(f'✓ {message}'))
                else:
                    raise CommandError(f'Failed to reload Nginx: {message}')
            else:
                self.stdout.write(
                    self.style.WARNING('\nNginx not reloaded. Run with --reload to reload automatically.')
                )
                
        except Exception as e:
            raise CommandError(f'Error generating Nginx config: {e}')
