from django.core.management.base import BaseCommand
from waf_project.waf_core.models import Tenant, WAFConfiguration, TenantFirewallConfig

class Command(BaseCommand):
    help = 'Check WAF configuration for a given domain'

    def add_arguments(self, parser):
        parser.add_argument('domain', type=str, help='Domain to check')

    def handle(self, *args, **options):
        domain = options['domain']
        self.stdout.write(f"Checking WAF config for domain: {domain}")

        # 1. Resolve Tenant
        tenant = None
        try:
            tenant = Tenant.objects.get(domain=domain)
            self.stdout.write(self.style.SUCCESS(f"Found Tenant (Exact Match): {tenant.name}"))
        except Tenant.DoesNotExist:
            # Check additional domains
            potential_tenants = Tenant.objects.filter(additional_domains__icontains=domain)
            for t in potential_tenants:
                if domain in t.get_all_domains():
                    tenant = t
                    self.stdout.write(self.style.SUCCESS(f"Found Tenant (Additional Domain): {tenant.name}"))
                    break
        
        if not tenant:
            self.stdout.write(self.style.ERROR(f"No tenant found for domain: {domain}"))
            return

        # 2. Check WAF Config
        try:
            waf_config = WAFConfiguration.objects.get(tenant=tenant)
            status = "ENABLED" if waf_config.is_enabled else "DISABLED"
            color = self.style.SUCCESS if waf_config.is_enabled else self.style.WARNING
            self.stdout.write(f"WAF Status: {color(status)}")
            self.stdout.write(f"Protection Level: {waf_config.protection_level}")
        except WAFConfiguration.DoesNotExist:
            self.stdout.write(self.style.ERROR("No WAF Configuration found!"))
            return

        # 3. List Rules
        configs = TenantFirewallConfig.objects.filter(tenant=tenant, is_enabled=True).select_related('rule')
        self.stdout.write(f"\nActive Rules ({configs.count()}):")
        for config in configs:
            rule = config.rule
            self.stdout.write(f" - {rule.name} [{rule.rule_type}]")
            self.stdout.write(f"   Pattern: {rule.pattern}")
            self.stdout.write(f"   Action: {config.get_effective_action()}")
            self.stdout.write("")
