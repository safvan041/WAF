import os
import django
from django.conf import settings
from django.test import RequestFactory

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf_project.settings')
django.setup()

from waf_project.waf_core.models import Tenant, FirewallRule, TenantFirewallConfig, WAFConfiguration
from waf_project.waf_engine.middleware import WAFMiddleware

def reproduce():
    print("--- Setting up reproduction environment ---")
    
    # 1. Create Tenant
    tenant_name = "Test Tenant"
    domain = "tenupsoft.com"
    tenant, created = Tenant.objects.get_or_create(
        domain=domain,
        defaults={'name': tenant_name, 'contact_email': 'test@example.com'}
    )
    print(f"Tenant: {tenant.name} ({tenant.domain})")

    # 2. Create WAF Config
    waf_config, created = WAFConfiguration.objects.get_or_create(
        tenant=tenant,
        defaults={'is_enabled': True, 'protection_level': 'custom'}
    )
    if not waf_config.is_enabled:
        waf_config.is_enabled = True
        waf_config.save()
    print(f"WAF Config Enabled: {waf_config.is_enabled}")

    # 3. Create Firewall Rule
    rule_pattern = "^/.*$"
    rule, created = FirewallRule.objects.get_or_create(
        name="Block All",
        defaults={
            'rule_type': 'custom',
            'pattern': rule_pattern,
            'action': 'block',
            'severity': 'critical'
        }
    )
    # Ensure pattern is correct if it already existed
    if rule.pattern != rule_pattern:
        rule.pattern = rule_pattern
        rule.save()
    print(f"Rule: {rule.name}, Pattern: {rule.pattern}")

    # 4. Link Rule to Tenant
    config, created = TenantFirewallConfig.objects.get_or_create(
        tenant=tenant,
        rule=rule,
        defaults={'is_enabled': True}
    )
    if not config.is_enabled:
        config.is_enabled = True
        config.save()
    print(f"Rule Linked to Tenant: {config.is_enabled}")

    # 5. Create Mock Request
    factory = RequestFactory()
    request = factory.get('/') # Path is '/'
    request.tenant = tenant # Simulate TenantMiddleware having run
    
    print(f"\n--- Processing Request: {request.path} ---")
    
    # 6. Run Middleware
    middleware = WAFMiddleware(lambda r: print("Request Allowed (Middleware passed)"))
    response = middleware(request)

    # 7. Check Result
    if response and response.status_code == 403:
        print("SUCCESS: Request was BLOCKED (403 Forbidden)")
    else:
        print("FAILURE: Request was ALLOWED")
        if response:
            print(f"Response Status: {response.status_code}")
        else:
            print("Response is None (Middleware passed)")

    # 8. Test Additional Domain Logic
    print("\n--- Testing Additional Domain (www.tenupsoft.com) ---")
    # Add www to additional_domains
    tenant.additional_domains = "www.tenupsoft.com"
    tenant.save()
    
    request_www = factory.get('/')
    # Simulate request coming to www.tenupsoft.com
    request_www.META['HTTP_HOST'] = 'www.tenupsoft.com'
    
    # We need to run TenantMiddleware manually here since we are mocking
    from waf_project.waf_engine.tenant_middleware import TenantMiddleware
    tenant_middleware = TenantMiddleware(lambda r: None)
    tenant_middleware(request_www) # This should set request_www.tenant
    
    if request_www.tenant == tenant:
        print(f"SUCCESS: Tenant resolved for additional domain: {request_www.tenant.name}")
    else:
        print(f"FAILURE: Tenant NOT resolved for additional domain. Got: {request_www.tenant}")

    # Run WAF on this request
    response_www = middleware(request_www)
    if response_www and response_www.status_code == 403:
        print("SUCCESS: Request to additional domain was BLOCKED")
    else:
        print("FAILURE: Request to additional domain was ALLOWED")

    # 9. Test msbcgroup.com (New Tenant)
    print("\n--- Testing msbcgroup.com ---")
    tenant_msbc, _ = Tenant.objects.get_or_create(
        domain="msbcgroup.com",
        defaults={'name': "MSBC Group", 'contact_email': 'admin@msbcgroup.com'}
    )
    
    # Enable WAF for msbcgroup.com
    waf_config_msbc, _ = WAFConfiguration.objects.get_or_create(
        tenant=tenant_msbc,
        defaults={'is_enabled': True, 'protection_level': 'custom'}
    )
    if not waf_config_msbc.is_enabled:
        waf_config_msbc.is_enabled = True
        waf_config_msbc.save()

    # Assign same blocking rule
    TenantFirewallConfig.objects.get_or_create(
        tenant=tenant_msbc,
        rule=rule,
        defaults={'is_enabled': True}
    )

    request_msbc = factory.get('/')
    request_msbc.META['HTTP_HOST'] = 'msbcgroup.com'
    
    # Run TenantMiddleware
    tenant_middleware(request_msbc)
    
    if request_msbc.tenant == tenant_msbc:
        print(f"SUCCESS: Tenant resolved for msbcgroup.com: {request_msbc.tenant.name}")
    else:
        print(f"FAILURE: Tenant NOT resolved for msbcgroup.com. Got: {request_msbc.tenant}")

    # Run WAF
    response_msbc = middleware(request_msbc)
    if response_msbc and response_msbc.status_code == 403:
        print("SUCCESS: Request to msbcgroup.com was BLOCKED")
    else:
        print("FAILURE: Request to msbcgroup.com was ALLOWED")

if __name__ == "__main__":
    reproduce()

