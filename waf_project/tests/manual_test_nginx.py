"""
Manual test script for Nginx automation

Run this script to manually test the Nginx config generation system.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf_project.settings')
django.setup()

from waf_project.waf_core.models import Tenant
from waf_project.waf_core.nginx_config_generator import NginxConfigGenerator, NginxReloader


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def test_tenant_creation():
    """Test creating tenants"""
    print_section("Test 1: Creating Test Tenants")
    
    # Clean up existing test tenants
    Tenant.objects.filter(domain__contains='test-tenant').delete()
    
    # Create verified tenant
    tenant1 = Tenant.objects.create(
        name="Test Tenant 1",
        domain="test-tenant1.com",
        waf_host="test1.waf-app.site",
        origin_url="https://app.test-tenant1.com",
        contact_email="admin@test-tenant1.com",
        contact_name="Admin 1",
        domain_verified=True,
        is_active=True
    )
    print(f"✓ Created verified tenant: {tenant1.name} ({tenant1.waf_host})")
    
    # Create another verified tenant
    tenant2 = Tenant.objects.create(
        name="Test Tenant 2",
        domain="test-tenant2.com",
        waf_host="test2.waf-app.site",
        origin_url="https://app.test-tenant2.com",
        contact_email="admin@test-tenant2.com",
        contact_name="Admin 2",
        domain_verified=True,
        is_active=True
    )
    print(f"✓ Created verified tenant: {tenant2.name} ({tenant2.waf_host})")
    
    # Create unverified tenant (should be excluded)
    tenant3 = Tenant.objects.create(
        name="Test Tenant 3 (Unverified)",
        domain="test-tenant3.com",
        waf_host="test3.waf-app.site",
        origin_url="https://app.test-tenant3.com",
        contact_email="admin@test-tenant3.com",
        contact_name="Admin 3",
        domain_verified=False,
        is_active=True
    )
    print(f"✓ Created unverified tenant: {tenant3.name} (should be excluded from config)")
    
    return tenant1, tenant2, tenant3


def test_get_verified_tenants():
    """Test fetching verified tenants"""
    print_section("Test 2: Fetching Verified Tenants")
    
    generator = NginxConfigGenerator()
    tenants = generator.get_verified_tenants()
    
    print(f"Found {len(tenants)} verified tenant(s):")
    for tenant in tenants:
        print(f"  - {tenant.name}: {tenant.waf_host} → {tenant.origin_url}")
    
    return tenants


def test_config_generation():
    """Test config generation"""
    print_section("Test 3: Generating Nginx Configuration")
    
    generator = NginxConfigGenerator()
    config = generator.generate_config()
    
    print("Generated configuration preview (first 1000 chars):")
    print("-" * 80)
    print(config[:1000])
    print("-" * 80)
    
    # Check for expected content
    checks = [
        ('upstream waf_app', 'Upstream definition'),
        ('server_name demo.waf-app.site', 'Base server block'),
        ('test1.waf-app.site', 'Test tenant 1'),
        ('test2.waf-app.site', 'Test tenant 2'),
        ('ssl_certificate', 'SSL configuration'),
    ]
    
    print("\nConfiguration checks:")
    for search_str, description in checks:
        if search_str in config:
            print(f"  ✓ {description}: Found")
        else:
            print(f"  ✗ {description}: NOT FOUND")
    
    # Check that unverified tenant is excluded
    if 'test3.waf-app.site' not in config:
        print(f"  ✓ Unverified tenant excluded: Correct")
    else:
        print(f"  ✗ Unverified tenant excluded: FAILED")
    
    return config


def test_config_write():
    """Test writing config to file"""
    print_section("Test 4: Writing Configuration to File")
    
    import tempfile
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
    temp_path = temp_file.name
    temp_file.close()
    
    try:
        generator = NginxConfigGenerator(output_path=temp_path)
        result = generator.generate_and_write(validate=False)  # Skip validation for test
        
        if result['success']:
            print(f"✓ Config written successfully to: {temp_path}")
            print(f"  - Tenant count: {result['tenant_count']}")
            print(f"  - Validated: {result['validated']}")
            
            # Read back and verify
            with open(temp_path, 'r') as f:
                content = f.read()
            print(f"  - File size: {len(content)} bytes")
        else:
            print(f"✗ Failed to write config: {result.get('error', 'Unknown error')}")
    
    finally:
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
            print(f"✓ Cleaned up temp file")


def test_tenant_update():
    """Test tenant update triggers config regeneration"""
    print_section("Test 5: Tenant Update (Signal Test)")
    
    print("Note: This test requires signal handlers to be active.")
    print("In production, updating a verified tenant should trigger automatic config regeneration.")
    
    tenant = Tenant.objects.filter(waf_host="test1.waf-app.site").first()
    if tenant:
        old_origin = tenant.origin_url
        new_origin = "https://new-app.test-tenant1.com"
        
        print(f"Updating tenant origin URL:")
        print(f"  Old: {old_origin}")
        print(f"  New: {new_origin}")
        
        tenant.origin_url = new_origin
        tenant.save()
        
        print(f"✓ Tenant updated")
        print(f"  Check logs for automatic config regeneration")
        
        # Revert change
        tenant.origin_url = old_origin
        tenant.save()
        print(f"✓ Reverted change")


def cleanup():
    """Clean up test data"""
    print_section("Cleanup")
    
    count = Tenant.objects.filter(domain__contains='test-tenant').delete()[0]
    print(f"✓ Deleted {count} test tenant(s)")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("  NGINX AUTOMATION MANUAL TEST SUITE")
    print("=" * 80)
    
    try:
        # Run tests
        tenant1, tenant2, tenant3 = test_tenant_creation()
        tenants = test_get_verified_tenants()
        config = test_config_generation()
        test_config_write()
        test_tenant_update()
        
        print_section("Test Summary")
        print("✓ All manual tests completed successfully!")
        print("\nNext steps:")
        print("  1. Review the generated configuration above")
        print("  2. Run automated tests: python manage.py test tests.test_nginx_*")
        print("  3. Test with actual Nginx: python manage.py generate_nginx_config --dry-run")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Ask before cleanup
        response = input("\nClean up test tenants? (y/n): ")
        if response.lower() == 'y':
            cleanup()
        else:
            print("Test tenants preserved for manual inspection")


if __name__ == '__main__':
    main()
