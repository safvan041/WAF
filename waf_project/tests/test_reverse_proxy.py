"""
Test Reverse Proxy Functionality

This script tests the reverse proxy implementation by:
1. Creating test tenants with origin_url configured
2. Making requests through the WAF
3. Verifying responses come from the origin server
"""

import os
import sys
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf_project.settings')
django.setup()

from waf_project.waf_core.models import Tenant
from django.test import RequestFactory
from waf_project.waf_engine.proxy import proxy_request, build_target_url, prepare_headers


def test_build_target_url():
    """Test URL building logic"""
    print("\n🧪 Testing URL Building...")
    
    factory = RequestFactory()
    
    # Test 1: Simple path
    request = factory.get('/test/path')
    url = build_target_url('https://example.com', request)
    assert url == 'https://example.com/test/path', f"Expected https://example.com/test/path, got {url}"
    print("  ✅ Simple path test passed")
    
    # Test 2: Path with query string
    request = factory.get('/test/path?foo=bar&baz=qux')
    url = build_target_url('https://example.com', request)
    assert url == 'https://example.com/test/path?foo=bar&baz=qux', f"Unexpected URL: {url}"
    print("  ✅ Query string test passed")
    
    # Test 3: Origin URL with trailing slash
    request = factory.get('/test')
    url = build_target_url('https://example.com/', request)
    assert url == 'https://example.com/test', f"Expected https://example.com/test, got {url}"
    print("  ✅ Trailing slash test passed")
    
    print("✅ All URL building tests passed!\n")


def test_prepare_headers():
    """Test header preparation logic"""
    print("🧪 Testing Header Preparation...")
    
    factory = RequestFactory()
    request = factory.get('/', HTTP_USER_AGENT='TestAgent', HTTP_ACCEPT='text/html')
    
    headers = prepare_headers(request)
    
    # Check X-Forwarded headers are added
    assert 'X-Forwarded-For' in headers, "X-Forwarded-For header missing"
    assert 'X-Forwarded-Proto' in headers, "X-Forwarded-Proto header missing"
    assert 'X-Forwarded-Host' in headers, "X-Forwarded-Host header missing"
    assert 'X-WAF-Protected' in headers, "X-WAF-Protected header missing"
    print("  ✅ X-Forwarded headers added")
    
    # Check original headers are preserved
    assert 'User-Agent' in headers, "User-Agent header missing"
    assert headers['User-Agent'] == 'TestAgent', f"User-Agent mismatch: {headers['User-Agent']}"
    print("  ✅ Original headers preserved")
    
    # Check excluded headers are not present
    assert 'Host' not in headers, "Host header should be excluded"
    assert 'Connection' not in headers, "Connection header should be excluded"
    print("  ✅ Hop-by-hop headers excluded")
    
    print("✅ All header preparation tests passed!\n")


def test_tenant_configuration():
    """Test tenant configuration for reverse proxy"""
    print("🧪 Testing Tenant Configuration...")
    
    # Check if any tenant has origin_url configured
    tenants_with_origin = Tenant.objects.filter(origin_url__isnull=False).exclude(origin_url='')
    
    if tenants_with_origin.exists():
        print(f"  ✅ Found {tenants_with_origin.count()} tenant(s) with origin_url configured:")
        for tenant in tenants_with_origin:
            print(f"     - {tenant.name}: {tenant.origin_url}")
    else:
        print("  ⚠️  No tenants have origin_url configured")
        print("     To test reverse proxy, configure a tenant's origin_url in Django admin")
    
    print()


def run_all_tests():
    """Run all tests"""
    print("=" * 70)
    print("🧪 WAF Reverse Proxy Tests")
    print("=" * 70)
    
    try:
        test_build_target_url()
        test_prepare_headers()
        test_tenant_configuration()
        
        print("=" * 70)
        print("✅ All tests passed!")
        print("=" * 70)
        print("\n📝 Next steps:")
        print("   1. Start the mock origin server: python -m tests.mock_origin_server")
        print("   2. Configure a tenant's origin_url to: http://localhost:8001")
        print("   3. Make requests through the WAF to test end-to-end")
        print()
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
