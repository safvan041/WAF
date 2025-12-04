#!/bin/bash
# Script to check current Nginx configuration on production

echo "=== Checking Current Nginx Configuration ==="
echo ""

echo "1. Check if Nginx config file exists:"
docker exec waf_nginx ls -la /etc/nginx/conf.d/

echo ""
echo "2. View current Nginx configuration:"
docker exec waf_nginx cat /etc/nginx/conf.d/nginx.conf

echo ""
echo "3. Check for tenant2.waf-app.site in config:"
docker exec waf_nginx grep -A 20 "tenant2.waf-app.site" /etc/nginx/conf.d/nginx.conf || echo "tenant2.waf-app.site NOT FOUND in config"

echo ""
echo "4. Check Nginx syntax:"
docker exec waf_nginx nginx -t

echo ""
echo "5. Check Django database for Tenup tenant:"
docker exec waf_app python manage.py shell -c "
from waf_project.waf_core.models import Tenant
tenant = Tenant.objects.filter(waf_host='tenant2.waf-app.site').first()
if tenant:
    print(f'Tenant found:')
    print(f'  Name: {tenant.name}')
    print(f'  WAF Host: {tenant.waf_host}')
    print(f'  Origin URL: {tenant.origin_url}')
    print(f'  Domain Verified: {tenant.domain_verified}')
    print(f'  Is Active: {tenant.is_active}')
else:
    print('Tenant NOT FOUND in database')
"

echo ""
echo "6. Manually generate Nginx config:"
docker exec waf_app python manage.py generate_nginx_config --dry-run

echo ""
echo "=== End of Check ==="
