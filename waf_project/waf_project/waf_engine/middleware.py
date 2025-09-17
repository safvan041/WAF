# waf_engine/middleware.py

import re
import ipaddress
import json
import logging
import geoip2.database
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.conf import settings
from waf_project.waf_core.models import (
    Tenant,
    TenantFirewallConfig,  # Updated model name
    SecurityEvent,
    FirewallRule,
    IPWhitelist,
    IPBlacklist,
    GeographicRule,
    WAFConfiguration,
)

logger = logging.getLogger('waf_engine')

class WAFMiddleware(MiddlewareMixin):
    async_mode = False

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(('/admin/', '/static/')):
            return self.get_response(request)

        host = request.META.get('HTTP_X_FORWARDED_HOST')
        if not host:
            host = request.get_host().split(':')[0]
        
        try:
            request.tenant = Tenant.objects.get(domain=host)
        except Tenant.DoesNotExist:
            request.tenant = None

        if not request.tenant or not request.tenant.is_active:
            return self.get_response(request)
            
        try:
            waf_config = WAFConfiguration.objects.get(tenant=request.tenant)
        except WAFConfiguration.DoesNotExist:
            return self.get_response(request)

        if not waf_config.is_enabled:
            return self.get_response(request)

        client_ip = self._get_client_ip(request)
        
        # IP Filtering checks
        if self._is_whitelisted(request.tenant, client_ip):
            logger.info(f"IP {client_ip} whitelisted for tenant {request.tenant.name}")
            return self.get_response(request)

        if self._is_blacklisted(request.tenant, client_ip):
            logger.info(f"IP {client_ip} blacklisted for tenant {request.tenant.name}")
            self._log_event(request.tenant, None, 'ip_blacklist', 'block', 'critical', client_ip, request)
            return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your IP has been blacklisted.</p>")

        #  Geographic Blocking Check ---
        if waf_config.geographic_blocking_enabled:
            if self._is_geoblocked(request.tenant, client_ip):
                logger.info(f"IP {client_ip} from a geoblocked country for tenant {request.tenant.name}")
                # Placeholder for rule object
                rule = FirewallRule.objects.filter(rule_type='geo_blocking').first()
                self._log_event(request.tenant, rule, 'geo_blocked', rule.action, rule.severity, client_ip, request)
                return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Access from your country is blocked.</p>")


        # Load active rules for the tenant
        tenant_rules = TenantFirewallConfig.objects.filter(
            tenant=request.tenant, is_enabled=True
        ).select_related('rule')

        for config in tenant_rules:
            rule = config.rule
            effective_action = config.get_effective_action()
            
            if self._match_pattern(request, rule):
                logger.info(f"Rule match: {rule.name} for tenant {request.tenant.name}")
                self._log_event(
                    request.tenant, 
                    rule, 
                    rule.rule_type, 
                    effective_action, 
                    rule.severity, 
                    client_ip, 
                    request
                )
                if effective_action == 'block':
                    return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your request has been blocked by the WAF.</p>")
        
        response = self.get_response(request)
        return response

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        
        try:
            ipaddress.ip_address(ip)
            return ip
        except (ValueError, ipaddress.AddressValueError):
            logger.warning(f"Invalid IP address received: {ip}")
            return '0.0.0.0'
        
    def _is_whitelisted(self, tenant, ip_address):
        return IPWhitelist.objects.filter(
            tenant=tenant,
            ip_address=ip_address,
            is_active=True
        ).exists()

    def _is_blacklisted(self, tenant, ip_address):
        return IPBlacklist.objects.filter(
            tenant=tenant,
            ip_address=ip_address,
            is_active=True
        ).exists()

    def _is_geoblocked(self, tenant, ip_address):
        try:
            reader = geoip2.database.Reader(settings.GEOIP_PATH / 'GeoLite2-Country.mmdb')
            response = reader.country(ip_address)
            country_code = response.country.iso_code
            
            is_blocked = GeographicRule.objects.filter(
                tenant=tenant,
                country_code=country_code,
                action='block',
                is_active=True
            ).exists()
            return is_blocked
        except Exception as e:
            logger.error(f"GeoIP check failed for IP {ip_address}: {e}")
            return False

    def _match_pattern(self, request, rule):
        target_data = request.get_full_path() + str(request.body) + str(request.headers)
        if rule.pattern:
            return re.search(rule.pattern, target_data, re.IGNORECASE)
        return False

    def _log_event(self, tenant, rule, event_type, action_taken, severity, client_ip, request):
        try:
            event = SecurityEvent.objects.create(
                tenant=tenant,
                rule=rule,  
                event_type=event_type,
                severity=severity,
                action_taken=action_taken,
                source_ip=client_ip,
                request_method=request.method,
                request_url=request.get_full_path(),
                request_headers=json.dumps(dict(request.headers)),
            )
            logger.info(f"Logged security event: {event.id}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")