# waf_engine/middleware.py

import re
import ipaddress
import json
import logging
import geoip2.database
from django.contrib.gis.geoip2 import GeoIP2, GeoIP2Exception
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from waf_project.waf_core.models import (
    Tenant,
    TenantFirewallConfig,  
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
        # Skip admin and static files
        if request.path.startswith(('/admin/', '/static/')):
            return self.get_response(request)

        print(f"DEBUG: WAF processing request: {request.get_full_path()}")
        print(f"DEBUG: Request host: {request.get_host()}")

        # Tenant should already be set by TenantMiddleware
        if not hasattr(request, 'tenant'):
            print("DEBUG: No tenant attribute found on request")
            return self.get_response(request)
            
        if not request.tenant:
            print("DEBUG: request.tenant is None")
            return self.get_response(request)
            
        if not request.tenant.is_active:
            print(f"DEBUG: Tenant {request.tenant.name} is not active")
            return self.get_response(request)

        print(f"DEBUG: Processing WAF for tenant: {request.tenant.name}")
        
        # Load tenant-specific WAF configuration and rules
        try:
            waf_config = WAFConfiguration.objects.get(tenant=request.tenant)
            print(f"DEBUG: Found WAF config, enabled: {waf_config.is_enabled}")
        except WAFConfiguration.DoesNotExist:
            print("DEBUG: No WAF configuration found for tenant")
            return self.get_response(request)

        if not waf_config.is_enabled:
            print("DEBUG: WAF is disabled for this tenant")
            return self.get_response(request)

        client_ip = self._get_client_ip(request)
        print(f"DEBUG: Client IP: {client_ip}")
        
        # Check IP against whitelists and blacklists
        if self._is_whitelisted(request.tenant, client_ip):
            return self._forward_request(request, request.tenant.domain)

        if self._is_blacklisted(request.tenant, client_ip):
            self._log_event(request.tenant, None, 'ip_blacklist', 'block', 'critical', client_ip, request)
            return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your IP has been blacklisted.</p>")

        if waf_config.geographic_blocking_enabled:
            if self._is_geoblocked(request.tenant, client_ip):
                rule = FirewallRule.objects.filter(rule_type='geo_blocking').first()
                self._log_event(request.tenant, rule, 'geo_blocked', rule.action, rule.severity, client_ip, request)
                return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Access from your country is blocked.</p>")

        # Load active rules for the tenant
        tenant_rules = TenantFirewallConfig.objects.filter(
            tenant=request.tenant, is_enabled=True
        ).select_related('rule')

        print(f"DEBUG: Found {tenant_rules.count()} active rules for tenant")

        for config in tenant_rules:
            rule = config.rule
            effective_action = config.get_effective_action()

            # 🚨 Skip geo rules here, since already handled above
            if rule.rule_type == "geo_blocking":
                print(f"DEBUG: Skipping geo rule '{rule.name}' (already processed)")
                continue

            print(f"DEBUG: Checking rule '{rule.name}' with pattern '{rule.pattern}'")
            print(f"DEBUG: Rule type: {rule.rule_type}, Action: {effective_action}")

            if self._match_pattern(request, rule):
                print(f"DEBUG: RULE MATCHED! Rule: {rule.name}")
                self._log_event(request.tenant, rule, rule.rule_type, effective_action, 'medium', client_ip, request)
                if effective_action == 'block':
                    print("DEBUG: Blocking request due to rule match")
                    return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your request has been blocked by the WAF.</p>")
                else:
                    print(f"DEBUG: Rule matched but action is '{effective_action}', allowing request")
            else:
                print(f"DEBUG: Rule '{rule.name}' did not match")
        print("DEBUG: No rules matched, allowing request")
        return self.get_response(request)


    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
        
    def _is_whitelisted(self, tenant, ip_address):
        is_whitelisted = IPWhitelist.objects.filter(
            tenant=tenant,
            ip_address=ip_address,
            is_active=True
        ).exists()
        print(f"DEBUG: IP whitelist check for {ip_address}: {is_whitelisted}")
        return is_whitelisted

    def _is_blacklisted(self, tenant, ip_address):
        is_blacklisted = IPBlacklist.objects.filter(
            tenant=tenant,
            ip_address=ip_address,
            is_active=True
        ).exists()
        print(f"DEBUG: IP blacklist check for {ip_address}: {is_blacklisted}")
        return is_blacklisted

    def _match_pattern(self, request, rule):
        from urllib.parse import unquote
        
        target_data = ""
        
        # Always check the full path and query string (both raw and decoded)
        full_path = request.get_full_path()
        decoded_path = unquote(full_path)
        
        target_data += full_path + " " + decoded_path
        print(f"DEBUG: Target data for pattern matching: '{target_data}'")
            
        # Check POST data
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                # Add the request body to the target data
                body_data = request.body.decode('utf-8')
                target_data += body_data
                print(f"DEBUG: Added body data: '{body_data}'")
            except UnicodeDecodeError:
                print("DEBUG: Could not decode request body")
                pass
                
        # Check headers (optional)
        # target_data += str(request.headers)

        if rule.pattern:
            print(f"DEBUG: Checking pattern '{rule.pattern}' against '{target_data}'")
            match = re.search(rule.pattern, target_data, re.IGNORECASE)
            print(f"DEBUG: Pattern match result: {bool(match)}")
            if match:
                print(f"DEBUG: Matched text: '{match.group()}'")
            return match
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

    def _is_geoblocked(self, tenant, ip_address):
        geo_rules = GeographicRule.objects.filter(tenant=tenant, is_active=True)
        if not geo_rules.exists():
            return False

        country_code = self._get_country_code_from_ip(ip_address)
        print(f"DEBUG: Resolved country code for {ip_address}: {country_code}")

        blocked_countries = [rule.country_code for rule in geo_rules]
        is_blocked = country_code in blocked_countries

        print(f"DEBUG: Blocked countries for tenant: {blocked_countries}")
        print(f"DEBUG: Is {country_code} blocked? {is_blocked}")

        return is_blocked

    def _get_country_code_from_ip(self, ip_address):
        """
        Get the ISO country code from an IP address using GeoLite2.
        Returns None if lookup fails.
        """
        try:
            g = GeoIP2()
            result = g.country(ip_address)
            country_code = result.get("country_code")

            logger.debug(f"Resolved country for {ip_address}: {result}")

            return country_code
        except GeoIP2Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error in GeoIP lookup for {ip_address}")
            return None