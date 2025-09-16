# waf_engine/middleware.py

import re
import ipaddress
import json
import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
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
        
        # Check against IP Whitelist first
        if self._is_whitelisted(request.tenant, client_ip):
            print("DEBUG: IP is whitelisted, allowing request")
            return self.get_response(request)

        # Check against IP Blacklist
        if self._is_blacklisted(request.tenant, client_ip):
            self._log_event(request, 'IP_BLACKLIST', None, 'block')
            return HttpResponseForbidden("Your IP has been blacklisted.")

        # Load active rules for the tenant
        tenant_rules = TenantFirewallConfig.objects.filter(
            tenant=request.tenant, is_enabled=True
        ).select_related('rule')

        print(f"DEBUG: Found {tenant_rules.count()} active rules for tenant")

        for config in tenant_rules:
            rule = config.rule
            effective_action = config.get_effective_action()
            
            print(f"DEBUG: Checking rule '{rule.name}' with pattern '{rule.pattern}'")
            print(f"DEBUG: Rule type: {rule.rule_type}, Action: {effective_action}")

            if self._match_pattern(request, rule):
                print(f"DEBUG: RULE MATCHED! Rule: {rule.name}")
                self._log_event(request, rule.rule_type, rule, effective_action)
                if effective_action == 'block':
                    print("DEBUG: Blocking request due to rule match")
                    return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your request has been blocked by the WAF.</p>")
                else:
                    print(f"DEBUG: Rule matched but action is '{effective_action}', allowing request")
            else:
                print(f"DEBUG: Rule '{rule.name}' did not match")

        print("DEBUG: No rules matched, allowing request")
        response = self.get_response(request)
        return response

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
        target_data = ""
        
        # Always check the full path and query string
        target_data += request.get_full_path()
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
                
        # Check headers (optional - you might want to be selective about which headers)
        # target_data += str(request.headers)

        if rule.pattern:
            print(f"DEBUG: Checking pattern '{rule.pattern}' against '{target_data}'")
            match = re.search(rule.pattern, target_data, re.IGNORECASE)
            print(f"DEBUG: Pattern match result: {bool(match)}")
            if match:
                print(f"DEBUG: Matched text: '{match.group()}'")
            return match
        return False

    def _log_event(self, request, event_type, rule, action_taken):
        try:
            event = SecurityEvent.objects.create(
                tenant=request.tenant,
                rule=rule,  
                event_type=event_type,
                severity=rule.severity if rule else "low",
                action_taken=action_taken,
                source_ip=self._get_client_ip(request),
                request_method=request.method,
                request_url=request.build_absolute_uri(),
            )
            print(f"DEBUG: Logged security event: {event.id}")
        except Exception as e:
            print(f"DEBUG: Failed to log security event: {e}")