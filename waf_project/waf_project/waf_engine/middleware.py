# waf_engine/middleware.py

import re
import ipaddress
import json
import logging
from django.conf import settings
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
from waf_project.waf_ml.ml_engine import FeatureExtractor, AnomalyDetector
from waf_project.waf_ml.models import MLModel, AnomalyScore

logger = logging.getLogger('waf_engine')

class WAFMiddleware(MiddlewareMixin):
    async_mode = False

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip admin and static files
        if request.path.startswith(('/admin/', '/static/')):
            return self.get_response(request)

        if settings.DEBUG:
            print(f"DEBUG: WAF processing request: {request.get_full_path()}")
            print(f"DEBUG: Request host: {request.get_host()}")

        # Tenant should already be set by TenantMiddleware
        if not hasattr(request, 'tenant'):
            if settings.DEBUG:
                print("DEBUG: No tenant attribute found on request")
            return self.get_response(request)
            
        if not request.tenant:
            if settings.DEBUG:
                print("DEBUG: request.tenant is None")
            return self.get_response(request)
            
        if not request.tenant.is_active:
            if settings.DEBUG:
                print(f"DEBUG: Tenant {request.tenant.name} is not active")
            return self.get_response(request)

        if settings.DEBUG:
            print(f"DEBUG: Processing WAF for tenant: {request.tenant.name}")
        
        # Load tenant-specific WAF configuration and rules
        try:
            waf_config = WAFConfiguration.objects.get(tenant=request.tenant)
            if settings.DEBUG:
                print(f"DEBUG: Found WAF config, enabled: {waf_config.is_enabled}")
        except WAFConfiguration.DoesNotExist:
            if settings.DEBUG:
                print("DEBUG: No WAF configuration found for tenant")
            return self.get_response(request)

        if not waf_config.is_enabled:
            if settings.DEBUG:
                print("DEBUG: WAF is disabled for this tenant")
            return self.get_response(request)

        client_ip = self._get_client_ip(request)
        if settings.DEBUG:
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

        if settings.DEBUG:
            print(f"DEBUG: Found {tenant_rules.count()} active rules for tenant")

        for config in tenant_rules:
            rule = config.rule
            effective_action = config.get_effective_action()

            # 🚨 Skip geo rules here, since already handled above
            if rule.rule_type == "geo_blocking":
                continue

            if settings.DEBUG:
                print(f"DEBUG: Checking rule '{rule.name}' with pattern '{rule.pattern}'")

            if self._match_pattern(request, rule):
                logger.info(f"WAF Rule Matched: {rule.name} for tenant {request.tenant.name}")
                self._log_event(request.tenant, rule, rule.rule_type, effective_action, 'medium', client_ip, request)
                if effective_action == 'block':
                    return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your request has been blocked by the WAF.</p>")
                else:
                    if settings.DEBUG:
                        print(f"DEBUG: Rule matched but action is '{effective_action}', allowing request")
            else:
                if settings.DEBUG:
                    print(f"DEBUG: Rule '{rule.name}' did not match")
        
        # Check ML-based anomaly detection
        ml_result = self._check_ml_anomaly(request, request.tenant, client_ip)
        if ml_result and ml_result.get("is_blocked"):
            return ml_result.get("response")
        
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
        import html
        
        # Helper to normalize data
        def normalize_data(data):
            decoded_list = set()
            decoded_list.add(data)
            
            # 1. URL Decode (Single & Double)
            try:
                u1 = unquote(data)
                decoded_list.add(u1)
                u2 = unquote(u1)
                decoded_list.add(u2)
            except: pass
            
            # 2. HTML Entity Decode
            try:
                h1 = html.unescape(data)
                decoded_list.add(h1)
            except: pass
            
            # 3. Unicode Decode (for \u003c type attacks)
            try:
                # This is a bit risky on raw strings, but useful for JSON bodies
                if "\\u" in data:
                    u_decode = data.encode('utf-8').decode('unicode_escape')
                    decoded_list.add(u_decode)
            except: pass
            
            return decoded_list

        # Collect all parts of the request
        raw_targets = []
        
        # Path and Query
        raw_targets.append(request.path)
        raw_targets.append(request.META.get('QUERY_STRING', ''))
        
        # Request Body
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body_data = request.body.decode('utf-8')
                raw_targets.append(body_data)
            except UnicodeDecodeError:
                pass
                
        # Headers (specific ones that are attack vectors)
        for header in ['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_COOKIE']:
            val = request.META.get(header)
            if val:
                raw_targets.append(val)

        # Check pattern against ALL normalized versions of ALL data
        if rule.pattern:
            print(f"DEBUG: Checking rule '{rule.name}'")
            for raw_data in raw_targets:
                # Get all variations (decoded, unescaped, etc)
                variations = normalize_data(raw_data)
                
                for target in variations:
                    # Skip empty strings
                    if not target: continue
                    
                    match = re.search(rule.pattern, target, re.IGNORECASE)
                    if match:
                        print(f"DEBUG: RULE MATCHED! Pattern: '{rule.pattern}' matched text: '{match.group()}' in data: '{target[:50]}...'")
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
        try:
            g = GeoIP2()
            result = g.country(ip_address)
            country_code = result.get("country_code")
            logger.debug(f"Resolved country for {ip_address}: {result}")
            return country_code
        except GeoIP2Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
        except Exception:
            logger.exception(
                f"Unexpected error in GeoIP lookup for {ip_address}"
            )
            return None

    def _check_ml_anomaly(self, request, tenant, client_ip):
        """
        Run ML-based anomaly detection for this request.

        - Always extracts features and logs an AnomalyScore row.
        - If an active model exists, uses it to compute anomaly_score + is_anomaly.
        - Optionally blocks if score exceeds threshold.
        """
        
        # If ML globally disabled in settings, do nothing
        if not getattr(settings, "WAF_ML_ENABLED", False):
            return None

        if not getattr(settings, "WAF_ML_FEATURE_EXTRACTION_ENABLED", True):
            return None

        try:
            # 1) Extract features + signature
            features = FeatureExtractor.extract_features(request)
            signature = FeatureExtractor.create_request_signature(request)
        except Exception as e:
            logger.exception(f"ML feature extraction failed: {e}")
            return None

        anomaly_score = 0.0
        is_anomaly = False

        # 2) Try to load active anomaly model for this tenant
        model_obj = MLModel.objects.filter(
            tenant=tenant,
            model_type="anomaly_detector",
            is_active=True,
        ).order_by("-model_version").first()

        if model_obj and model_obj.model_data:
            try:
                detector = AnomalyDetector.deserialize(model_obj.model_data)
                anomaly_score, is_anomaly = detector.predict(features)
                logger.debug(
                    "ML anomaly prediction: score=%.3f, is_anomaly=%s",
                    anomaly_score,
                    is_anomaly,
                )
            except Exception as e:
                logger.exception(f"Failed to run ML prediction: {e}")
                # fall back to "no anomaly"
                anomaly_score = 0.0
                is_anomaly = False
        else:
            # No trained model yet – just collect baseline data
            logger.debug("No active ML model for tenant, logging baseline features only")

        # 3) Decide whether to block based on score
        threshold = getattr(settings, "WAF_ML_ANOMALY_THRESHOLD", 0.7)
        should_block = bool(is_anomaly and anomaly_score >= threshold)

        # 4) Persist AnomalyScore row so training can use it later
        try:
            AnomalyScore.objects.create(
                tenant=tenant,
                request_signature=signature,
                source_ip=client_ip,
                request_path=request.path,
                request_method=request.method,
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                features=features,
                was_blocked=should_block,
                blocking_rule=None,
            )
        except Exception as e:
            logger.exception(f"Failed to log AnomalyScore: {e}")

        # 5) If ML says block, return a blocking response
        if should_block:
            resp = HttpResponseForbidden(
                "<h1>403 Forbidden</h1><p>Your request was flagged as anomalous by ML.</p>"
            )
            return {"is_blocked": True, "response": resp}

        # Otherwise, let WAF continue checking rules
        return {"is_blocked": False}

