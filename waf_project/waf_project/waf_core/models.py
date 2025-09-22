from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import URLValidator
import uuid

# --- Core Platform Models ---

class Tenant(models.Model):
    """Model representing a tenant/customer using the WAF service"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
        ('trial', 'Trial'),
    ]

    PLAN_CHOICES = [
        ('free', 'Free'),
        ('basic', 'Basic'),
        ('pro', 'Professional'),
        ('enterprise', 'Enterprise'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, help_text="Company/Organization name")
    domain = models.CharField(max_length=255, unique=True, help_text="Primary domain to protect (e.g., example.com)")
    additional_domains = models.TextField(blank=True,
                                         help_text="Additional domains (one per line)")

    # Contact information
    contact_email = models.EmailField()
    contact_name = models.CharField(max_length=100)
    contact_phone = models.CharField(max_length=20, blank=True)

    # Service details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='trial')
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='free')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Configuration
    api_key = models.CharField(max_length=64, unique=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Tenant"
        verbose_name_plural = "Tenants"

    def __str__(self):
        return f"{self.name} ({self.domain})"

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = uuid.uuid4().hex
        super().save(*args, **kwargs)

    def get_all_domains(self):
        """Return list of all domains (primary + additional)"""
        domains = [self.domain]
        if self.additional_domains:
            additional = [d.strip() for d in self.additional_domains.split('\n') if d.strip()]
            domains.extend(additional)
        return domains

class User(AbstractUser):
    ROLE_CHOICES = (
        ('superadmin', 'Super Admin'),
        ('tenant_admin', 'Tenant Admin'),
        ('analyst', 'Analyst'),
        ('user', 'User'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    tenant = models.ForeignKey('Tenant', on_delete=models.SET_NULL, null=True, blank=True)

    groups = models.ManyToManyField(
        Group,
        related_name="waf_core_users",  # 👈 prevents clash
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="waf_core_users",  # 👈 prevents clash
        blank=True
    )

    def is_superadmin(self):
        return self.role == 'superadmin' or self.is_superuser

    def is_tenant_admin(self):
        return self.role == 'tenant_admin' and self.tenant is not None

# --- WAF Rules and Configuration Models ---

class FirewallRule(models.Model):
    """Model for defining general WAF rules"""

    RULE_TYPES = [
        ('sql_injection', 'SQL Injection Protection'),
        ('xss', 'Cross-Site Scripting (XSS) Protection'),
        ('bot_protection', 'Bot Protection'),
        ('rate_limiting', 'Rate Limiting'),
        ('geo_blocking', 'Geographic Blocking'),
        ('ip_whitelist', 'IP Whitelist'),
        ('ip_blacklist', 'IP Blacklist'),
        ('custom', 'Custom Rule'),
    ]

    ACTION_CHOICES = [
        ('block', 'Block Request'),
        ('allow', 'Allow Request'),
        ('log', 'Log Only'),
        ('challenge', 'Challenge (Captcha)'),
        ('rate_limit', 'Rate Limit'),
    ]

    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    rule_type = models.CharField(max_length=50, choices=RULE_TYPES)

    # Rule configuration
    pattern = models.TextField(blank=True, # This line is changed to make the field optional
                              help_text="Regex pattern or rule definition")
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='block')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')


    # Targeting
    target_field = models.CharField(max_length=50, default='all',
                                   help_text="Target field: all, headers, body, url, etc.")

    # Status
    is_active = models.BooleanField(default=True)
    is_custom = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-severity', 'name']
        verbose_name = "Firewall Rule"
        verbose_name_plural = "Firewall Rules"

    def __str__(self):
        return f"{self.name} ({self.rule_type})"

class TenantFirewallConfig(models.Model):
    """Configuration linking tenants to firewall rules"""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='firewall_configs')
    rule = models.ForeignKey(FirewallRule, on_delete=models.CASCADE, related_name='tenant_configs')

    # Override settings
    is_enabled = models.BooleanField(default=True)
    custom_action = models.CharField(max_length=20, choices=FirewallRule.ACTION_CHOICES,
                                   blank=True, help_text="Override default rule action")
    custom_threshold = models.IntegerField(null=True, blank=True,
                                          help_text="Custom threshold for rate limiting")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['tenant', 'rule']
        ordering = ['rule__severity', 'rule__name']
        verbose_name = "Tenant Firewall Configuration"
        verbose_name_plural = "Tenant Firewall Configurations"

    def __str__(self):
        return f"{self.tenant.name} - {self.rule.name}"

    def get_effective_action(self):
        """Get the effective action (custom or default)"""
        return self.custom_action if self.custom_action else self.rule.action

class RateLimitConfig(models.Model):
    """Configuration for rate limiting per tenant"""

    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='rate_limit_config')

    # Rate limiting settings
    requests_per_minute = models.IntegerField(default=60)
    requests_per_hour = models.IntegerField(default=1000)
    requests_per_day = models.IntegerField(default=10000)

    # Burst allowance
    burst_allowance = models.IntegerField(default=10,
                                         help_text="Additional requests allowed in burst")

    # IP-based rate limiting
    per_ip_requests_per_minute = models.IntegerField(default=10)
    per_ip_requests_per_hour = models.IntegerField(default=100)

    # Whitelist settings
    whitelist_bypass = models.BooleanField(default=True,
                                          help_text="Allow whitelisted IPs to bypass rate limits")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Rate Limit Configuration"
        verbose_name_plural = "Rate Limit Configurations"

    def __str__(self):
        return f"{self.tenant.name} - Rate Limit Config"

class IPWhitelist(models.Model):
    """IP addresses whitelisted for a tenant"""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='ip_whitelist')
    ip_address = models.GenericIPAddressField()
    cidr_range = models.CharField(max_length=50, blank=True,
                                 help_text="CIDR notation for IP ranges (e.g., 192.168.1.0/24)")
    description = models.CharField(max_length=200, blank=True)

    # Status
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['tenant', 'ip_address']
        verbose_name = "IP Whitelist Entry"
        verbose_name_plural = "IP Whitelist Entries"

    def __str__(self):
        return f"{self.tenant.name} - {self.ip_address}"

class IPBlacklist(models.Model):
    """IP addresses blacklisted for a tenant"""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='ip_blacklist')
    ip_address = models.GenericIPAddressField()
    cidr_range = models.CharField(max_length=50, blank=True)
    reason = models.CharField(max_length=200, help_text="Reason for blacklisting")

    # Auto-blacklist settings
    auto_added = models.BooleanField(default=False, help_text="Automatically added by WAF")
    threat_score_threshold = models.IntegerField(null=True, blank=True,
                                                help_text="Threat score that triggered auto-blacklist")

    # Expiration
    expires_at = models.DateTimeField(null=True, blank=True,
                                     help_text="Automatic expiration time (optional)")

    # Status
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['tenant', 'ip_address']
        verbose_name = "IP Blacklist Entry"
        verbose_name_plural = "IP Blacklist Entries"

    def __str__(self):
        return f"{self.tenant.name} - {self.ip_address}"

class GeographicRule(models.Model):
    """Geographic blocking rules for tenants"""

    ACTION_CHOICES = [
        ('allow', 'Allow'),
        ('block', 'Block'),
        ('challenge', 'Challenge'),
    ]

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='geo_rules')

    # Geographic targeting
    country_code = models.CharField(max_length=2, help_text="ISO 3166-1 alpha-2 country code")
    country_name = models.CharField(max_length=100)

    # Action to take
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='block')

    # Status
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['tenant', 'country_code']
        verbose_name = "Geographic Rule"
        verbose_name_plural = "Geographic Rules"

    def __str__(self):
        return f"{self.tenant.name} - {self.country_name} ({self.action})"

class WAFConfiguration(models.Model):
    """Overall WAF configuration for a tenant"""

    PROTECTION_LEVELS = [
        ('low', 'Low - Basic protection'),
        ('medium', 'Medium - Standard protection'),
        ('high', 'High - Aggressive protection'),
        ('custom', 'Custom - User-defined rules'),
    ]

    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='waf_config')
    
    # General settings
    protection_level = models.CharField(max_length=10, choices=PROTECTION_LEVELS, default='medium')
    is_enabled = models.BooleanField(default=True)

    # Feature toggles
    sql_injection_protection = models.BooleanField(default=True)
    xss_protection = models.BooleanField(default=True)
    bot_protection = models.BooleanField(default=True)
    rate_limiting_enabled = models.BooleanField(default=True)
    geographic_blocking_enabled = models.BooleanField(default=False)

    # Sensitivity settings
    sql_injection_sensitivity = models.IntegerField(default=5,
                                                   help_text="Sensitivity level 1-10 (10 = most sensitive)")
    xss_sensitivity = models.IntegerField(default=5)
    bot_sensitivity = models.IntegerField(default=5)

    # Response settings
    block_page_content = models.TextField(blank=True,
                                         help_text="Custom HTML content for blocked requests")
    challenge_type = models.CharField(max_length=20, default='captcha',
                                     choices=[('captcha', 'CAPTCHA'), ('js_challenge', 'JavaScript Challenge')])

    # Logging settings
    log_all_requests = models.BooleanField(default=False,
                                          help_text="Log all requests (not just threats)")
    log_request_body = models.BooleanField(default=False,
                                          help_text="Include request body in logs")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "WAF Configuration"
        verbose_name_plural = "WAF Configurations"

    def __str__(self):
        return f"{self.tenant.name} - WAF Config ({self.protection_level})"

class SecurityEvent(models.Model):
    """Model for logging security events and attacks"""

    EVENT_TYPES = [
        ('attack_blocked', 'Attack Blocked'),
        ('attack_logged', 'Attack Logged'),
        ('rate_limited', 'Rate Limited'),
        ('bot_detected', 'Bot Detected'),
        ('geo_blocked', 'Geographic Block'),
        ('whitelist_pass', 'Whitelist Pass'),
        ('custom_rule', 'Custom Rule Triggered'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='security_events')
    rule = models.ForeignKey(FirewallRule, on_delete=models.SET_NULL, null=True, blank=True)

    # Event details
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=FirewallRule.SEVERITY_CHOICES)
    action_taken = models.CharField(max_length=20, choices=FirewallRule.ACTION_CHOICES)

    # Request details
    source_ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    request_method = models.CharField(
        max_length=10, 
        default='UNKNOWN', # Add this line
        help_text="The HTTP method of the request."
    )
    request_url = models.URLField()
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True)

    # Location data (if available)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)

    # Attack details
    attack_pattern = models.TextField(blank=True, help_text="Matched pattern or signature")
    threat_score = models.IntegerField(default=0, help_text="Threat score (0-100)")

    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['source_ip', 'timestamp']),
            models.Index(fields=['event_type', 'timestamp']),
        ]
        verbose_name = "Security Event"
        verbose_name_plural = "Security Events"

    def __str__(self):
        return f"{self.tenant.name} - {self.event_type} from {self.source_ip}"

class DailyReport(models.Model):
    """Model for storing daily security reports"""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='daily_reports')
    report_date = models.DateField()

    # Statistics
    total_requests = models.IntegerField(default=0)
    blocked_requests = models.IntegerField(default=0)
    allowed_requests = models.IntegerField(default=0)
    threat_score_avg = models.FloatField(default=0.0)

    # Attack breakdown
    sql_injection_attempts = models.IntegerField(default=0)
    xss_attempts = models.IntegerField(default=0)
    bot_requests = models.IntegerField(default=0)
    rate_limited_requests = models.IntegerField(default=0)
    geo_blocked_requests = models.IntegerField(default=0)

    # Top statistics (JSON fields)
    top_attacking_ips = models.JSONField(default=list, help_text="Top 10 attacking IPs")
    top_attack_types = models.JSONField(default=list, help_text="Most common attack types")
    top_targeted_urls = models.JSONField(default=list, help_text="Most targeted URLs")

    # Report metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    is_sent = models.BooleanField(default=False, help_text="Email sent to tenant")

    class Meta:
        unique_together = ['tenant', 'report_date']
        ordering = ['-report_date']
        verbose_name = "Daily Report"
        verbose_name_plural = "Daily Reports"

    def __str__(self):
        return f"{self.tenant.name} - {self.report_date}"

    @property
    def block_rate(self):
        """Calculate block rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.blocked_requests / self.total_requests) * 100