from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    Tenant, 
    User, 
    FirewallRule, 
    TenantFirewallConfig, 
    SecurityEvent, 
    DailyReport,
    RateLimitConfig,
    IPWhitelist,
    IPBlacklist,
    GeographicRule,
    WAFConfiguration
)

# Register all models in the admin panel
@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'domain', 'origin_url', 'waf_host', 'status', 'plan', 'is_active', 'created_at')
    list_filter = ('status', 'plan', 'is_active')
    search_fields = ('name', 'domain', 'waf_host', 'contact_email')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'domain', 'additional_domains')
        }),
        ('Reverse Proxy Configuration', {
            'fields': ('origin_url', 'waf_host'),
            'description': 'Configure where to forward allowed traffic and the WAF subdomain'
        }),
        ('Contact Information', {
            'fields': ('contact_email', 'contact_name', 'contact_phone')
        }),
        ('Service Details', {
            'fields': ('status', 'plan', 'is_active')
        }),
        ('Advanced', {
            'fields': ('api_key',),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'tenant', 'is_staff', 'is_superuser')
    list_filter = ('role', 'tenant', 'is_staff', 'is_superuser')

    fieldsets = UserAdmin.fieldsets + (
        ('Tenant & Role Info', {'fields': ('tenant', 'role')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Tenant & Role Info', {'fields': ('tenant', 'role')}),
    )

    search_fields = ('username', 'email')
    ordering = ('username',)

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'rule_type', 'action', 'severity', 'is_active')
    list_filter = ('rule_type', 'action', 'severity', 'is_active')
    search_fields = ('name', 'pattern')

@admin.register(TenantFirewallConfig)
class TenantFirewallConfigAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'rule', 'is_enabled', 'get_effective_action')
    list_filter = ('tenant', 'rule__rule_type', 'is_enabled')
    search_fields = ('tenant__name', 'rule__name')

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'rule', 'event_type', 'action_taken', 'source_ip', 'timestamp')
    list_filter = ('tenant', 'event_type', 'action_taken')
    search_fields = ('source_ip', 'request_url')

@admin.register(DailyReport)
class DailyReportAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'report_date', 'total_requests', 'blocked_requests', 'block_rate', 'is_sent')
    list_filter = ('tenant', 'report_date', 'is_sent')
    search_fields = ('tenant__name', 'report_date')

@admin.register(RateLimitConfig)
class RateLimitConfigAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'requests_per_minute', 'requests_per_hour', 'per_ip_requests_per_minute')
    list_filter = ('tenant',)

@admin.register(IPWhitelist)
class IPWhitelistAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'ip_address', 'is_active')
    list_filter = ('tenant', 'is_active')
    search_fields = ('ip_address', 'cidr_range')

@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'ip_address', 'is_active', 'expires_at')
    list_filter = ('tenant', 'is_active', 'expires_at')
    search_fields = ('ip_address', 'reason')

@admin.register(GeographicRule)
class GeographicRuleAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'country_code', 'action', 'is_active')
    list_filter = ('tenant', 'action', 'is_active')
    search_fields = ('country_code', 'country_name')

@admin.register(WAFConfiguration)
class WAFConfigurationAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'protection_level', 'is_enabled', 'sql_injection_protection', 'xss_protection')
    list_filter = ('tenant', 'protection_level', 'is_enabled')
