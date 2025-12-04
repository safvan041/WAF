from django.contrib import admin
from .models import IPReputationScore, RateLimitViolation, GeoBlockEvent


@admin.register(IPReputationScore)
class IPReputationScoreAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 'tenant', 'reputation_score', 'reputation_level',
        'total_violations', 'is_blocked', 'last_seen'
    ]
    list_filter = ['tenant', 'reputation_level', 'is_blocked', 'auto_blocked']
    search_fields = ['ip_address', 'tenant__name']
    readonly_fields = [
        'first_seen', 'last_seen', 'last_violation', 'blocked_at',
        'total_violations', 'sql_injection_attempts', 'xss_attempts',
        'rate_limit_violations', 'bot_detections'
    ]
    fieldsets = (
        ('Basic Information', {
            'fields': ('tenant', 'ip_address')
        }),
        ('Reputation', {
            'fields': ('reputation_score', 'reputation_level')
        }),
        ('Violations', {
            'fields': (
                'total_violations', 'sql_injection_attempts', 'xss_attempts',
                'rate_limit_violations', 'bot_detections'
            )
        }),
        ('Blocking', {
            'fields': ('is_blocked', 'auto_blocked', 'block_reason', 'blocked_at')
        }),
        ('Timestamps', {
            'fields': ('first_seen', 'last_seen', 'last_violation')
        }),
    )
    
    actions = ['block_ips', 'unblock_ips', 'reset_scores']
    
    def block_ips(self, request, queryset):
        from .ip_reputation import IPReputationManager
        count = 0
        for reputation in queryset:
            IPReputationManager.manual_block(
                reputation.tenant,
                reputation.ip_address,
                f"Manually blocked by {request.user.username}"
            )
            count += 1
        self.message_user(request, f"Blocked {count} IP(s)")
    block_ips.short_description = "Block selected IPs"
    
    def unblock_ips(self, request, queryset):
        from .ip_reputation import IPReputationManager
        count = 0
        for reputation in queryset:
            IPReputationManager.unblock(reputation.tenant, reputation.ip_address)
            count += 1
        self.message_user(request, f"Unblocked {count} IP(s)")
    unblock_ips.short_description = "Unblock selected IPs"
    
    def reset_scores(self, request, queryset):
        count = queryset.update(reputation_score=0, total_violations=0)
        self.message_user(request, f"Reset scores for {count} IP(s)")
    reset_scores.short_description = "Reset reputation scores"


@admin.register(RateLimitViolation)
class RateLimitViolationAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 'tenant', 'limit_type', 'current_count',
        'limit_value', 'request_path', 'timestamp'
    ]
    list_filter = ['tenant', 'limit_type', 'timestamp']
    search_fields = ['ip_address', 'tenant__name', 'request_path']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False  # Read-only
    
    def has_change_permission(self, request, obj=None):
        return False  # Read-only


@admin.register(GeoBlockEvent)
class GeoBlockEventAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 'tenant', 'country_name', 'country_code',
        'action', 'request_path', 'timestamp'
    ]
    list_filter = ['tenant', 'country_code', 'action', 'timestamp']
    search_fields = ['ip_address', 'tenant__name', 'country_name', 'request_path']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False  # Read-only
    
    def has_change_permission(self, request, obj=None):
        return False  # Read-only
