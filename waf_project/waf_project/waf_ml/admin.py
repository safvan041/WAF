from django.contrib import admin
from .models import (
    TrafficPattern,
    MLModel,
    RuleLearningHistory,
    FalsePositiveFeedback,
    AdaptiveRule,
    AnomalyScore,
)


@admin.register(TrafficPattern)
class TrafficPatternAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'time_window_start', 'request_count', 'unique_ips', 'created_at']
    list_filter = ['tenant', 'time_window_start']
    search_fields = ['tenant__name']
    readonly_fields = ['created_at']
    ordering = ['-time_window_start']


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'model_type', 'model_version', 'accuracy_score', 
                   'is_active', 'trained_at']
    list_filter = ['tenant', 'model_type', 'is_active']
    search_fields = ['tenant__name']
    readonly_fields = ['trained_at', 'model_data']
    ordering = ['-trained_at']
    
    fieldsets = (
        ('Model Information', {
            'fields': ('tenant', 'model_type', 'model_version', 'is_active')
        }),
        ('Performance Metrics', {
            'fields': ('accuracy_score', 'precision_score', 'recall_score', 'f1_score')
        }),
        ('Training Information', {
            'fields': ('training_samples_count', 'training_duration_seconds', 
                      'trained_at', 'training_config')
        }),
        ('Model Data', {
            'fields': ('model_data',),
            'classes': ('collapse',)
        }),
    )


@admin.register(RuleLearningHistory)
class RuleLearningHistoryAdmin(admin.ModelAdmin):
    list_display = ['rule', 'tenant', 'confidence_score', 'precision', 'recall', 
                   'f1_score', 'last_updated']
    list_filter = ['tenant', 'confidence_score']
    search_fields = ['rule__name', 'tenant__name']
    readonly_fields = ['created_at', 'last_updated', 'precision', 'recall', 
                      'f1_score', 'confidence_score']
    ordering = ['-confidence_score']
    
    fieldsets = (
        ('Rule Information', {
            'fields': ('rule', 'tenant', 'evaluation_period_start', 'evaluation_period_end')
        }),
        ('Performance Metrics', {
            'fields': ('true_positives', 'false_positives', 'true_negatives', 'false_negatives')
        }),
        ('Calculated Scores', {
            'fields': ('confidence_score', 'precision', 'recall', 'f1_score')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_updated')
        }),
    )
    
    actions = ['recalculate_metrics']
    
    def recalculate_metrics(self, request, queryset):
        for history in queryset:
            history.calculate_metrics()
        self.message_user(request, f"Recalculated metrics for {queryset.count()} rule histories.")
    recalculate_metrics.short_description = "Recalculate metrics"


@admin.register(FalsePositiveFeedback)
class FalsePositiveFeedbackAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'security_event', 'is_false_positive', 'resolved', 
                   'reported_by', 'created_at']
    list_filter = ['tenant', 'is_false_positive', 'resolved', 'created_at']
    search_fields = ['tenant__name', 'reported_by', 'user_comment']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Feedback Information', {
            'fields': ('security_event', 'tenant', 'is_false_positive', 
                      'reported_by', 'user_comment')
        }),
        ('Resolution', {
            'fields': ('resolved', 'resolution_action', 'resolved_at')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    actions = ['mark_as_resolved']
    
    def mark_as_resolved(self, request, queryset):
        from django.utils import timezone
        queryset.update(resolved=True, resolved_at=timezone.now())
        self.message_user(request, f"Marked {queryset.count()} feedback items as resolved.")
    mark_as_resolved.short_description = "Mark as resolved"


@admin.register(AdaptiveRule)
class AdaptiveRuleAdmin(admin.ModelAdmin):
    list_display = ['suggested_name', 'tenant', 'confidence_score', 'status', 
                   'attack_count', 'created_at']
    list_filter = ['tenant', 'status', 'rule_type', 'suggested_severity']
    search_fields = ['suggested_name', 'tenant__name', 'suggested_pattern']
    readonly_fields = ['created_at', 'updated_at', 'reviewed_at', 'created_rule']
    ordering = ['-confidence_score', '-created_at']
    
    fieldsets = (
        ('Rule Details', {
            'fields': ('tenant', 'suggested_name', 'suggested_pattern', 
                      'rule_type', 'suggested_action', 'suggested_severity')
        }),
        ('ML Confidence', {
            'fields': ('confidence_score', 'attack_count', 'pattern_frequency')
        }),
        ('Supporting Evidence', {
            'fields': ('supporting_events',),
            'classes': ('collapse',)
        }),
        ('Review Status', {
            'fields': ('status', 'reviewed_by', 'reviewed_at', 'review_notes', 'created_rule')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    actions = ['approve_rules', 'reject_rules']
    
    def approve_rules(self, request, queryset):
        approved_count = 0
        for adaptive_rule in queryset.filter(status='pending'):
            adaptive_rule.approve(reviewed_by=request.user.username)
            approved_count += 1
        self.message_user(request, f"Approved {approved_count} adaptive rules.")
    approve_rules.short_description = "Approve selected rules"
    
    def reject_rules(self, request, queryset):
        from django.utils import timezone
        queryset.filter(status='pending').update(
            status='rejected',
            reviewed_by=request.user.username,
            reviewed_at=timezone.now()
        )
        self.message_user(request, f"Rejected {queryset.count()} adaptive rules.")
    reject_rules.short_description = "Reject selected rules"


@admin.register(AnomalyScore)
class AnomalyScoreAdmin(admin.ModelAdmin):
    list_display = ['tenant', 'source_ip', 'request_path', 'anomaly_score', 
                   'is_anomaly', 'was_blocked', 'timestamp']
    list_filter = ['tenant', 'is_anomaly', 'was_blocked', 'timestamp']
    search_fields = ['source_ip', 'request_path', 'tenant__name']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Request Information', {
            'fields': ('tenant', 'source_ip', 'request_path', 'request_method', 
                      'request_signature')
        }),
        ('Anomaly Detection', {
            'fields': ('anomaly_score', 'is_anomaly', 'features')
        }),
        ('Action Taken', {
            'fields': ('was_blocked', 'blocking_rule')
        }),
        ('Timestamp', {
            'fields': ('timestamp',)
        }),
    )
