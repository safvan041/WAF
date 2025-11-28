"""
REST API serializers for WAF ML module
"""

from rest_framework import serializers
from .models import (
    AdaptiveRule,
    FalsePositiveFeedback,
    AnomalyScore,
    MLModel,
    RuleLearningHistory,
    TrafficPattern
)
from waf_project.waf_core.models import SecurityEvent


class AdaptiveRuleSerializer(serializers.ModelSerializer):
    created_rule_name = serializers.CharField(source='created_rule.name', read_only=True, allow_null=True)
    
    class Meta:
        model = AdaptiveRule
        fields = [
            'id', 'tenant', 'suggested_name', 'suggested_pattern',
            'rule_type', 'suggested_action', 'suggested_severity',
            'confidence_score', 'supporting_events', 'attack_count',
            'pattern_frequency', 'status', 'created_by_ml',
            'reviewed_by', 'reviewed_at', 'review_notes',
            'created_rule', 'created_rule_name', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_rule', 'created_rule_name']


class FalsePositiveFeedbackSerializer(serializers.ModelSerializer):
    event_details = serializers.SerializerMethodField()
    
    class Meta:
        model = FalsePositiveFeedback
        fields = [
            'id', 'security_event', 'tenant', 'is_false_positive',
            'user_comment', 'reported_by', 'resolved', 'resolution_action',
            'resolved_at', 'created_at', 'updated_at', 'event_details'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'tenant', 'reported_by']
    
    def get_event_details(self, obj):
        event = obj.security_event
        return {
            'event_type': event.event_type,
            'source_ip': event.source_ip,
            'request_url': event.request_url,
            'timestamp': event.timestamp
        }


class AnomalyScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnomalyScore
        fields = [
            'id', 'tenant', 'request_signature', 'source_ip',
            'request_path', 'request_method', 'anomaly_score',
            'is_anomaly', 'features', 'was_blocked', 'blocking_rule',
            'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class MLModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModel
        fields = [
            'id', 'tenant', 'model_type', 'model_version',
            'accuracy_score', 'precision_score', 'recall_score', 'f1_score',
            'training_samples_count', 'training_duration_seconds',
            'trained_at', 'is_active', 'training_config'
        ]
        read_only_fields = ['id', 'trained_at']


class RuleLearningHistorySerializer(serializers.ModelSerializer):
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    
    class Meta:
        model = RuleLearningHistory
        fields = [
            'id', 'rule', 'rule_name', 'tenant', 'true_positives',
            'false_positives', 'true_negatives', 'false_negatives',
            'confidence_score', 'precision', 'recall', 'f1_score',
            'evaluation_period_start', 'evaluation_period_end',
            'created_at', 'last_updated'
        ]
        read_only_fields = ['id', 'created_at', 'last_updated', 'precision', 'recall', 'f1_score', 'confidence_score']


class TrafficPatternSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficPattern
        fields = [
            'id', 'tenant', 'time_window_start', 'time_window_end',
            'window_duration_minutes', 'request_count', 'unique_ips',
            'avg_request_size', 'avg_response_time', 'common_paths',
            'common_user_agents', 'common_methods', 'avg_path_depth',
            'avg_param_count', 'avg_header_count', 'avg_entropy',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']
