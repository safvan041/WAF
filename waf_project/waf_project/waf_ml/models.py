from django.db import models
from waf_project.waf_core.models import Tenant, FirewallRule, SecurityEvent
import uuid


class TrafficPattern(models.Model):
    """Stores aggregated traffic statistics for baseline establishment"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='traffic_patterns')
    
    # Time window
    time_window_start = models.DateTimeField()
    time_window_end = models.DateTimeField()
    window_duration_minutes = models.IntegerField(default=60)
    
    # Traffic statistics
    request_count = models.IntegerField(default=0)
    unique_ips = models.IntegerField(default=0)
    avg_request_size = models.FloatField(default=0.0)
    avg_response_time = models.FloatField(default=0.0)
    
    # Common patterns (stored as JSON)
    common_paths = models.JSONField(default=list, help_text="Most frequently accessed paths")
    common_user_agents = models.JSONField(default=list, help_text="Most common user agents")
    common_methods = models.JSONField(default=dict, help_text="HTTP method distribution")
    
    # Feature statistics for ML
    avg_path_depth = models.FloatField(default=0.0)
    avg_param_count = models.FloatField(default=0.0)
    avg_header_count = models.FloatField(default=0.0)
    avg_entropy = models.FloatField(default=0.0)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-time_window_start']
        indexes = [
            models.Index(fields=['tenant', 'time_window_start']),
        ]
        verbose_name = "Traffic Pattern"
        verbose_name_plural = "Traffic Patterns"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.time_window_start.strftime('%Y-%m-%d %H:%M')}"


class MLModel(models.Model):
    """Stores trained machine learning models"""
    
    MODEL_TYPES = [
        ('anomaly_detector', 'Anomaly Detector'),
        ('rule_suggester', 'Rule Suggester'),
        ('pattern_classifier', 'Pattern Classifier'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='ml_models')
    
    # Model information
    model_type = models.CharField(max_length=50, choices=MODEL_TYPES)
    model_version = models.IntegerField(default=1)
    
    # Serialized model data (pickled scikit-learn model)
    model_data = models.BinaryField(help_text="Serialized model using joblib")
    
    # Performance metrics
    accuracy_score = models.FloatField(default=0.0)
    precision_score = models.FloatField(default=0.0)
    recall_score = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    
    # Training information
    training_samples_count = models.IntegerField(default=0)
    training_duration_seconds = models.FloatField(default=0.0)
    trained_at = models.DateTimeField(auto_now_add=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Metadata
    training_config = models.JSONField(default=dict, help_text="Hyperparameters and config")
    
    class Meta:
        ordering = ['-trained_at']
        unique_together = ['tenant', 'model_type', 'model_version']
        indexes = [
            models.Index(fields=['tenant', 'model_type', 'is_active']),
        ]
        verbose_name = "ML Model"
        verbose_name_plural = "ML Models"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.model_type} v{self.model_version}"


class RuleLearningHistory(models.Model):
    """Tracks firewall rule performance over time"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule = models.ForeignKey(FirewallRule, on_delete=models.CASCADE, related_name='learning_history')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='rule_histories')
    
    # Performance metrics
    true_positives = models.IntegerField(default=0, help_text="Correctly blocked attacks")
    false_positives = models.IntegerField(default=0, help_text="Incorrectly blocked legitimate requests")
    true_negatives = models.IntegerField(default=0, help_text="Correctly allowed legitimate requests")
    false_negatives = models.IntegerField(default=0, help_text="Missed attacks")
    
    # Calculated scores
    confidence_score = models.FloatField(default=0.5, help_text="Overall rule confidence (0-1)")
    precision = models.FloatField(default=0.0)
    recall = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    
    # Time window
    evaluation_period_start = models.DateTimeField()
    evaluation_period_end = models.DateTimeField()
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-last_updated']
        indexes = [
            models.Index(fields=['rule', 'tenant']),
            models.Index(fields=['tenant', 'confidence_score']),
        ]
        verbose_name = "Rule Learning History"
        verbose_name_plural = "Rule Learning Histories"
    
    def __str__(self):
        return f"{self.rule.name} - Confidence: {self.confidence_score:.2f}"
    
    def calculate_metrics(self):
        """Calculate precision, recall, and F1 score"""
        tp = self.true_positives
        fp = self.false_positives
        fn = self.false_negatives
        
        # Precision: TP / (TP + FP)
        if tp + fp > 0:
            self.precision = tp / (tp + fp)
        else:
            self.precision = 0.0
        
        # Recall: TP / (TP + FN)
        if tp + fn > 0:
            self.recall = tp / (tp + fn)
        else:
            self.recall = 0.0
        
        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
        
        # Confidence score (weighted combination)
        # Higher weight on precision to minimize false positives
        self.confidence_score = (0.6 * self.precision) + (0.4 * self.recall)
        
        self.save()


class FalsePositiveFeedback(models.Model):
    """Captures user feedback on blocked requests"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    security_event = models.ForeignKey(SecurityEvent, on_delete=models.CASCADE, related_name='feedback')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='false_positive_feedback')
    
    # Feedback details
    is_false_positive = models.BooleanField(default=True)
    user_comment = models.TextField(blank=True)
    reported_by = models.CharField(max_length=100, help_text="User who reported this")
    
    # Resolution
    resolved = models.BooleanField(default=False)
    resolution_action = models.CharField(max_length=200, blank=True, 
                                        help_text="Action taken to resolve")
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'resolved']),
            models.Index(fields=['security_event']),
        ]
        verbose_name = "False Positive Feedback"
        verbose_name_plural = "False Positive Feedback"
    
    def __str__(self):
        status = "Resolved" if self.resolved else "Pending"
        return f"{self.tenant.name} - {status} - {self.created_at.strftime('%Y-%m-%d')}"


class AdaptiveRule(models.Model):
    """Auto-generated rules pending approval"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('auto_approved', 'Auto-Approved'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='adaptive_rules')
    
    # Rule details
    suggested_name = models.CharField(max_length=200)
    suggested_pattern = models.TextField(help_text="Regex pattern for the rule")
    rule_type = models.CharField(max_length=50, choices=FirewallRule.RULE_TYPES)
    suggested_action = models.CharField(max_length=20, choices=FirewallRule.ACTION_CHOICES, default='block')
    suggested_severity = models.CharField(max_length=10, choices=FirewallRule.SEVERITY_CHOICES, default='medium')
    
    # ML confidence
    confidence_score = models.FloatField(help_text="ML confidence in this rule (0-1)")
    
    # Supporting evidence
    supporting_events = models.JSONField(default=list, help_text="Security event IDs that support this rule")
    attack_count = models.IntegerField(default=0, help_text="Number of attacks this would have blocked")
    pattern_frequency = models.IntegerField(default=0, help_text="How often this pattern appears")
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_by_ml = models.BooleanField(default=True)
    
    # Review information
    reviewed_by = models.CharField(max_length=100, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)
    
    # If approved, link to created rule
    created_rule = models.ForeignKey(FirewallRule, on_delete=models.SET_NULL, 
                                    null=True, blank=True, related_name='source_adaptive_rule')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-confidence_score', '-created_at']
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['confidence_score']),
        ]
        verbose_name = "Adaptive Rule"
        verbose_name_plural = "Adaptive Rules"
    
    def __str__(self):
        return f"{self.suggested_name} - {self.status} (Confidence: {self.confidence_score:.2f})"
    
    def approve(self, reviewed_by):
        """Approve the rule and create a FirewallRule"""
        from django.utils import timezone
        from waf_project.waf_core.models import TenantFirewallConfig
        
        # Create the actual firewall rule
        firewall_rule = FirewallRule.objects.create(
            name=self.suggested_name,
            description=f"Auto-generated rule (Confidence: {self.confidence_score:.2f})",
            rule_type=self.rule_type,
            pattern=self.suggested_pattern,
            action=self.suggested_action,
            severity=self.suggested_severity,
            is_custom=True,
        )
        
        # Create the tenant-firewall config link so the rule appears for this tenant
        TenantFirewallConfig.objects.create(
            tenant=self.tenant,
            rule=firewall_rule,
            is_enabled=True,
        )
        
        # Update adaptive rule status
        self.status = 'approved'
        self.reviewed_by = reviewed_by
        self.reviewed_at = timezone.now()
        self.created_rule = firewall_rule
        self.save()
        
        return firewall_rule


class AnomalyScore(models.Model):
    """Real-time anomaly scores for requests"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='anomaly_scores')
    
    # Request identification
    request_signature = models.CharField(max_length=64, help_text="Hash of request characteristics")
    source_ip = models.GenericIPAddressField()
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    
    # Anomaly detection
    anomaly_score = models.FloatField(help_text="Anomaly score from ML model (0-1, higher = more anomalous)")
    is_anomaly = models.BooleanField(default=False, help_text="Score exceeded threshold")
    
    # Features used for detection (stored as JSON)
    features = models.JSONField(default=dict, help_text="Extracted features for this request")
    
    # Action taken
    was_blocked = models.BooleanField(default=False)
    blocking_rule = models.ForeignKey(FirewallRule, on_delete=models.SET_NULL, 
                                     null=True, blank=True, related_name='anomaly_blocks')
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['anomaly_score']),
            models.Index(fields=['is_anomaly', 'timestamp']),
        ]
        verbose_name = "Anomaly Score"
        verbose_name_plural = "Anomaly Scores"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.source_ip} - Score: {self.anomaly_score:.3f}"
