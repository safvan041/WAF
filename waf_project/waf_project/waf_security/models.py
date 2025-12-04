from django.db import models
from django.utils import timezone
from waf_project.waf_core.models import Tenant
import uuid


class IPReputationScore(models.Model):
    """
    Tracks IP reputation scores per tenant for automatic blocking.
    Each tenant maintains independent IP reputation data.
    """
    REPUTATION_CHOICES = [
        ('excellent', 'Excellent (0-20)'),
        ('good', 'Good (21-40)'),
        ('neutral', 'Neutral (41-60)'),
        ('suspicious', 'Suspicious (61-80)'),
        ('malicious', 'Malicious (81-100)'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='ip_reputations')
    ip_address = models.GenericIPAddressField()
    
    # Reputation scoring
    reputation_score = models.IntegerField(
        default=0,
        help_text="Reputation score 0-100 (higher = more malicious)"
    )
    reputation_level = models.CharField(
        max_length=20,
        choices=REPUTATION_CHOICES,
        default='neutral'
    )
    
    # Violation tracking
    total_violations = models.IntegerField(default=0)
    sql_injection_attempts = models.IntegerField(default=0)
    xss_attempts = models.IntegerField(default=0)
    rate_limit_violations = models.IntegerField(default=0)
    bot_detections = models.IntegerField(default=0)
    
    # Status
    is_blocked = models.BooleanField(default=False)
    auto_blocked = models.BooleanField(
        default=False,
        help_text="Automatically blocked by reputation system"
    )
    block_reason = models.TextField(blank=True)
    
    # Timestamps
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_violation = models.DateTimeField(null=True, blank=True)
    blocked_at = models.DateTimeField(null=True, blank=True)
    
    # Decay tracking
    last_decay = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['tenant', 'ip_address']
        ordering = ['-reputation_score', '-last_seen']
        indexes = [
            models.Index(fields=['tenant', 'ip_address']),
            models.Index(fields=['tenant', 'reputation_score']),
            models.Index(fields=['is_blocked']),
        ]
        verbose_name = "IP Reputation Score"
        verbose_name_plural = "IP Reputation Scores"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.ip_address} (Score: {self.reputation_score})"
    
    def update_reputation_level(self):
        """Update reputation level based on score"""
        if self.reputation_score <= 20:
            self.reputation_level = 'excellent'
        elif self.reputation_score <= 40:
            self.reputation_level = 'good'
        elif self.reputation_score <= 60:
            self.reputation_level = 'neutral'
        elif self.reputation_score <= 80:
            self.reputation_level = 'suspicious'
        else:
            self.reputation_level = 'malicious'
    
    def save(self, *args, **kwargs):
        self.update_reputation_level()
        super().save(*args, **kwargs)


class RateLimitViolation(models.Model):
    """
    Logs rate limit violations for analytics and IP reputation tracking.
    """
    LIMIT_TYPE_CHOICES = [
        ('per_minute', 'Per Minute'),
        ('per_hour', 'Per Hour'),
        ('per_day', 'Per Day'),
        ('per_ip_minute', 'Per IP Per Minute'),
        ('per_ip_hour', 'Per IP Per Hour'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='rate_violations')
    
    # Request details
    ip_address = models.GenericIPAddressField()
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    user_agent = models.TextField(blank=True)
    
    # Violation details
    limit_type = models.CharField(max_length=20, choices=LIMIT_TYPE_CHOICES)
    limit_value = models.IntegerField(help_text="The rate limit threshold")
    current_count = models.IntegerField(help_text="Current request count when violated")
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['limit_type', 'timestamp']),
        ]
        verbose_name = "Rate Limit Violation"
        verbose_name_plural = "Rate Limit Violations"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.ip_address} - {self.limit_type} at {self.timestamp}"


class GeoBlockEvent(models.Model):
    """
    Tracks geo-blocking events for analytics and reporting.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='geo_block_events')
    
    # Request details
    ip_address = models.GenericIPAddressField()
    country_code = models.CharField(max_length=2)
    country_name = models.CharField(max_length=100)
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    user_agent = models.TextField(blank=True)
    
    # Action taken
    action = models.CharField(
        max_length=20,
        choices=[('block', 'Blocked'), ('allow', 'Allowed'), ('challenge', 'Challenged')],
        default='block'
    )
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['country_code', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
        verbose_name = "Geo-Block Event"
        verbose_name_plural = "Geo-Block Events"
    
    def __str__(self):
        return f"{self.tenant.name} - {self.country_name} - {self.action} at {self.timestamp}"
