# waf_core/models.py

from django.db import models

class SecurityEvent(models.Model):
    """
    A model to log security events detected by the WAF.
    """
    EVENT_CHOICES = [
        ('SQLI', 'SQL Injection'),
        ('XSS', 'Cross-Site Scripting'),
        ('LFI', 'Local File Inclusion'),
        ('RCE', 'Remote Code Execution'),
        ('OTHER', 'Other'),
    ]

    ACTION_CHOICES = [
        ('BLOCKED', 'Blocked'),
        ('LOGGED', 'Logged'),
        ('ALLOWED', 'Allowed'),
    ]

    source_ip = models.GenericIPAddressField(help_text="The source IP address of the request.")
    event_type = models.CharField(max_length=10, choices=EVENT_CHOICES, help_text="The type of security event.")
    rule_name = models.CharField(max_length=255, help_text="The name of the rule that was triggered.")
    action_taken = models.CharField(max_length=10, choices=ACTION_CHOICES, help_text="The action taken by the WAF.")
    details = models.TextField(help_text="Detailed information about the request.")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_type} event from {self.source_ip}"