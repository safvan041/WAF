# waf_engine/models.py

from django.db import models

class WAFRule(models.Model):
    """
    A model to store WAF rules.
    """
    ACTION_CHOICES = [
        ('BLOCK', 'Block Request'),
        ('LOG', 'Log Only'),
        ('REDIRECT', 'Redirect Request'),
    ]
    
    name = models.CharField(max_length=255, unique=True, help_text="A unique name for the rule.")
    pattern = models.CharField(max_length=255, help_text="The regex pattern to match against.")
    action = models.CharField(max_length=10, choices=ACTION_CHOICES, default='BLOCK', help_text="The action to take when the pattern is matched.")
    is_active = models.BooleanField(default=True, help_text="Whether the rule is currently active.")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name