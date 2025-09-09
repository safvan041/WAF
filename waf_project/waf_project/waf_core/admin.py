# waf_core/admin.py
from django.contrib import admin
from .models import SecurityEvent

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('source_ip', 'event_type', 'rule_name', 'action_taken', 'timestamp')
    list_filter = ('event_type', 'action_taken')
    search_fields = ('source_ip', 'details')