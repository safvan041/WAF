# waf_engine/admin.py
from django.contrib import admin
from .models import WAFRule

@admin.register(WAFRule)
class WAFRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'pattern', 'action', 'is_active', 'created_at')
    list_filter = ('action', 'is_active')
    search_fields = ('name', 'pattern')