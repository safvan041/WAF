# waf_engine/serializers.py
from rest_framework import serializers
from waf_project.waf_core.models import FirewallRule, Tenant

class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'domain', 'additional_domains',
            'origin_url', 'waf_host',  # New reverse proxy fields
            'contact_email', 'contact_name', 'contact_phone',
            'status', 'plan', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'api_key']

class FirewallRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = FirewallRule
        fields = '__all__'