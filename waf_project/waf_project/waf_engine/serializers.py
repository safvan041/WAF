# waf_engine/serializers.py
from rest_framework import serializers
from waf_project.waf_core.models import FirewallRule

class FirewallRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = FirewallRule
        fields = '__all__'