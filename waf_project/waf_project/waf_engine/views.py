# waf_engine/views.py
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from waf_project.waf_core.models import FirewallRule, TenantFirewallConfig
from .serializers import FirewallRuleSerializer
from django.shortcuts import get_object_or_404

class FirewallRuleViewSet(viewsets.ModelViewSet):
    queryset = FirewallRule.objects.all()
    serializer_class = FirewallRuleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Filters the queryset to return only rules belonging to the current user's tenant.
        """
        user = self.request.user
        if user.is_superuser:
            return FirewallRule.objects.all()
        
        # Get all rules configured for the current user's tenant
        configured_rules = TenantFirewallConfig.objects.filter(
            tenant=user.tenant,
            is_enabled=True
        ).values_list('rule_id', flat=True)
        
        # Return the FirewallRule objects that are in the list
        return FirewallRule.objects.filter(id__in=configured_rules)

    def perform_create(self, serializer):
        """
        Ensures a new rule is automatically assigned to the current user's tenant.
        This will also create a TenantFirewallConfig entry.
        """
        user = self.request.user
        if user.is_superuser:
            # For superusers, save the rule directly
            serializer.save()
        else:
            # For tenant users, save the rule and create a TenantFirewallConfig entry
            rule = serializer.save()
            TenantFirewallConfig.objects.create(
                tenant=user.tenant,
                rule=rule,
                is_enabled=True
            )
            
    def perform_update(self, serializer):
        """
        Ensures a tenant user can only update their own rules.
        """
        user = self.request.user
        if user.is_superuser:
            # Superusers can update any rule
            serializer.save()
            return
            
        # Get the rule instance being updated
        rule_instance = self.get_object()
        
        # Check if the rule is linked to the user's tenant
        if not TenantFirewallConfig.objects.filter(tenant=user.tenant, rule=rule_instance).exists():
            raise serializers.ValidationError("You do not have permission to edit this rule.")
            
        serializer.save()