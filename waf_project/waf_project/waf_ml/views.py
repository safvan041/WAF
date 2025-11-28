"""
REST API views for WAF ML module
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Avg, Q

from .models import (
    AdaptiveRule,
    FalsePositiveFeedback,
    AnomalyScore,
    MLModel,
    RuleLearningHistory,
    TrafficPattern
)
from .serializers import (
    AdaptiveRuleSerializer,
    FalsePositiveFeedbackSerializer,
    AnomalyScoreSerializer,
    MLModelSerializer,
    RuleLearningHistorySerializer,
    TrafficPatternSerializer
)
from waf_project.waf_core.models import SecurityEvent


class AdaptiveRuleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing adaptive rules
    """
    queryset = AdaptiveRule.objects.all()
    serializer_class = AdaptiveRuleSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return AdaptiveRule.objects.all()
        elif user.tenant:
            return AdaptiveRule.objects.filter(tenant=user.tenant)
        return AdaptiveRule.objects.none()
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve an adaptive rule"""
        adaptive_rule = self.get_object()
        
        if adaptive_rule.status != 'pending':
            return Response(
                {'error': 'Only pending rules can be approved'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            firewall_rule = adaptive_rule.approve(reviewed_by=request.user.username)
            return Response({
                'message': 'Rule approved successfully',
                'firewall_rule_id': str(firewall_rule.id),
                'firewall_rule_name': firewall_rule.name
            })
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject an adaptive rule"""
        adaptive_rule = self.get_object()
        
        if adaptive_rule.status != 'pending':
            return Response(
                {'error': 'Only pending rules can be rejected'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        review_notes = request.data.get('review_notes', '')
        
        adaptive_rule.status = 'rejected'
        adaptive_rule.reviewed_by = request.user.username
        adaptive_rule.reviewed_at = timezone.now()
        adaptive_rule.review_notes = review_notes
        adaptive_rule.save()
        
        return Response({'message': 'Rule rejected successfully'})
    
    @action(detail=False, methods=['get'])
    def pending(self, request):
        """Get all pending rules for review"""
        queryset = self.get_queryset().filter(status='pending').order_by('-confidence_score')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class FalsePositiveFeedbackViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing false positive feedback
    """
    queryset = FalsePositiveFeedback.objects.all()
    serializer_class = FalsePositiveFeedbackSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return FalsePositiveFeedback.objects.all()
        elif user.tenant:
            return FalsePositiveFeedback.objects.filter(tenant=user.tenant)
        return FalsePositiveFeedback.objects.none()
    
    def perform_create(self, serializer):
        """Auto-populate tenant and reported_by"""
        security_event = serializer.validated_data['security_event']
        serializer.save(
            tenant=security_event.tenant,
            reported_by=self.request.user.username
        )
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Mark feedback as resolved"""
        feedback = self.get_object()
        resolution_action = request.data.get('resolution_action', '')
        
        feedback.resolved = True
        feedback.resolved_at = timezone.now()
        feedback.resolution_action = resolution_action
        feedback.save()
        
        return Response({'message': 'Feedback marked as resolved'})


class AnomalyScoreViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing anomaly scores (read-only)
    """
    queryset = AnomalyScore.objects.all()
    serializer_class = AnomalyScoreSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return AnomalyScore.objects.all()
        elif user.tenant:
            return AnomalyScore.objects.filter(tenant=user.tenant)
        return AnomalyScore.objects.none()
    
    @action(detail=False, methods=['get'])
    def trends(self, request):
        """Get anomaly score trends over time"""
        days = int(request.query_params.get('days', 7))
        cutoff_date = timezone.now() - timedelta(days=days)
        
        queryset = self.get_queryset().filter(timestamp__gte=cutoff_date)
        
        # Group by day and calculate statistics
        trends = queryset.extra(
            select={'day': 'date(timestamp)'}
        ).values('day').annotate(
            total_requests=Count('id'),
            anomalies_detected=Count('id', filter=Q(is_anomaly=True)),
            avg_score=Avg('anomaly_score'),
            blocked_count=Count('id', filter=Q(was_blocked=True))
        ).order_by('day')
        
        return Response(list(trends))
    
    @action(detail=False, methods=['get'])
    def high_risk(self, request):
        """Get recent high-risk anomalies"""
        threshold = float(request.query_params.get('threshold', 0.8))
        limit = int(request.query_params.get('limit', 50))
        
        queryset = self.get_queryset().filter(
            anomaly_score__gte=threshold
        ).order_by('-timestamp')[:limit]
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class MLModelViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing ML models (read-only)
    """
    queryset = MLModel.objects.all()
    serializer_class = MLModelSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return MLModel.objects.all()
        elif user.tenant:
            return MLModel.objects.filter(tenant=user.tenant)
        return MLModel.objects.none()
    
    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get currently active models"""
        queryset = self.get_queryset().filter(is_active=True)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class RuleLearningHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing rule learning history (read-only)
    """
    queryset = RuleLearningHistory.objects.all()
    serializer_class = RuleLearningHistorySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return RuleLearningHistory.objects.all()
        elif user.tenant:
            return RuleLearningHistory.objects.filter(tenant=user.tenant)
        return RuleLearningHistory.objects.none()
    
    @action(detail=False, methods=['get'])
    def low_confidence(self, request):
        """Get rules with low confidence scores"""
        threshold = float(request.query_params.get('threshold', 0.5))
        
        queryset = self.get_queryset().filter(
            confidence_score__lt=threshold
        ).order_by('confidence_score')
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class TrafficPatternViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing traffic patterns (read-only)
    """
    queryset = TrafficPattern.objects.all()
    serializer_class = TrafficPatternSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter by user's tenant"""
        user = self.request.user
        if user.is_superadmin():
            return TrafficPattern.objects.all()
        elif user.tenant:
            return TrafficPattern.objects.filter(tenant=user.tenant)
        return TrafficPattern.objects.none()


class MLInsightsViewSet(viewsets.ViewSet):
    """
    API endpoint for ML insights and analytics
    """
    permission_classes = [IsAuthenticated]
    
    def list(self, request):
        """Get overall ML insights"""
        user = request.user
        
        if not user.tenant and not user.is_superadmin():
            return Response({'error': 'No tenant associated'}, status=status.HTTP_403_FORBIDDEN)
        
        tenant = user.tenant if user.tenant else None
        
        # Get statistics
        if tenant:
            adaptive_rules_count = AdaptiveRule.objects.filter(tenant=tenant).count()
            pending_rules = AdaptiveRule.objects.filter(tenant=tenant, status='pending').count()
            active_models = MLModel.objects.filter(tenant=tenant, is_active=True).count()
            
            # Recent anomalies
            recent_anomalies = AnomalyScore.objects.filter(
                tenant=tenant,
                timestamp__gte=timezone.now() - timedelta(days=7),
                is_anomaly=True
            ).count()
            
            # False positive rate
            total_feedback = FalsePositiveFeedback.objects.filter(tenant=tenant).count()
            resolved_feedback = FalsePositiveFeedback.objects.filter(tenant=tenant, resolved=True).count()
            
        else:
            # Superadmin - aggregate across all tenants
            adaptive_rules_count = AdaptiveRule.objects.count()
            pending_rules = AdaptiveRule.objects.filter(status='pending').count()
            active_models = MLModel.objects.filter(is_active=True).count()
            recent_anomalies = AnomalyScore.objects.filter(
                timestamp__gte=timezone.now() - timedelta(days=7),
                is_anomaly=True
            ).count()
            total_feedback = FalsePositiveFeedback.objects.count()
            resolved_feedback = FalsePositiveFeedback.objects.filter(resolved=True).count()
        
        return Response({
            'adaptive_rules': {
                'total': adaptive_rules_count,
                'pending_review': pending_rules
            },
            'ml_models': {
                'active': active_models
            },
            'anomalies': {
                'last_7_days': recent_anomalies
            },
            'feedback': {
                'total': total_feedback,
                'resolved': resolved_feedback,
                'pending': total_feedback - resolved_feedback
            }
        })
