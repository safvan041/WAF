"""
URL configuration for WAF ML API
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'adaptive-rules', views.AdaptiveRuleViewSet, basename='adaptive-rule')
router.register(r'feedback', views.FalsePositiveFeedbackViewSet, basename='feedback')
router.register(r'anomaly-scores', views.AnomalyScoreViewSet, basename='anomaly-score')
router.register(r'ml-models', views.MLModelViewSet, basename='ml-model')
router.register(r'rule-history', views.RuleLearningHistoryViewSet, basename='rule-history')
router.register(r'traffic-patterns', views.TrafficPatternViewSet, basename='traffic-pattern')
router.register(r'insights', views.MLInsightsViewSet, basename='ml-insights')

app_name = 'waf_ml'

urlpatterns = [
    path('', include(router.urls)),
]
