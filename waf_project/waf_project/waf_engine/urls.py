# waf_engine/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import FirewallRuleViewSet

router = DefaultRouter()
router.register(r'rules', FirewallRuleViewSet)

urlpatterns = [
    path('', include(router.urls)),
]