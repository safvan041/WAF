"""
Tests for ML API endpoints
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from datetime import timedelta

from waf_project.waf_core.models import Tenant, User, FirewallRule, SecurityEvent
from waf_project.waf_ml.models import (
    AdaptiveRule,
    FalsePositiveFeedback,
    AnomalyScore,
    MLModel,
    RuleLearningHistory
)


class AdaptiveRuleAPITest(TestCase):
    """Test AdaptiveRule API endpoints"""
    
    def setUp(self):
        self.client = APIClient()
        
        # Create tenant
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        # Create user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@test.com',
            role='tenant_admin',
            tenant=self.tenant
        )
        
        # Authenticate
        self.client.force_authenticate(user=self.user)
    
    def test_list_adaptive_rules(self):
        """Test listing adaptive rules"""
        # Create some adaptive rules
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Test Rule 1",
            suggested_pattern=r'test_pattern_1',
            rule_type='custom',
            confidence_score=0.85,
            status='pending'
        )
        
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Test Rule 2",
            suggested_pattern=r'test_pattern_2',
            rule_type='sql_injection',
            confidence_score=0.92,
            status='approved'
        )
        
        url = reverse('waf_ml:adaptive-rule-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
    
    def test_get_pending_rules(self):
        """Test getting pending rules"""
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Pending Rule",
            suggested_pattern=r'pending',
            rule_type='custom',
            confidence_score=0.80,
            status='pending'
        )
        
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Approved Rule",
            suggested_pattern=r'approved',
            rule_type='custom',
            confidence_score=0.90,
            status='approved'
        )
        
        url = reverse('waf_ml:adaptive-rule-pending')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['status'], 'pending')
    
    def test_approve_adaptive_rule(self):
        """Test approving an adaptive rule"""
        rule = AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Test Rule",
            suggested_pattern=r'test',
            rule_type='custom',
            confidence_score=0.88,
            status='pending'
        )
        
        url = reverse('waf_ml:adaptive-rule-approve', kwargs={'pk': rule.pk})
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('firewall_rule_id', response.data)
        
        # Verify rule was approved
        rule.refresh_from_db()
        self.assertEqual(rule.status, 'approved')
        self.assertIsNotNone(rule.created_rule)
    
    def test_reject_adaptive_rule(self):
        """Test rejecting an adaptive rule"""
        rule = AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Test Rule",
            suggested_pattern=r'test',
            rule_type='custom',
            confidence_score=0.60,
            status='pending'
        )
        
        url = reverse('waf_ml:adaptive-rule-reject', kwargs={'pk': rule.pk})
        response = self.client.post(url, {'review_notes': 'Too many false positives'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify rule was rejected
        rule.refresh_from_db()
        self.assertEqual(rule.status, 'rejected')
        self.assertEqual(rule.review_notes, 'Too many false positives')


class FalsePositiveFeedbackAPITest(TestCase):
    """Test FalsePositiveFeedback API endpoints"""
    
    def setUp(self):
        self.client = APIClient()
        
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            role='tenant_admin',
            tenant=self.tenant
        )
        
        self.rule = FirewallRule.objects.create(
            name="Test Rule",
            rule_type='xss',
            pattern=r'<script',
            action='block'
        )
        
        self.event = SecurityEvent.objects.create(
            tenant=self.tenant,
            rule=self.rule,
            event_type='attack_blocked',
            severity='high',
            action_taken='block',
            source_ip='192.168.1.100',
            request_url='http://test.com/page'
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_create_feedback(self):
        """Test creating false positive feedback"""
        url = reverse('waf_ml:feedback-list')
        data = {
            'security_event': str(self.event.id),
            'tenant': str(self.tenant.id),
            'is_false_positive': True,
            'user_comment': 'This was legitimate',
            'reported_by': 'admin@test.com'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(FalsePositiveFeedback.objects.count(), 1)
    
    def test_resolve_feedback(self):
        """Test resolving feedback"""
        feedback = FalsePositiveFeedback.objects.create(
            security_event=self.event,
            tenant=self.tenant,
            is_false_positive=True,
            reported_by='admin@test.com'
        )
        
        url = reverse('waf_ml:feedback-resolve', kwargs={'pk': feedback.pk})
        response = self.client.post(url, {'resolution_action': 'Whitelisted IP'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        feedback.refresh_from_db()
        self.assertTrue(feedback.resolved)
        self.assertIsNotNone(feedback.resolved_at)


class AnomalyScoreAPITest(TestCase):
    """Test AnomalyScore API endpoints"""
    
    def setUp(self):
        self.client = APIClient()
        
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            role='tenant_admin',
            tenant=self.tenant
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_list_anomaly_scores(self):
        """Test listing anomaly scores"""
        # Create some anomaly scores
        for i in range(5):
            AnomalyScore.objects.create(
                tenant=self.tenant,
                request_signature=f'sig_{i}',
                source_ip=f'192.168.1.{i}',
                request_path='/api/test',
                request_method='GET',
                anomaly_score=0.5 + (i * 0.1),
                is_anomaly=i >= 3,
                features={'test': True}
            )
        
        url = reverse('waf_ml:anomaly-score-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 5)
    
    def test_get_trends(self):
        """Test getting anomaly trends"""
        # Create scores over multiple days
        now = timezone.now()
        for i in range(10):
            AnomalyScore.objects.create(
                tenant=self.tenant,
                request_signature=f'sig_{i}',
                source_ip='192.168.1.1',
                request_path='/api/test',
                request_method='GET',
                anomaly_score=0.6,
                is_anomaly=i % 2 == 0,
                features={}
            )
        
        url = reverse('waf_ml:anomaly-score-trends')
        response = self.client.get(url, {'days': 7})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)
    
    def test_get_high_risk_anomalies(self):
        """Test getting high-risk anomalies"""
        # Create mix of low and high risk scores
        AnomalyScore.objects.create(
            tenant=self.tenant,
            request_signature='low_risk',
            source_ip='192.168.1.1',
            request_path='/api/test',
            request_method='GET',
            anomaly_score=0.3,
            is_anomaly=False,
            features={}
        )
        
        AnomalyScore.objects.create(
            tenant=self.tenant,
            request_signature='high_risk',
            source_ip='192.168.1.2',
            request_path='/api/admin',
            request_method='POST',
            anomaly_score=0.95,
            is_anomaly=True,
            features={}
        )
        
        url = reverse('waf_ml:anomaly-score-high-risk')
        response = self.client.get(url, {'threshold': 0.8})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['request_signature'], 'high_risk')


class MLInsightsAPITest(TestCase):
    """Test ML Insights API endpoint"""
    
    def setUp(self):
        self.client = APIClient()
        
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            role='tenant_admin',
            tenant=self.tenant
        )
        
        self.client.force_authenticate(user=self.user)
    
    def test_get_insights(self):
        """Test getting ML insights"""
        # Create some test data
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Rule 1",
            suggested_pattern=r'test',
            rule_type='custom',
            confidence_score=0.8,
            status='pending'
        )
        
        AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Rule 2",
            suggested_pattern=r'test2',
            rule_type='custom',
            confidence_score=0.9,
            status='approved'
        )
        
        MLModel.objects.create(
            tenant=self.tenant,
            model_type='anomaly_detector',
            model_version=1,
            model_data=b'test',
            is_active=True
        )
        
        url = reverse('waf_ml:ml-insights-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('adaptive_rules', response.data)
        self.assertIn('ml_models', response.data)
        self.assertIn('anomalies', response.data)
        self.assertIn('feedback', response.data)
        
        self.assertEqual(response.data['adaptive_rules']['total'], 2)
        self.assertEqual(response.data['adaptive_rules']['pending_review'], 1)
        self.assertEqual(response.data['ml_models']['active'], 1)


class APIPermissionsTest(TestCase):
    """Test API permissions"""
    
    def setUp(self):
        self.client = APIClient()
        
        self.tenant1 = Tenant.objects.create(
            name="Tenant 1",
            domain="tenant1.com",
            contact_email="test1@test.com",
            contact_name="Test User 1"
        )
        
        self.tenant2 = Tenant.objects.create(
            name="Tenant 2",
            domain="tenant2.com",
            contact_email="test2@test.com",
            contact_name="Test User 2"
        )
        
        self.user1 = User.objects.create_user(
            username='user1',
            password='pass123',
            role='tenant_admin',
            tenant=self.tenant1
        )
        
        self.user2 = User.objects.create_user(
            username='user2',
            password='pass123',
            role='tenant_admin',
            tenant=self.tenant2
        )
    
    def test_tenant_isolation(self):
        """Test that users can only see their tenant's data"""
        # Create rules for both tenants
        rule1 = AdaptiveRule.objects.create(
            tenant=self.tenant1,
            suggested_name="Tenant 1 Rule",
            suggested_pattern=r'test1',
            rule_type='custom',
            confidence_score=0.8
        )
        
        rule2 = AdaptiveRule.objects.create(
            tenant=self.tenant2,
            suggested_name="Tenant 2 Rule",
            suggested_pattern=r'test2',
            rule_type='custom',
            confidence_score=0.8
        )
        
        # User 1 should only see their rules
        self.client.force_authenticate(user=self.user1)
        url = reverse('waf_ml:adaptive-rule-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['suggested_name'], "Tenant 1 Rule")
    
    def test_unauthenticated_access(self):
        """Test that unauthenticated users cannot access API"""
        url = reverse('waf_ml:adaptive-rule-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
