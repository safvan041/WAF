"""
Tests for WAF ML models
"""

from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import Tenant, FirewallRule, SecurityEvent
from waf_project.waf_ml.models import (
    TrafficPattern,
    MLModel,
    RuleLearningHistory,
    FalsePositiveFeedback,
    AdaptiveRule,
    AnomalyScore
)


class TrafficPatternModelTest(TestCase):
    """Test TrafficPattern model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
    
    def test_create_traffic_pattern(self):
        """Test creating a traffic pattern"""
        now = timezone.now()
        pattern = TrafficPattern.objects.create(
            tenant=self.tenant,
            time_window_start=now,
            time_window_end=now + timedelta(hours=1),
            window_duration_minutes=60,
            request_count=1000,
            unique_ips=50,
            avg_request_size=2048.5,
            avg_response_time=150.3,
            common_paths=['/api/users', '/api/posts'],
            common_user_agents=['Mozilla/5.0', 'Chrome/90.0'],
            common_methods={'GET': 800, 'POST': 200},
            avg_path_depth=2.5,
            avg_param_count=3.2,
            avg_header_count=15.0,
            avg_entropy=4.5
        )
        
        self.assertEqual(pattern.tenant, self.tenant)
        self.assertEqual(pattern.request_count, 1000)
        self.assertEqual(pattern.unique_ips, 50)
        self.assertEqual(len(pattern.common_paths), 2)
        self.assertIn('GET', pattern.common_methods)
    
    def test_traffic_pattern_str(self):
        """Test string representation"""
        now = timezone.now()
        pattern = TrafficPattern.objects.create(
            tenant=self.tenant,
            time_window_start=now,
            time_window_end=now + timedelta(hours=1),
            request_count=100
        )
        
        self.assertIn(self.tenant.name, str(pattern))


class MLModelTest(TestCase):
    """Test MLModel model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
    
    def test_create_ml_model(self):
        """Test creating an ML model"""
        model = MLModel.objects.create(
            tenant=self.tenant,
            model_type='anomaly_detector',
            model_version=1,
            model_data=b'test_model_data',
            accuracy_score=0.95,
            precision_score=0.92,
            recall_score=0.88,
            f1_score=0.90,
            training_samples_count=1000,
            training_duration_seconds=45.5,
            is_active=True,
            training_config={'contamination': 0.1}
        )
        
        self.assertEqual(model.tenant, self.tenant)
        self.assertEqual(model.model_type, 'anomaly_detector')
        self.assertEqual(model.model_version, 1)
        self.assertTrue(model.is_active)
        self.assertEqual(model.accuracy_score, 0.95)
    
    def test_unique_together_constraint(self):
        """Test unique constraint on tenant, model_type, version"""
        MLModel.objects.create(
            tenant=self.tenant,
            model_type='anomaly_detector',
            model_version=1,
            model_data=b'test'
        )
        
        # Should raise error for duplicate
        with self.assertRaises(Exception):
            MLModel.objects.create(
                tenant=self.tenant,
                model_type='anomaly_detector',
                model_version=1,
                model_data=b'test2'
            )


class RuleLearningHistoryTest(TestCase):
    """Test RuleLearningHistory model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        self.rule = FirewallRule.objects.create(
            name="Test SQL Injection Rule",
            rule_type='sql_injection',
            pattern=r'(union|select|insert)',
            action='block'
        )
    
    def test_create_learning_history(self):
        """Test creating rule learning history"""
        now = timezone.now()
        history = RuleLearningHistory.objects.create(
            rule=self.rule,
            tenant=self.tenant,
            true_positives=100,
            false_positives=5,
            true_negatives=1000,
            false_negatives=2,
            evaluation_period_start=now - timedelta(days=7),
            evaluation_period_end=now
        )
        
        self.assertEqual(history.true_positives, 100)
        self.assertEqual(history.false_positives, 5)
    
    def test_calculate_metrics(self):
        """Test metric calculation"""
        now = timezone.now()
        history = RuleLearningHistory.objects.create(
            rule=self.rule,
            tenant=self.tenant,
            true_positives=100,
            false_positives=10,
            true_negatives=1000,
            false_negatives=5,
            evaluation_period_start=now - timedelta(days=7),
            evaluation_period_end=now
        )
        
        history.calculate_metrics()
        
        # Precision = TP / (TP + FP) = 100 / 110 = 0.909
        self.assertAlmostEqual(history.precision, 0.909, places=2)
        
        # Recall = TP / (TP + FN) = 100 / 105 = 0.952
        self.assertAlmostEqual(history.recall, 0.952, places=2)
        
        # F1 Score
        self.assertGreater(history.f1_score, 0)
        
        # Confidence score (weighted)
        self.assertGreater(history.confidence_score, 0)
        self.assertLessEqual(history.confidence_score, 1.0)


class FalsePositiveFeedbackTest(TestCase):
    """Test FalsePositiveFeedback model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
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
    
    def test_create_feedback(self):
        """Test creating false positive feedback"""
        feedback = FalsePositiveFeedback.objects.create(
            security_event=self.event,
            tenant=self.tenant,
            is_false_positive=True,
            user_comment="This was a legitimate request",
            reported_by="admin@test.com",
            resolved=False
        )
        
        self.assertTrue(feedback.is_false_positive)
        self.assertFalse(feedback.resolved)
        self.assertEqual(feedback.reported_by, "admin@test.com")
    
    def test_resolve_feedback(self):
        """Test resolving feedback"""
        feedback = FalsePositiveFeedback.objects.create(
            security_event=self.event,
            tenant=self.tenant,
            is_false_positive=True,
            reported_by="admin@test.com"
        )
        
        feedback.resolved = True
        feedback.resolved_at = timezone.now()
        feedback.resolution_action = "Whitelisted IP"
        feedback.save()
        
        self.assertTrue(feedback.resolved)
        self.assertIsNotNone(feedback.resolved_at)


class AdaptiveRuleTest(TestCase):
    """Test AdaptiveRule model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
    
    def test_create_adaptive_rule(self):
        """Test creating an adaptive rule"""
        rule = AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Auto-detected SQL injection pattern",
            suggested_pattern=r'union\s+select',
            rule_type='sql_injection',
            suggested_action='block',
            suggested_severity='high',
            confidence_score=0.85,
            supporting_events=['event-1', 'event-2', 'event-3'],
            attack_count=15,
            pattern_frequency=20,
            status='pending'
        )
        
        self.assertEqual(rule.status, 'pending')
        self.assertEqual(rule.confidence_score, 0.85)
        self.assertEqual(rule.attack_count, 15)
    
    def test_approve_adaptive_rule(self):
        """Test approving an adaptive rule"""
        adaptive_rule = AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Test Pattern",
            suggested_pattern=r'test_pattern',
            rule_type='custom',
            confidence_score=0.90,
            status='pending'
        )
        
        firewall_rule = adaptive_rule.approve(reviewed_by='admin')
        
        self.assertEqual(adaptive_rule.status, 'approved')
        self.assertIsNotNone(adaptive_rule.reviewed_at)
        self.assertEqual(adaptive_rule.reviewed_by, 'admin')
        self.assertIsNotNone(adaptive_rule.created_rule)
        self.assertEqual(firewall_rule.pattern, r'test_pattern')


class AnomalyScoreTest(TestCase):
    """Test AnomalyScore model"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
    
    def test_create_anomaly_score(self):
        """Test creating an anomaly score"""
        score = AnomalyScore.objects.create(
            tenant=self.tenant,
            request_signature='abc123def456',
            source_ip='192.168.1.100',
            request_path='/api/users',
            request_method='GET',
            anomaly_score=0.75,
            is_anomaly=True,
            features={
                'request_size': 1024,
                'path_depth': 2,
                'entropy': 4.5
            },
            was_blocked=False
        )
        
        self.assertEqual(score.anomaly_score, 0.75)
        self.assertTrue(score.is_anomaly)
        self.assertFalse(score.was_blocked)
        self.assertIn('entropy', score.features)
    
    def test_high_anomaly_score(self):
        """Test high anomaly score detection"""
        score = AnomalyScore.objects.create(
            tenant=self.tenant,
            request_signature='xyz789',
            source_ip='10.0.0.1',
            request_path='/admin/delete',
            request_method='POST',
            anomaly_score=0.95,
            is_anomaly=True,
            features={'suspicious': True},
            was_blocked=True
        )
        
        self.assertGreater(score.anomaly_score, 0.9)
        self.assertTrue(score.was_blocked)
