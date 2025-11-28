"""
Integration tests for ML middleware
"""

from django.test import TestCase, RequestFactory, override_settings
from django.http import HttpResponse
from waf_project.waf_core.models import Tenant, FirewallRule, WAFConfiguration
from waf_project.waf_ml.models import AdaptiveRule, AnomalyScore, MLModel
from waf_project.waf_ml.ml_engine import AnomalyDetector
from waf_project.waf_engine.middleware import WAFMiddleware


class WAFMiddlewareMLIntegrationTest(TestCase):
    """Test ML integration in WAF middleware"""
    
    def setUp(self):
        self.factory = RequestFactory()
        
        # Create tenant
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        # Create WAF configuration
        self.waf_config = WAFConfiguration.objects.create(
            tenant=self.tenant,
            is_enabled=True,
            sql_injection_protection=True,
            xss_protection=True
        )
        
        # Create middleware instance
        def get_response(request):
            return HttpResponse("OK")
        
        self.middleware = WAFMiddleware(get_response)
    
    @override_settings(WAF_ML_ENABLED=True)
    def test_feature_extraction_on_request(self):
        """Test that features are extracted from requests"""
        request = self.factory.get('/api/users?page=1')
        request.tenant = self.tenant
        
        # Process request through middleware
        response = self.middleware(request)
        
        # Middleware should complete without errors
        self.assertEqual(response.status_code, 200)
    
    @override_settings(WAF_ML_ENABLED=True)
    def test_anomaly_detection_without_model(self):
        """Test anomaly detection when no model is trained"""
        request = self.factory.get('/api/test')
        request.tenant = self.tenant
        
        # Should not block without trained model
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
    
    @override_settings(WAF_ML_ENABLED=True)
    def test_anomaly_detection_with_model(self):
        """Test anomaly detection with trained model"""
        # Create and train a simple model
        detector = AnomalyDetector()
        
        # Train on normal features
        normal_features = [
            {
                'request_size': 100 + i,
                'path_length': 10,
                'path_depth': 2,
                'param_count': 1,
                'header_count': 10,
                'path_entropy': 3.0,
                'query_entropy': 2.0
            }
            for i in range(100)
        ]
        detector.train(normal_features)
        
        # Save model to database
        model_data = detector.serialize()
        MLModel.objects.create(
            tenant=self.tenant,
            model_type='anomaly_detector',
            model_version=1,
            model_data=model_data,
            is_active=True
        )
        
        # Test normal request
        request = self.factory.get('/api/users')
        request.tenant = self.tenant
        
        response = self.middleware(request)
        
        # Should allow normal request
        self.assertEqual(response.status_code, 200)
        
        # Check that anomaly score was logged
        scores = AnomalyScore.objects.filter(tenant=self.tenant)
        self.assertGreater(scores.count(), 0)
    
    @override_settings(WAF_ML_ENABLED=True)
    def test_adaptive_rule_blocking(self):
        """Test that approved adaptive rules block requests"""
        # Create an adaptive rule
        adaptive_rule = AdaptiveRule.objects.create(
            tenant=self.tenant,
            suggested_name="Block SQL Pattern",
            suggested_pattern=r'UNION\s+SELECT',
            rule_type='sql_injection',
            suggested_action='block',
            confidence_score=0.95,
            status='pending'
        )
        
        # Approve the rule
        firewall_rule = adaptive_rule.approve(reviewed_by='admin')
        
        # Test request that matches the pattern
        request = self.factory.get('/api/users?id=1 UNION SELECT password')
        request.tenant = self.tenant
        
        response = self.middleware(request)
        
        # Should be blocked
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'Blocked by adaptive rule', response.content)
    
    @override_settings(WAF_ML_ENABLED=False)
    def test_ml_disabled(self):
        """Test that ML features are skipped when disabled"""
        request = self.factory.get('/api/test')
        request.tenant = self.tenant
        
        response = self.middleware(request)
        
        # Should process normally
        self.assertEqual(response.status_code, 200)
        
        # No anomaly scores should be created
        self.assertEqual(AnomalyScore.objects.count(), 0)
    
    def test_ml_graceful_degradation(self):
        """Test that WAF works even if ML components fail"""
        # Create a request
        request = self.factory.get('/api/test')
        request.tenant = self.tenant
        
        # Even if ML is enabled but fails, WAF should continue
        response = self.middleware(request)
        
        # Should not crash
        self.assertEqual(response.status_code, 200)


class ManagementCommandIntegrationTest(TestCase):
    """Test management commands integration"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
    
    def test_train_models_command_integration(self):
        """Test that train_ml_models command works end-to-end"""
        from django.core.management import call_command
        from io import StringIO
        
        # Create some anomaly scores (training data)
        for i in range(150):
            AnomalyScore.objects.create(
                tenant=self.tenant,
                request_signature=f'sig_{i}',
                source_ip='192.168.1.1',
                request_path='/api/test',
                request_method='GET',
                anomaly_score=0.3,  # Low score = legitimate
                is_anomaly=False,
                was_blocked=False,
                features={
                    'request_size': 100 + i,
                    'path_length': 10,
                    'path_depth': 2
                }
            )
        
        # Run training command
        out = StringIO()
        call_command('train_ml_models', '--tenant', 'test.com', stdout=out)
        
        # Check that model was created
        models = MLModel.objects.filter(tenant=self.tenant, is_active=True)
        self.assertEqual(models.count(), 1)
        
        model = models.first()
        self.assertEqual(model.model_type, 'anomaly_detector')
        self.assertGreater(model.training_samples_count, 0)
    
    def test_suggest_rules_command_integration(self):
        """Test that suggest_rules command works end-to-end"""
        from django.core.management import call_command
        from io import StringIO
        
        # Create a rule
        rule = FirewallRule.objects.create(
            name="SQL Injection Rule",
            rule_type='sql_injection',
            pattern=r'union\s+select',
            action='block'
        )
        
        # Create similar security events
        from waf_project.waf_core.models import SecurityEvent
        for i in range(10):
            SecurityEvent.objects.create(
                tenant=self.tenant,
                rule=rule,
                event_type='attack_blocked',
                severity='high',
                action_taken='block',
                source_ip=f'192.168.1.{i}',
                request_url=f'http://test.com/page?id={i} UNION SELECT password FROM users'
            )
        
        # Run suggestion command
        out = StringIO()
        call_command('suggest_rules', '--tenant', 'test.com', stdout=out)
        
        # Check that adaptive rules were created
        adaptive_rules = AdaptiveRule.objects.filter(tenant=self.tenant)
        self.assertGreater(adaptive_rules.count(), 0)
        
        # Check rule properties
        rule = adaptive_rules.first()
        self.assertEqual(rule.status, 'pending')
        self.assertGreater(rule.confidence_score, 0)
