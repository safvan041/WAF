"""
Tests for ML engine components
"""

from django.test import TestCase, RequestFactory
from waf_project.waf_ml.ml_engine import (
    FeatureExtractor,
    AnomalyDetector,
    RuleSuggestionEngine,
    RuleOptimizer
)
from waf_project.waf_core.models import Tenant, FirewallRule, SecurityEvent
from django.utils import timezone
from datetime import timedelta


class FeatureExtractorTest(TestCase):
    """Test FeatureExtractor class"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.extractor = FeatureExtractor()
    
    def test_extract_basic_features(self):
        """Test basic feature extraction"""
        request = self.factory.get('/api/users?page=1&limit=10')
        features = self.extractor.extract_features(request)
        
        # Check that features are returned
        self.assertIsInstance(features, dict)
        self.assertIn('request_size', features)
        self.assertIn('path_length', features)
        self.assertIn('path_depth', features)
        self.assertIn('param_count', features)
        
        # Check values
        self.assertEqual(features['path_depth'], 2)  # /api/users
        self.assertEqual(features['param_count'], 2)  # page and limit
        self.assertEqual(features['method_get'], 1.0)
    
    def test_extract_post_features(self):
        """Test feature extraction for POST request"""
        request = self.factory.post(
            '/api/login',
            data={'username': 'test', 'password': 'secret'},
            content_type='application/json'
        )
        features = self.extractor.extract_features(request)
        
        self.assertEqual(features['method_post'], 1.0)
        self.assertEqual(features['method_get'], 0.0)
        self.assertEqual(features['is_json'], 1.0)
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # High entropy (random-looking)
        high_entropy = self.extractor._calculate_entropy('aB3$xY9@zQ2!')
        
        # Low entropy (repetitive)
        low_entropy = self.extractor._calculate_entropy('aaaaaaa')
        
        self.assertGreater(high_entropy, low_entropy)
        self.assertGreater(high_entropy, 0)
    
    def test_special_char_ratio(self):
        """Test special character ratio calculation"""
        text = "hello@world!"  # 2 special chars out of 12
        ratio = self.extractor._special_char_ratio(text)
        
        self.assertAlmostEqual(ratio, 2/12, places=2)
    
    def test_sql_keyword_detection(self):
        """Test SQL keyword detection"""
        # Should detect SQL keywords
        self.assertTrue(self.extractor._has_sql_keywords("SELECT * FROM users"))
        self.assertTrue(self.extractor._has_sql_keywords("union select password"))
        
        # Should not detect in normal text
        self.assertFalse(self.extractor._has_sql_keywords("hello world"))
    
    def test_xss_pattern_detection(self):
        """Test XSS pattern detection"""
        # Should detect script tags
        self.assertTrue(self.extractor._has_script_tags("<script>alert(1)</script>"))
        self.assertTrue(self.extractor._has_script_tags("onerror=alert(1)"))
        
        # Should not detect in normal text
        self.assertFalse(self.extractor._has_script_tags("normal text"))
    
    def test_request_signature(self):
        """Test request signature generation"""
        request1 = self.factory.get('/api/users')
        request2 = self.factory.get('/api/users')
        request3 = self.factory.get('/api/posts')
        
        sig1 = self.extractor.create_request_signature(request1)
        sig2 = self.extractor.create_request_signature(request2)
        sig3 = self.extractor.create_request_signature(request3)
        
        # Same requests should have same signature
        self.assertEqual(sig1, sig2)
        
        # Different requests should have different signatures
        self.assertNotEqual(sig1, sig3)
        
        # Signature should be a hash
        self.assertEqual(len(sig1), 64)  # SHA256 hex digest


class AnomalyDetectorTest(TestCase):
    """Test AnomalyDetector class"""
    
    def test_detector_initialization(self):
        """Test detector initialization"""
        detector = AnomalyDetector(contamination=0.1, random_state=42)
        
        self.assertIsNotNone(detector.model)
        self.assertFalse(detector.is_trained)
    
    def test_training_with_insufficient_samples(self):
        """Test training with too few samples"""
        detector = AnomalyDetector()
        
        # Only 5 samples (need at least 10)
        features = [
            {'feature1': 1.0, 'feature2': 2.0},
            {'feature1': 1.1, 'feature2': 2.1},
            {'feature1': 0.9, 'feature2': 1.9},
            {'feature1': 1.2, 'feature2': 2.2},
            {'feature1': 0.8, 'feature2': 1.8},
        ]
        
        result = detector.train(features)
        
        self.assertIn('error', result)
        self.assertFalse(detector.is_trained)
    
    def test_training_with_sufficient_samples(self):
        """Test training with enough samples"""
        detector = AnomalyDetector()
        
        # Generate 100 normal samples
        features = [
            {
                'feature1': 1.0 + (i * 0.1),
                'feature2': 2.0 + (i * 0.1),
                'feature3': 3.0 + (i * 0.1)
            }
            for i in range(100)
        ]
        
        result = detector.train(features)
        
        self.assertNotIn('error', result)
        self.assertTrue(detector.is_trained)
        self.assertEqual(result['training_samples'], 100)
        self.assertGreater(result['training_duration_seconds'], 0)
    
    def test_prediction_without_training(self):
        """Test prediction before training"""
        detector = AnomalyDetector()
        
        features = {'feature1': 1.0, 'feature2': 2.0}
        score, is_anomaly = detector.predict(features)
        
        # Should return default values
        self.assertEqual(score, 0.0)
        self.assertFalse(is_anomaly)
    
    def test_prediction_after_training(self):
        """Test prediction after training"""
        detector = AnomalyDetector()
        
        # Train on normal data
        normal_features = [
            {'feature1': 1.0 + (i * 0.01), 'feature2': 2.0 + (i * 0.01)}
            for i in range(100)
        ]
        detector.train(normal_features)
        
        # Test normal sample
        normal_sample = {'feature1': 1.5, 'feature2': 2.5}
        score_normal, is_anomaly_normal = detector.predict(normal_sample)
        
        # Test anomalous sample (very different)
        anomalous_sample = {'feature1': 100.0, 'feature2': 200.0}
        score_anomalous, is_anomaly_anomalous = detector.predict(anomalous_sample)
        
        # Anomalous sample should have higher score
        self.assertGreater(score_anomalous, score_normal)
    
    def test_serialization(self):
        """Test model serialization and deserialization"""
        detector1 = AnomalyDetector()
        
        # Train the model
        features = [
            {'feature1': 1.0 + (i * 0.1), 'feature2': 2.0 + (i * 0.1)}
            for i in range(50)
        ]
        detector1.train(features)
        
        # Serialize
        model_data = detector1.serialize()
        self.assertIsInstance(model_data, bytes)
        self.assertGreater(len(model_data), 0)
        
        # Deserialize
        detector2 = AnomalyDetector.deserialize(model_data)
        self.assertTrue(detector2.is_trained)
        self.assertEqual(detector2.feature_names, detector1.feature_names)


class RuleSuggestionEngineTest(TestCase):
    """Test RuleSuggestionEngine class"""
    
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.com",
            contact_email="test@test.com",
            contact_name="Test User"
        )
        
        self.rule = FirewallRule.objects.create(
            name="SQL Injection Rule",
            rule_type='sql_injection',
            pattern=r'union\s+select',
            action='block'
        )
    
    def test_analyze_with_insufficient_events(self):
        """Test analysis with too few events"""
        # Create only 3 events (need at least 5)
        for i in range(3):
            SecurityEvent.objects.create(
                tenant=self.tenant,
                rule=self.rule,
                event_type='attack_blocked',
                severity='high',
                action_taken='block',
                source_ip=f'192.168.1.{i}',
                request_url=f'http://test.com/page?id={i} UNION SELECT password'
            )
        
        events = SecurityEvent.objects.filter(tenant=self.tenant)
        suggestions = RuleSuggestionEngine.analyze_attack_patterns(events)
        
        # Should return empty list (not enough events)
        self.assertEqual(len(suggestions), 0)
    
    def test_analyze_with_sufficient_events(self):
        """Test analysis with enough similar events"""
        # Create 10 similar SQL injection attempts
        for i in range(10):
            SecurityEvent.objects.create(
                tenant=self.tenant,
                rule=self.rule,
                event_type='attack_blocked',
                severity='high',
                action_taken='block',
                source_ip=f'192.168.1.{i}',
                request_url=f'http://test.com/page?id={i} UNION SELECT password FROM users'
            )
        
        events = SecurityEvent.objects.filter(tenant=self.tenant)
        suggestions = RuleSuggestionEngine.analyze_attack_patterns(events)
        
        # Should return at least one suggestion
        self.assertGreater(len(suggestions), 0)
        
        # Check suggestion structure
        suggestion = suggestions[0]
        self.assertIn('suggested_name', suggestion)
        self.assertIn('suggested_pattern', suggestion)
        self.assertIn('confidence_score', suggestion)
        self.assertIn('attack_count', suggestion)
    
    def test_find_common_substrings(self):
        """Test common substring extraction"""
        strings = [
            "SELECT * FROM users WHERE id=1",
            "SELECT * FROM users WHERE id=2",
            "SELECT * FROM users WHERE id=3",
            "SELECT password FROM users WHERE admin=1"
        ]
        
        common = RuleSuggestionEngine._find_common_substrings(strings, min_length=5)
        
        # Should find "SELECT" and "FROM users" as common patterns
        self.assertGreater(len(common), 0)
        
        # Check that common substrings appear multiple times
        for substring, count in common.items():
            self.assertGreaterEqual(count, 2)


class RuleOptimizerTest(TestCase):
    """Test RuleOptimizer class"""
    
    def test_calculate_confidence_perfect_rule(self):
        """Test confidence calculation for perfect rule"""
        # Perfect rule: 100 TP, 0 FP, 1000 TN, 0 FN
        metrics = RuleOptimizer.calculate_confidence(
            true_positives=100,
            false_positives=0,
            true_negatives=1000,
            false_negatives=0
        )
        
        self.assertEqual(metrics['precision'], 1.0)
        self.assertEqual(metrics['recall'], 1.0)
        self.assertEqual(metrics['f1_score'], 1.0)
        self.assertEqual(metrics['confidence_score'], 1.0)
    
    def test_calculate_confidence_with_false_positives(self):
        """Test confidence calculation with false positives"""
        # Rule with some false positives
        metrics = RuleOptimizer.calculate_confidence(
            true_positives=90,
            false_positives=10,
            true_negatives=900,
            false_negatives=5
        )
        
        # Precision = 90 / (90 + 10) = 0.9
        self.assertAlmostEqual(metrics['precision'], 0.9, places=2)
        
        # Recall = 90 / (90 + 5) = 0.947
        self.assertAlmostEqual(metrics['recall'], 0.947, places=2)
        
        # Confidence should be weighted toward precision
        self.assertGreater(metrics['confidence_score'], 0)
        self.assertLess(metrics['confidence_score'], 1.0)
    
    def test_calculate_confidence_no_detections(self):
        """Test confidence calculation with no detections"""
        metrics = RuleOptimizer.calculate_confidence(
            true_positives=0,
            false_positives=0,
            true_negatives=1000,
            false_negatives=10
        )
        
        # Should handle division by zero
        self.assertEqual(metrics['precision'], 0.0)
        self.assertEqual(metrics['recall'], 0.0)
        self.assertEqual(metrics['f1_score'], 0.0)
    
    def test_suggest_threshold_adjustment_high_fp(self):
        """Test threshold adjustment suggestion with high FP rate"""
        suggestion = RuleOptimizer.suggest_threshold_adjustment(
            confidence_score=0.7,
            false_positive_rate=0.15  # 15% FP rate
        )
        
        self.assertEqual(suggestion, "decrease_sensitivity")
    
    def test_suggest_threshold_adjustment_perfect_rule(self):
        """Test threshold adjustment for perfect rule"""
        suggestion = RuleOptimizer.suggest_threshold_adjustment(
            confidence_score=0.95,
            false_positive_rate=0.005  # 0.5% FP rate
        )
        
        self.assertEqual(suggestion, "increase_sensitivity")
    
    def test_suggest_threshold_adjustment_maintain(self):
        """Test threshold adjustment to maintain current"""
        suggestion = RuleOptimizer.suggest_threshold_adjustment(
            confidence_score=0.75,
            false_positive_rate=0.05  # 5% FP rate
        )
        
        self.assertEqual(suggestion, "maintain_current")
