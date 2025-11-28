"""
WAF Machine Learning Engine

This module provides the core ML functionality for the adaptive WAF system:
- Traffic feature extraction
- Anomaly detection using Isolation Forest
- Rule suggestion based on attack pattern analysis
- Rule optimization and confidence scoring
"""

import re
import math
import hashlib
import logging
from collections import Counter
from datetime import timedelta
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs

import numpy as np
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger('waf_ml')


class FeatureExtractor:
    """Extract numerical features from HTTP requests for ML analysis"""
    
    @staticmethod
    def extract_features(request) -> Dict[str, float]:
        """
        Extract features from an HTTP request
        
        Returns a dictionary of numerical features suitable for ML models
        """
        features = {}
        
        # Request size features
        features['request_size'] = len(request.body) if hasattr(request, 'body') else 0
        features['path_length'] = len(request.path)
        features['query_string_length'] = len(request.META.get('QUERY_STRING', ''))
        
        # URL structure features
        path_parts = [p for p in request.path.split('/') if p]
        features['path_depth'] = len(path_parts)
        features['has_query_params'] = 1.0 if request.META.get('QUERY_STRING') else 0.0
        
        # Query parameter features
        query_params = parse_qs(request.META.get('QUERY_STRING', ''))
        features['param_count'] = len(query_params)
        features['max_param_length'] = max([len(str(v)) for v in query_params.values()], default=0)
        
        # Header features
        features['header_count'] = len(request.headers)
        features['user_agent_length'] = len(request.META.get('HTTP_USER_AGENT', ''))
        features['has_referer'] = 1.0 if request.META.get('HTTP_REFERER') else 0.0
        features['cookie_count'] = len(request.COOKIES)
        
        # Method encoding (one-hot)
        method = request.method.upper()
        features['method_get'] = 1.0 if method == 'GET' else 0.0
        features['method_post'] = 1.0 if method == 'POST' else 0.0
        features['method_put'] = 1.0 if method == 'PUT' else 0.0
        features['method_delete'] = 1.0 if method == 'DELETE' else 0.0
        features['method_other'] = 1.0 if method not in ['GET', 'POST', 'PUT', 'DELETE'] else 0.0
        
        # Content type features
        content_type = request.META.get('CONTENT_TYPE', '')
        features['is_json'] = 1.0 if 'json' in content_type.lower() else 0.0
        features['is_form'] = 1.0 if 'form' in content_type.lower() else 0.0
        features['is_multipart'] = 1.0 if 'multipart' in content_type.lower() else 0.0
        
        # Entropy features (measure randomness - high entropy can indicate attacks)
        features['path_entropy'] = FeatureExtractor._calculate_entropy(request.path)
        query_string = request.META.get('QUERY_STRING', '')
        features['query_entropy'] = FeatureExtractor._calculate_entropy(query_string)
        
        # Special character features (common in attacks)
        full_url = request.get_full_path()
        features['special_char_ratio'] = FeatureExtractor._special_char_ratio(full_url)
        features['has_sql_keywords'] = 1.0 if FeatureExtractor._has_sql_keywords(full_url) else 0.0
        features['has_script_tags'] = 1.0 if FeatureExtractor._has_script_tags(full_url) else 0.0
        
        # Numeric character features
        features['numeric_ratio'] = FeatureExtractor._numeric_ratio(full_url)
        features['uppercase_ratio'] = FeatureExtractor._uppercase_ratio(full_url)
        
        return features
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def _special_char_ratio(text: str) -> float:
        """Calculate ratio of special characters"""
        if not text:
            return 0.0
        
        special_chars = set('!@#$%^&*(){}[]|\\:;"\'<>?,./`~')
        special_count = sum(1 for c in text if c in special_chars)
        return special_count / len(text)
    
    @staticmethod
    def _numeric_ratio(text: str) -> float:
        """Calculate ratio of numeric characters"""
        if not text:
            return 0.0
        
        numeric_count = sum(1 for c in text if c.isdigit())
        return numeric_count / len(text)
    
    @staticmethod
    def _uppercase_ratio(text: str) -> float:
        """Calculate ratio of uppercase letters"""
        if not text:
            return 0.0
        
        alpha_chars = [c for c in text if c.isalpha()]
        if not alpha_chars:
            return 0.0
        
        uppercase_count = sum(1 for c in alpha_chars if c.isupper())
        return uppercase_count / len(alpha_chars)
    
    @staticmethod
    def _has_sql_keywords(text: str) -> bool:
        """Check if text contains SQL injection keywords"""
        sql_keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'create', 'alter', 'exec', 'execute', 'script', 'javascript',
            'onerror', 'onload', '--', '/*', '*/', 'xp_', 'sp_'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in sql_keywords)
    
    @staticmethod
    def _has_script_tags(text: str) -> bool:
        """Check if text contains script tags or XSS patterns"""
        xss_patterns = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onfocus=', 'onmouseover=', '<iframe', 'eval('
        ]
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in xss_patterns)
    
    @staticmethod
    def create_request_signature(request) -> str:
        """Create a unique signature for a request based on its characteristics"""
        signature_parts = [
            request.method,
            request.path,
            request.META.get('QUERY_STRING', ''),
            request.META.get('HTTP_USER_AGENT', '')[:50],  # First 50 chars
        ]
        signature_string = '|'.join(signature_parts)
        return hashlib.sha256(signature_string.encode()).hexdigest()


class AnomalyDetector:
    """
    Anomaly detection using Isolation Forest algorithm
    
    This class wraps scikit-learn's IsolationForest for detecting
    anomalous HTTP requests based on extracted features.
    """
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize the anomaly detector
        
        Args:
            contamination: Expected proportion of anomalies (0.1 = 10%)
            random_state: Random seed for reproducibility
        """
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=contamination,
                random_state=random_state,
                n_estimators=100,
                max_samples='auto'
            )
            self.is_trained = False
            self.feature_names = None
        except ImportError:
            logger.error("scikit-learn not installed. ML features will be disabled.")
            self.model = None
    
    def train(self, feature_list: List[Dict[str, float]]) -> Dict[str, float]:
        """
        Train the anomaly detector on normal traffic
        
        Args:
            feature_list: List of feature dictionaries from normal requests
            
        Returns:
            Dictionary with training metrics
        """
        if self.model is None:
            return {'error': 'scikit-learn not available'}
        
        if len(feature_list) < 10:
            return {'error': 'Insufficient training samples (need at least 10)'}
        
        # Convert feature dicts to numpy array
        self.feature_names = sorted(feature_list[0].keys())
        X = np.array([[f.get(name, 0.0) for name in self.feature_names] 
                      for f in feature_list])
        
        # Train the model
        import time
        start_time = time.time()
        self.model.fit(X)
        training_duration = time.time() - start_time
        
        self.is_trained = True
        
        # Calculate training metrics
        predictions = self.model.predict(X)
        anomaly_count = np.sum(predictions == -1)
        
        return {
            'training_samples': len(feature_list),
            'training_duration_seconds': training_duration,
            'detected_anomalies_in_training': int(anomaly_count),
            'anomaly_rate': float(anomaly_count / len(feature_list))
        }
    
    def predict(self, features: Dict[str, float]) -> Tuple[float, bool]:
        """
        Predict anomaly score for a request
        
        Args:
            features: Feature dictionary for the request
            
        Returns:
            Tuple of (anomaly_score, is_anomaly)
            - anomaly_score: 0.0 (normal) to 1.0 (highly anomalous)
            - is_anomaly: Boolean indicating if score exceeds threshold
        """
        if not self.model or not self.is_trained:
            return 0.0, False
        
        # Convert features to numpy array
        X = np.array([[features.get(name, 0.0) for name in self.feature_names]])
        
        # Get anomaly score (decision_function returns negative for anomalies)
        # We normalize to 0-1 range where higher = more anomalous
        decision_score = self.model.decision_function(X)[0]
        
        # Normalize score to 0-1 range (approximate)
        # Typical range is around -0.5 to 0.5, but can vary
        anomaly_score = max(0.0, min(1.0, (0.5 - decision_score) / 1.0))
        
        # Check against threshold
        threshold = getattr(settings, 'WAF_ML_ANOMALY_THRESHOLD', 0.7)
        is_anomaly = anomaly_score >= threshold
        
        return anomaly_score, is_anomaly
    
    def serialize(self) -> bytes:
        """Serialize the trained model to bytes"""
        if not self.model:
            return b''
        
        try:
            import joblib
            import io
            buffer = io.BytesIO()
            joblib.dump({
                'model': self.model,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }, buffer)
            return buffer.getvalue()
        except ImportError:
            logger.error("joblib not installed. Cannot serialize model.")
            return b''
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'AnomalyDetector':
        """Deserialize a trained model from bytes"""
        try:
            import joblib
            import io
            buffer = io.BytesIO(data)
            loaded = joblib.load(buffer)
            
            detector = cls()
            detector.model = loaded['model']
            detector.feature_names = loaded['feature_names']
            detector.is_trained = loaded['is_trained']
            
            return detector
        except ImportError:
            logger.error("joblib not installed. Cannot deserialize model.")
            return cls()


class RuleSuggestionEngine:
    """
    Analyzes attack patterns and suggests new firewall rules
    """
    
    @staticmethod
    def analyze_attack_patterns(security_events) -> List[Dict]:
        """
        Analyze security events to find common attack patterns
        
        Args:
            security_events: QuerySet of SecurityEvent objects
            
        Returns:
            List of suggested rules with confidence scores
        """
        suggestions = []
        
        # Group events by rule type
        events_by_type = {}
        for event in security_events:
            rule_type = event.rule.rule_type if event.rule else 'unknown'
            if rule_type not in events_by_type:
                events_by_type[rule_type] = []
            events_by_type[rule_type].append(event)
        
        # Analyze each type
        for rule_type, events in events_by_type.items():
            if len(events) < 5:  # Need at least 5 similar events
                continue
            
            # Extract common patterns from URLs
            patterns = RuleSuggestionEngine._extract_common_patterns(events)
            
            for pattern, count, event_ids in patterns:
                confidence = min(1.0, count / 20.0)  # Max confidence at 20 occurrences
                
                suggestions.append({
                    'suggested_name': f'Auto-detected {rule_type} pattern',
                    'suggested_pattern': pattern,
                    'rule_type': rule_type,
                    'confidence_score': confidence,
                    'attack_count': count,
                    'supporting_events': event_ids,
                    'pattern_frequency': count
                })
        
        return suggestions
    
    @staticmethod
    def _extract_common_patterns(events) -> List[Tuple[str, int, List[str]]]:
        """
        Extract common regex patterns from security events
        
        Returns:
            List of (pattern, count, event_ids) tuples
        """
        patterns = []
        
        # Extract URLs from events
        urls = [(event.request_url, str(event.id)) for event in events]
        
        # Find common substrings
        url_texts = [url for url, _ in urls]
        common_substrings = RuleSuggestionEngine._find_common_substrings(url_texts)
        
        for substring, count in common_substrings.items():
            if count >= 5 and len(substring) >= 5:  # At least 5 occurrences and 5 chars
                # Convert to regex pattern (escape special chars)
                pattern = re.escape(substring)
                
                # Get event IDs that match this pattern
                event_ids = [event_id for url, event_id in urls if substring in url]
                
                patterns.append((pattern, count, event_ids))
        
        # Sort by count (most common first)
        patterns.sort(key=lambda x: x[1], reverse=True)
        
        return patterns[:10]  # Return top 10 patterns
    
    @staticmethod
    def _find_common_substrings(strings: List[str], min_length=5) -> Dict[str, int]:
        """Find common substrings across multiple strings"""
        substring_counts = Counter()
        
        for string in strings:
            # Extract all substrings of minimum length
            seen_in_this_string = set()
            for i in range(len(string) - min_length + 1):
                for j in range(i + min_length, len(string) + 1):
                    substring = string[i:j]
                    if substring not in seen_in_this_string:
                        substring_counts[substring] += 1
                        seen_in_this_string.add(substring)
        
        # Filter to only substrings that appear in multiple strings
        return {k: v for k, v in substring_counts.items() if v >= 2}


class RuleOptimizer:
    """
    Optimizes firewall rules based on performance metrics
    """
    
    @staticmethod
    def calculate_confidence(true_positives: int, false_positives: int,
                           true_negatives: int, false_negatives: int) -> Dict[str, float]:
        """
        Calculate rule confidence metrics
        
        Returns:
            Dictionary with precision, recall, f1_score, and confidence_score
        """
        tp = true_positives
        fp = false_positives
        tn = true_negatives
        fn = false_negatives
        
        # Precision: TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        
        # Recall: TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Confidence score (weighted toward precision to minimize false positives)
        confidence_score = (0.6 * precision) + (0.4 * recall)
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'confidence_score': confidence_score
        }
    
    @staticmethod
    def suggest_threshold_adjustment(confidence_score: float, false_positive_rate: float) -> str:
        """
        Suggest threshold adjustments based on performance
        
        Returns:
            Recommendation string
        """
        if false_positive_rate > 0.1:  # More than 10% false positives
            return "decrease_sensitivity"
        elif confidence_score > 0.9 and false_positive_rate < 0.01:
            return "increase_sensitivity"
        else:
            return "maintain_current"
