"""
Tests for IPReputationManager - IP reputation tracking and automatic blocking
"""
from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import Tenant, IPBlacklist
from waf_project.waf_security.ip_reputation import IPReputationManager
from waf_project.waf_security.models import IPReputationScore


class IPReputationManagerTestCase(TestCase):
    """Test cases for IP reputation tracking and auto-blocking"""
    
    def setUp(self):
        """Set up test tenant"""
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            domain="test.example.com",
            contact_email="admin@test.com",
            contact_name="Admin"
        )
        self.test_ip = "192.168.1.100"
    
    def test_record_violation_creates_reputation(self):
        """Test that recording a violation creates reputation record"""
        score, is_blocked = IPReputationManager.record_violation(
            self.tenant, self.test_ip, 'sql_injection'
        )
        
        # Check reputation was created
        reputation = IPReputationScore.objects.get(
            tenant=self.tenant,
            ip_address=self.test_ip
        )
        self.assertIsNotNone(reputation)
        self.assertEqual(reputation.sql_injection_attempts, 1)
        self.assertEqual(reputation.total_violations, 1)
    
    def test_violation_scoring(self):
        """Test that different violations have different scores"""
        # SQL injection should add 25 points
        score1, _ = IPReputationManager.record_violation(
            self.tenant, self.test_ip, 'sql_injection'
        )
        self.assertEqual(score1, 25)
        
        # XSS should add 20 points (total 45)
        score2, _ = IPReputationManager.record_violation(
            self.tenant, self.test_ip, 'xss'
        )
        self.assertEqual(score2, 45)
        
        # Rate limit should add 10 points (total 55)
        score3, _ = IPReputationManager.record_violation(
            self.tenant, self.test_ip, 'rate_limit'
        )
        self.assertEqual(score3, 55)
    
    def test_auto_blocking_at_threshold(self):
        """Test that IPs are auto-blocked when reaching threshold"""
        # Record violations to reach threshold (80)
        # SQL injection (25) + XSS (20) + SQL injection (25) + XSS (20) = 90
        IPReputationManager.record_violation(self.tenant, self.test_ip, 'sql_injection')
        IPReputationManager.record_violation(self.tenant, self.test_ip, 'xss')
        IPReputationManager.record_violation(self.tenant, self.test_ip, 'sql_injection')
        score, is_blocked = IPReputationManager.record_violation(
            self.tenant, self.test_ip, 'xss'
        )
        
        # Should be auto-blocked
        self.assertTrue(is_blocked, "IP should be auto-blocked at threshold")
        self.assertGreaterEqual(score, 80)
        
        # Check reputation record
        reputation = IPReputationScore.objects.get(
            tenant=self.tenant,
            ip_address=self.test_ip
        )
        self.assertTrue(reputation.is_blocked)
        self.assertTrue(reputation.auto_blocked)
        
        # Check blacklist entry was created
        blacklist_entry = IPBlacklist.objects.filter(
            tenant=self.tenant,
            ip_address=self.test_ip,
            auto_added=True
        ).exists()
        self.assertTrue(blacklist_entry, "IP should be added to blacklist")
    
    def test_check_reputation_clean_ip(self):
        """Test checking reputation for clean IP"""
        status = IPReputationManager.check_reputation(self.tenant, self.test_ip)
        
        self.assertEqual(status['score'], 0)
        self.assertFalse(status['is_blocked'])
        self.assertEqual(status['level'], 'excellent')
        self.assertFalse(status['should_block'])
    
    def test_check_reputation_malicious_ip(self):
        """Test checking reputation for malicious IP"""
        # Create malicious IP
        for i in range(4):
            IPReputationManager.record_violation(
                self.tenant, self.test_ip, 'sql_injection'
            )
        
        status = IPReputationManager.check_reputation(self.tenant, self.test_ip)
        
        self.assertGreater(status['score'], 0)
        self.assertTrue(status['is_blocked'])
        self.assertEqual(status['level'], 'malicious')
    
    def test_reputation_decay(self):
        """Test that reputation scores decay over time"""
        # Record violation
        IPReputationManager.record_violation(self.tenant, self.test_ip, 'sql_injection')
        
        reputation = IPReputationScore.objects.get(
            tenant=self.tenant,
            ip_address=self.test_ip
        )
        initial_score = reputation.reputation_score
        
        # Simulate time passage (25 hours)
        reputation.last_decay = timezone.now() - timedelta(hours=25)
        reputation.save()
        
        # Check reputation (triggers decay)
        status = IPReputationManager.check_reputation(self.tenant, self.test_ip)
        
        # Score should have decayed by 5 points (1 decay period)
        self.assertEqual(status['score'], initial_score - 5)
    
    def test_manual_block(self):
        """Test manually blocking an IP"""
        IPReputationManager.manual_block(
            self.tenant,
            self.test_ip,
            "Suspicious activity detected"
        )
        
        reputation = IPReputationScore.objects.get(
            tenant=self.tenant,
            ip_address=self.test_ip
        )
        
        self.assertTrue(reputation.is_blocked)
        self.assertFalse(reputation.auto_blocked)  # Manual block
        self.assertEqual(reputation.reputation_score, 100)
        self.assertIn("Manual block", reputation.block_reason)
    
    def test_unblock_ip(self):
        """Test unblocking an IP"""
        # Block IP first
        IPReputationManager.manual_block(self.tenant, self.test_ip, "Test")
        
        # Unblock
        IPReputationManager.unblock(self.tenant, self.test_ip)
        
        reputation = IPReputationScore.objects.get(
            tenant=self.tenant,
            ip_address=self.test_ip
        )
        
        self.assertFalse(reputation.is_blocked)
        self.assertEqual(reputation.reputation_score, 0)
    
    def test_tenant_isolation(self):
        """Test that reputation is isolated per tenant"""
        tenant2 = Tenant.objects.create(
            name="Test Tenant 2",
            domain="test2.example.com",
            contact_email="admin@test2.com",
            contact_name="Admin 2"
        )
        
        # Block IP for tenant1
        for i in range(4):
            IPReputationManager.record_violation(
                self.tenant, self.test_ip, 'sql_injection'
            )
        
        # Check tenant1 - should be blocked
        status1 = IPReputationManager.check_reputation(self.tenant, self.test_ip)
        self.assertTrue(status1['is_blocked'])
        
        # Check tenant2 - should be clean
        status2 = IPReputationManager.check_reputation(tenant2, self.test_ip)
        self.assertFalse(status2['is_blocked'])
        self.assertEqual(status2['score'], 0)
    
    def test_get_top_offenders(self):
        """Test getting top offending IPs"""
        # Create multiple IPs with different scores
        ips = [
            ("192.168.1.100", 3),  # 75 points
            ("192.168.1.101", 2),  # 50 points
            ("192.168.1.102", 1),  # 25 points
        ]
        
        for ip, violations in ips:
            for _ in range(violations):
                IPReputationManager.record_violation(
                    self.tenant, ip, 'sql_injection'
                )
        
        # Get top offenders
        top_offenders = IPReputationManager.get_top_offenders(self.tenant, limit=3)
        
        self.assertEqual(len(top_offenders), 3)
        # Should be ordered by score (highest first)
        self.assertEqual(top_offenders[0].ip_address, "192.168.1.100")
        self.assertEqual(top_offenders[1].ip_address, "192.168.1.101")
        self.assertEqual(top_offenders[2].ip_address, "192.168.1.102")
    
    def test_reputation_levels(self):
        """Test that reputation levels are correctly assigned"""
        test_cases = [
            (10, 'excellent'),   # 0-20
            (30, 'good'),        # 21-40
            (50, 'neutral'),     # 41-60
            (70, 'suspicious'),  # 61-80
            (90, 'malicious'),   # 81-100
        ]
        
        for score, expected_level in test_cases:
            # Create reputation with specific score
            reputation = IPReputationScore.objects.create(
                tenant=self.tenant,
                ip_address=f"192.168.1.{score}",
                reputation_score=score
            )
            
            self.assertEqual(
                reputation.reputation_level,
                expected_level,
                f"Score {score} should be level '{expected_level}'"
            )
