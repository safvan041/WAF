"""
IP Reputation tracking and automatic blocking system.
Each tenant maintains independent IP reputation scores.
"""
import logging
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from waf_project.waf_core.models import Tenant, IPBlacklist
from .models import IPReputationScore

logger = logging.getLogger('waf_security')


class IPReputationManager:
    """
    Manages IP reputation scores and automatic blocking.
    Reputation scores increase with malicious behavior and decay over time.
    """
    
    # Reputation thresholds
    AUTO_BLOCK_THRESHOLD = getattr(settings, 'WAF_IP_REPUTATION_BLOCK_THRESHOLD', 80)
    DECAY_RATE = getattr(settings, 'WAF_IP_REPUTATION_DECAY_RATE', 5)  # Points per day
    DECAY_INTERVAL_HOURS = getattr(settings, 'WAF_IP_REPUTATION_DECAY_INTERVAL', 24)
    
    # Violation scores
    VIOLATION_SCORES = {
        'sql_injection': 25,
        'xss': 20,
        'rate_limit': 10,
        'bot_detection': 15,
        'geo_block_bypass': 30,
        'custom_rule': 15,
    }
    
    @classmethod
    def record_violation(cls, tenant, ip_address, violation_type, auto_block=True):
        """
        Record a security violation and update IP reputation.
        
        Args:
            tenant: Tenant object
            ip_address: Client IP address
            violation_type: Type of violation (sql_injection, xss, etc.)
            auto_block: Whether to automatically block if threshold exceeded
        
        Returns:
            tuple: (reputation_score, is_blocked)
        """
        # Get or create reputation record
        reputation, created = IPReputationScore.objects.get_or_create(
            tenant=tenant,
            ip_address=ip_address,
            defaults={'reputation_score': 0}
        )
        
        if created:
            logger.info(f"Created new reputation record for {ip_address} on tenant {tenant.name}")
        
        # Apply decay before adding new violation
        cls._apply_decay(reputation)
        
        # Get violation score
        score_increase = cls.VIOLATION_SCORES.get(violation_type, 10)
        
        # Update reputation score
        reputation.reputation_score = min(100, reputation.reputation_score + score_increase)
        reputation.total_violations += 1
        reputation.last_violation = timezone.now()
        
        # Update specific violation counters
        if violation_type == 'sql_injection':
            reputation.sql_injection_attempts += 1
        elif violation_type == 'xss':
            reputation.xss_attempts += 1
        elif violation_type == 'rate_limit':
            reputation.rate_limit_violations += 1
        elif violation_type == 'bot_detection':
            reputation.bot_detections += 1
        
        # Check if should be auto-blocked
        if auto_block and reputation.reputation_score >= cls.AUTO_BLOCK_THRESHOLD and not reputation.is_blocked:
            cls._auto_block_ip(reputation, violation_type)
        
        reputation.save()
        
        logger.info(
            f"Updated reputation for {ip_address} on tenant {tenant.name}: "
            f"score={reputation.reputation_score}, violations={reputation.total_violations}, "
            f"blocked={reputation.is_blocked}"
        )
        
        return reputation.reputation_score, reputation.is_blocked
    
    @classmethod
    def check_reputation(cls, tenant, ip_address):
        """
        Check IP reputation and return current status.
        
        Returns:
            dict: {
                'score': int,
                'is_blocked': bool,
                'level': str,
                'should_block': bool
            }
        """
        try:
            reputation = IPReputationScore.objects.get(
                tenant=tenant,
                ip_address=ip_address
            )
            
            # Apply decay
            cls._apply_decay(reputation)
            reputation.save()
            
            return {
                'score': reputation.reputation_score,
                'is_blocked': reputation.is_blocked,
                'level': reputation.reputation_level,
                'should_block': reputation.reputation_score >= cls.AUTO_BLOCK_THRESHOLD,
                'total_violations': reputation.total_violations,
            }
        except IPReputationScore.DoesNotExist:
            # No reputation record = clean IP
            return {
                'score': 0,
                'is_blocked': False,
                'level': 'excellent',
                'should_block': False,
                'total_violations': 0,
            }
    
    @classmethod
    def _apply_decay(cls, reputation):
        """Apply time-based decay to reputation score"""
        if not reputation.last_decay:
            reputation.last_decay = timezone.now()
            return
        
        hours_since_decay = (timezone.now() - reputation.last_decay).total_seconds() / 3600
        
        if hours_since_decay >= cls.DECAY_INTERVAL_HOURS:
            # Calculate decay periods
            decay_periods = int(hours_since_decay / cls.DECAY_INTERVAL_HOURS)
            total_decay = decay_periods * cls.DECAY_RATE
            
            # Apply decay
            reputation.reputation_score = max(0, reputation.reputation_score - total_decay)
            reputation.last_decay = timezone.now()
            
            logger.debug(
                f"Applied decay to {reputation.ip_address}: "
                f"periods={decay_periods}, decay={total_decay}, new_score={reputation.reputation_score}"
            )
            
            # If score dropped below threshold, consider unblocking
            if reputation.is_blocked and reputation.auto_blocked:
                if reputation.reputation_score < cls.AUTO_BLOCK_THRESHOLD - 20:  # Hysteresis
                    cls._auto_unblock_ip(reputation)
    
    @classmethod
    def _auto_block_ip(cls, reputation, reason):
        """Automatically block an IP based on reputation"""
        reputation.is_blocked = True
        reputation.auto_blocked = True
        reputation.blocked_at = timezone.now()
        reputation.block_reason = f"Automatic block due to reputation score {reputation.reputation_score} (threshold: {cls.AUTO_BLOCK_THRESHOLD}). Last violation: {reason}"
        
        # Also add to IPBlacklist for enforcement
        try:
            IPBlacklist.objects.get_or_create(
                tenant=reputation.tenant,
                ip_address=reputation.ip_address,
                defaults={
                    'reason': reputation.block_reason,
                    'auto_added': True,
                    'threat_score_threshold': reputation.reputation_score,
                    'is_active': True,
                }
            )
        except Exception as e:
            logger.error(f"Failed to add IP to blacklist: {e}")
        
        logger.warning(
            f"AUTO-BLOCKED IP {reputation.ip_address} for tenant {reputation.tenant.name}: "
            f"score={reputation.reputation_score}, reason={reason}"
        )
    
    @classmethod
    def _auto_unblock_ip(cls, reputation):
        """Automatically unblock an IP when reputation improves"""
        reputation.is_blocked = False
        reputation.auto_blocked = False
        
        # Remove from IPBlacklist if auto-added
        try:
            IPBlacklist.objects.filter(
                tenant=reputation.tenant,
                ip_address=reputation.ip_address,
                auto_added=True
            ).delete()
        except Exception as e:
            logger.error(f"Failed to remove IP from blacklist: {e}")
        
        logger.info(
            f"AUTO-UNBLOCKED IP {reputation.ip_address} for tenant {reputation.tenant.name}: "
            f"score={reputation.reputation_score}"
        )
    
    @classmethod
    def manual_block(cls, tenant, ip_address, reason, admin_user=None):
        """Manually block an IP (not subject to auto-unblock)"""
        reputation, created = IPReputationScore.objects.get_or_create(
            tenant=tenant,
            ip_address=ip_address,
            defaults={'reputation_score': 100}
        )
        
        reputation.is_blocked = True
        reputation.auto_blocked = False  # Manual block
        reputation.blocked_at = timezone.now()
        reputation.block_reason = f"Manual block: {reason}"
        reputation.reputation_score = 100
        reputation.save()
        
        logger.warning(
            f"MANUALLY BLOCKED IP {ip_address} for tenant {tenant.name}: {reason}"
        )
    
    @classmethod
    def unblock(cls, tenant, ip_address):
        """Manually unblock an IP"""
        try:
            reputation = IPReputationScore.objects.get(
                tenant=tenant,
                ip_address=ip_address
            )
            reputation.is_blocked = False
            reputation.auto_blocked = False
            reputation.reputation_score = 0  # Reset score
            reputation.save()
            
            # Remove from blacklist
            IPBlacklist.objects.filter(
                tenant=tenant,
                ip_address=ip_address
            ).delete()
            
            logger.info(f"UNBLOCKED IP {ip_address} for tenant {tenant.name}")
        except IPReputationScore.DoesNotExist:
            logger.warning(f"Attempted to unblock non-existent reputation record: {ip_address}")
    
    @classmethod
    def get_top_offenders(cls, tenant, limit=10):
        """Get top offending IPs for a tenant"""
        return IPReputationScore.objects.filter(
            tenant=tenant
        ).order_by('-reputation_score', '-total_violations')[:limit]
    
    @classmethod
    def cleanup_old_records(cls, days=90):
        """Clean up old reputation records with low scores"""
        cutoff_date = timezone.now() - timedelta(days=days)
        
        deleted_count = IPReputationScore.objects.filter(
            last_seen__lt=cutoff_date,
            reputation_score__lt=20,
            is_blocked=False
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old reputation records")
        return deleted_count
