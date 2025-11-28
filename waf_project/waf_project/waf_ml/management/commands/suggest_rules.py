"""
Management command to analyze attack patterns and suggest new rules
"""

from datetime import timedelta
import re

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from waf_project.waf_core.models import Tenant, SecurityEvent
from waf_project.waf_ml.models import AdaptiveRule
from waf_project.waf_ml.ml_engine import RuleSuggestionEngine


class Command(BaseCommand):
    help = "Analyze attack patterns and suggest adaptive rules"

    def add_arguments(self, parser):
        parser.add_argument(
            "--tenant",
            type=str,
            help="Analyze patterns for specific tenant (by domain)",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Number of days of attack data to analyze (currently used only for info)",
        )
        parser.add_argument(
            "--auto-approve",
            action="store_true",
            help="Auto-approve high-confidence rules",
        )

    def handle(self, *args, **options):
        tenant_domain = options.get("tenant")
        days = options.get("days")
        auto_approve = options.get("auto_approve")

        if tenant_domain:
            # Analyze for specific tenant
            try:
                tenant = Tenant.objects.get(domain=tenant_domain)
                self.analyze_tenant_patterns(tenant, days, auto_approve)
            except Tenant.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Tenant not found: {tenant_domain}")
                )
        else:
            # Analyze for all active tenants
            tenants = Tenant.objects.filter(is_active=True)
            self.stdout.write(f"Analyzing patterns for {tenants.count()} tenants...")

            for tenant in tenants:
                self.analyze_tenant_patterns(tenant, days, auto_approve)

    def analyze_tenant_patterns(self, tenant, days, auto_approve):
        """Analyze attack patterns for a specific tenant"""
        self.stdout.write(f"\nAnalyzing patterns for tenant: {tenant.name}")

        # Minimum events required (configurable, default 1 for local/dev)
        min_blocked_events = getattr(settings, "WAF_ML_MIN_BLOCKED_EVENTS", 1)

        # NOTE: we intentionally do NOT filter by timestamp here for local testing.
        # In your own production setup you can re-enable a cutoff_date filter.
        security_events = (
            SecurityEvent.objects.filter(
                tenant=tenant,
                action_taken="block",
            )
            .select_related("rule")
            .order_by("-timestamp")
        )

        total_blocked = security_events.count()
        if total_blocked < min_blocked_events:
            self.stdout.write(
                self.style.WARNING(
                    f"Not enough attack data ({total_blocked}), "
                    f"need at least {min_blocked_events} blocked events"
                )
            )
            return

        self.stdout.write(f"Analyzing {total_blocked} blocked events...")

        # Primary: use the ML rule suggestion engine
        suggestions = RuleSuggestionEngine.analyze_attack_patterns(security_events)

        # If engine found nothing but we have enough blocked events, create a simple fallback rule
        if not suggestions:
            # Check if fallback rules are enabled
            if not getattr(settings, "WAF_ML_ENABLE_FALLBACK_RULES", False):
                self.stdout.write(self.style.WARNING("No patterns found (fallback rules disabled)"))
                return

            if total_blocked >= min_blocked_events:
                last_event = security_events.first()
                url = last_event.request_url or last_event.request_path or "/"

                # Very naive pattern extraction for demo purposes:
                #  - if UNION SELECT present, treat as SQLi pattern
                #  - otherwise, use first 20 chars of the URL path
                if "UNION" in url.upper() and "SELECT" in url.upper():
                    suggested_pattern = r"UNION\s+SELECT"
                    rule_type = "sql_injection"
                    suggested_name = "Fallback SQLi pattern (auto)"
                else:
                    path_only = url.split("?", 1)[0]
                    # Avoid creating rules for root path or very short paths
                    if path_only == "/" or len(path_only) < 4:
                        self.stdout.write(self.style.WARNING(f"Skipping fallback rule for path '{path_only}' - too broad/short"))
                        return

                    base = path_only[:20]
                    suggested_pattern = re.escape(base)
                    rule_type = "generic_block"
                    suggested_name = "Fallback generic pattern (auto)"

                adaptive_rule = AdaptiveRule.objects.create(
                    tenant=tenant,
                    suggested_name=suggested_name,
                    suggested_pattern=suggested_pattern,
                    rule_type=rule_type,
                    confidence_score=0.5,
                    supporting_events=[str(e.id) for e in security_events[:10]],
                    attack_count=total_blocked,
                    pattern_frequency=total_blocked,
                    status="pending",
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Fallback adaptive rule created: {adaptive_rule.suggested_name}"
                    )
                )
            else:
                self.stdout.write(self.style.WARNING("No patterns found"))
            return

        # Normal path: suggestions returned by RuleSuggestionEngine
        self.stdout.write(f"Found {len(suggestions)} potential rules:")

        auto_approve_threshold = getattr(
            settings, "WAF_ML_AUTO_APPROVE_THRESHOLD", 0.95
        )
        created_count = 0
        auto_approved_count = 0

        for suggestion in suggestions:
            # Check if similar rule already exists
            existing = AdaptiveRule.objects.filter(
                tenant=tenant,
                suggested_pattern=suggestion["suggested_pattern"],
                status__in=["pending", "approved", "auto_approved"],
            ).exists()

            if existing:
                self.stdout.write("  - Skipping duplicate pattern")
                continue

            # Create adaptive rule
            adaptive_rule = AdaptiveRule.objects.create(
                tenant=tenant,
                suggested_name=suggestion["suggested_name"],
                suggested_pattern=suggestion["suggested_pattern"],
                rule_type=suggestion["rule_type"],
                confidence_score=suggestion["confidence_score"],
                supporting_events=suggestion["supporting_events"],
                attack_count=suggestion["attack_count"],
                pattern_frequency=suggestion["pattern_frequency"],
                status="pending",
            )

            created_count += 1

            # Auto-approve if confidence is high enough and flag is set
            if auto_approve and suggestion["confidence_score"] >= auto_approve_threshold:
                adaptive_rule.approve(reviewed_by="auto_ml_system")
                auto_approved_count += 1
                status_icon = "✓"
                status_text = "AUTO-APPROVED"
            else:
                status_icon = "○"
                status_text = "PENDING"

            self.stdout.write(
                f'  {status_icon} {suggestion["suggested_name"]}\n'
                f'     Confidence: {suggestion["confidence_score"]:.2%}\n'
                f'     Attacks: {suggestion["attack_count"]}\n'
                f'     Status: {status_text}'
            )

        if created_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f"\n✓ Created {created_count} adaptive rule(s)")
            )
            if auto_approved_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Auto-approved {auto_approved_count} high-confidence rule(s)"
                    )
                )
        else:
            self.stdout.write(self.style.WARNING("No new rules created"))
