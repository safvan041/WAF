from django.shortcuts import render
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import SecurityEvent, Tenant, WAFConfiguration
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

def home_view(request):
    return HttpResponse("Welcome to the WAF protected homepage!")


@login_required
def dashboard_view(request):
    """
    Displays the WAF security dashboard based on user's role.
    - Superuser: global stats across all tenants.
    - Tenant-bound user: stats for their specific tenant.
    """
    user = request.user
    context = {}

    # Check for a user role. If the role field doesn't exist, this will default to None.
    user_role = getattr(user, "role", None)

    # Superuser or Admin role (for global dashboard)
    if user.is_superuser or user_role == "admin":
        tenants = Tenant.objects.all()
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        
        # Optimized query for all events in the last 24 hours
        all_recent_events = SecurityEvent.objects.filter(timestamp__gte=twenty_four_hours_ago)
        
        # Aggregate stats globally
        total_events = all_recent_events.count()
        blocked_events = all_recent_events.filter(action_taken='block').count()
        recent_events_list = all_recent_events.order_by('-timestamp')[:10]
        
        # Get top attacking IPs globally
        top_ips = all_recent_events.values('source_ip').annotate(
            count=Count('source_ip')
        ).order_by('-count')[:5]

        # Use prefetching to optimize per-tenant stats
        tenants_with_stats = Tenant.objects.annotate(
            total_events_count=Count('security_events', filter=Q(security_events__timestamp__gte=twenty_four_hours_ago)),
            blocked_events_count=Count('security_events', filter=Q(security_events__timestamp__gte=twenty_four_hours_ago, security_events__action_taken='block'))
        ).order_by('-total_events_count')

        return render(request, 'waf_core/global_dashboard.html', {
            'tenants_with_stats': tenants_with_stats,
            'total_events': total_events,
            'blocked_events': blocked_events,
            'recent_events': recent_events_list,
            'top_ips_json': list(top_ips),
        })

    # Tenant-bound roles (tenant_admin, analyst)
    if user_role in ["tenant_admin", "analyst"] and getattr(user, "tenant", None):
        tenant = user.tenant
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)

        recent_events = SecurityEvent.objects.filter(
            tenant=tenant,
            timestamp__gte=twenty_four_hours_ago
        )
        total_events = recent_events.count()
        blocked_events = recent_events.filter(action_taken='block').count()
        recent_security_events_list = recent_events.order_by('-timestamp')[:10]
        top_ips = recent_events.values('source_ip').annotate(
            count=Count('source_ip')
        ).order_by('-count')[:5]

        return render(request, 'waf_core/dashboard.html', {
            'tenant': tenant,
            'total_events': total_events,
            'blocked_events': blocked_events,
            'recent_events': recent_security_events_list,
            'top_ips_json': list(top_ips),
        })

    # Fallback for all other cases
    return render(request, 'waf_core/error_dashboard.html', {
        'message': 'You don’t have access to the dashboard. Contact your admin.'
    })
