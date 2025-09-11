from django.shortcuts import render
from django.db.models import Count
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
    Displays the WAF security dashboard for an authenticated user.
    Role-based access:
    - Superuser / Admin role → global stats across tenants
    - Tenant Admin / Analyst → only their tenant stats
    - Others → error page
    """
    user = request.user

    # Case 1: Superuser or role == "admin" → global dashboard
    if user.is_superuser or getattr(user, "role", None) == "admin":
        tenants = Tenant.objects.all()
        total_events = SecurityEvent.objects.count()
        blocked_events = SecurityEvent.objects.filter(action_taken='block').count()
        recent_events = SecurityEvent.objects.order_by('-timestamp')[:10]

        # Precompute per-tenant stats
        tenants_stats = []
        for tenant in tenants:
            total = SecurityEvent.objects.filter(tenant=tenant).count()
            blocked = SecurityEvent.objects.filter(tenant=tenant, action_taken='block').count()
            tenants_stats.append({
                'tenant': tenant,
                'total_events': total,
                'blocked_events': blocked,
            })

        return render(request, 'waf_core/global_dashboard.html', {
            'tenants_stats': tenants_stats,
            'total_events': total_events,
            'blocked_events': blocked_events,
            'recent_events': recent_events,
        })

    # Case 2: Tenant-bound roles (tenant_admin, analyst)
    if getattr(user, "role", None) in ["tenant_admin", "analyst"] and getattr(user, "tenant", None):
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

    # Case 3: Fallback for users without role/tenant
    return render(request, 'waf_core/error_dashboard.html', {
        'message': 'You don’t have access to the dashboard. Contact your admin.'
    })
