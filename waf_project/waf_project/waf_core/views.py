from django.shortcuts import render, redirect
from .forms import TenantRegistrationForm
from django.contrib.auth import login
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from waf_project.waf_core.models import SecurityEvent, Tenant, WAFConfiguration
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .models import User
import json
from django.core.paginator import Paginator

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
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    # Base query for events
    events = SecurityEvent.objects.filter(timestamp__gte=last_24h).select_related('rule')
    
    tenant = None
    if not user.is_superuser:
        if user.tenant:
            events = events.filter(tenant=user.tenant)
            tenant = user.tenant
        else:
            # Fallback for users without tenant
            events = SecurityEvent.objects.none()
    
    # Stats
    total_events = events.count()
    blocked_events = events.filter(action_taken='block').count()
    
    # Top IPs
    top_ips = events.values('source_ip').annotate(count=Count('id')).order_by('-count')[:10]
    top_ips_list = list(top_ips)
    top_ips_json = json.dumps(top_ips_list)
    
    # Pagination
    paginator = Paginator(events.order_by('-timestamp'), 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'tenant': tenant,
        'total_events': total_events,
        'blocked_events': blocked_events,
        'top_ips_json': top_ips_json,
        'recent_events': page_obj,
        'superuser_email': user.email if user.is_superuser else None,
    }
    
    return render(request, 'waf_core/dashboard.html', context)

def register(request):
    # If the user is already authenticated, redirect them to the dashboard
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = TenantRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            from django.contrib import messages
            messages.success(request, f"Welcome, {user.username}! Your account has been successfully created.")
            return redirect('dashboard')
    else:
        form = TenantRegistrationForm()
    return render(request, 'waf_core/register.html', {'form': form})

def rules_list(request):
    return render(request, 'waf_core/rules_list.html')