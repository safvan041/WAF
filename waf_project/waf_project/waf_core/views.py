from django.shortcuts import render, redirect, get_object_or_404
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
    """
    Onboarding view: creates Tenant + initial User.

    EXPECTATION:
    - TenantRegistrationForm must expose origin_url and waf_host.
    - We then ensure those are saved onto the Tenant instance.
    """
    # If the user is already authenticated, redirect them to the dashboard
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = TenantRegistrationForm(request.POST)
        if form.is_valid():
            # form.save() should create the user (and tenant)
            user = form.save()

            # Make sure origin_url and waf_host are set on the tenant
            tenant = getattr(user, 'tenant', None)
            if tenant is not None:
                origin_url = form.cleaned_data.get('origin_url')
                waf_host = form.cleaned_data.get('waf_host')

                if origin_url:
                    tenant.origin_url = origin_url
                if waf_host:
                    tenant.waf_host = waf_host

                tenant.save()

            login(request, user)
            from django.contrib import messages
            messages.success(request, f"Welcome, {user.username}! Your account has been successfully created.")
            return redirect('dashboard')
    else:
        form = TenantRegistrationForm()
    return render(request, 'waf_core/register.html', {'form': form})


@login_required
def tenant_detail_view(request, tenant_id=None):
    """
    Tenant detail page:
    - Superuser can view any tenant by ID.
    - Normal user only sees their own tenant.
    Shows origin_url and waf_host so you can verify routing.
    """
    user = request.user

    if user.is_superuser and tenant_id is not None:
        tenant = get_object_or_404(Tenant, id=tenant_id)
    else:
        # Non-superuser must be bound to a tenant
        if not getattr(user, 'tenant', None):
            return HttpResponse("No tenant associated with this user.", status=400)
        tenant = user.tenant

    context = {
        'tenant': tenant,
        'origin_url': tenant.origin_url,
        'waf_host': tenant.waf_host,
    }
    return render(request, 'waf_core/tenant_detail.html', context)


def rules_list(request):
    return render(request, 'waf_core/rules_list.html')


@login_required
def tenant_detail_view(request, tenant_id=None):
    """
    Tenant detail page:
    - Superuser can view any tenant by ID.
    - Normal user only sees their own tenant.
    Shows origin_url and waf_host so you can verify routing.
    """
    user = request.user

    if user.is_superuser and tenant_id is not None:
        tenant = get_object_or_404(Tenant, id=tenant_id)
    else:
        if not getattr(user, "tenant", None):
            return HttpResponse("No tenant associated with this user.", status=400)
        tenant = user.tenant

    context = {
        "tenant": tenant,
        "origin_url": tenant.origin_url,
        "waf_host": tenant.waf_host,
    }
    return render(request, "waf_core/tenant_detail.html", context)


@login_required
def verify_domain(request, tenant_id):
    """
    Trigger DNS verification for a tenant.
    """
    tenant = get_object_or_404(Tenant, id=tenant_id)
    
    # Ensure user has permission
    if not request.user.is_superuser and request.user.tenant != tenant:
        return HttpResponse("Unauthorized", status=403)
        
    from waf_project.waf_engine.verification import DomainVerifier
    from django.contrib import messages
    
    if DomainVerifier.verify_dns_record(tenant.domain, str(tenant.verification_token)):
        tenant.domain_verified = True
        tenant.save()
        messages.success(request, f"Domain {tenant.domain} verified successfully!")
    else:
        messages.error(request, f"Verification failed. Could not find TXT record for {tenant.domain}.")
        
    # If user is superuser viewing specific tenant, keep them there.
    # Otherwise redirect to generic tenant detail.
    if request.user.is_superuser:
         return redirect('tenant_detail_admin', tenant_id=tenant.id)
    return redirect('tenant_detail')