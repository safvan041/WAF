from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.db import transaction
from .models import User, Tenant

class TenantRegistrationForm(UserCreationForm):
    name = forms.CharField(label='Organization Name', max_length=200)
    domain = forms.CharField(label='Protected Domain', max_length=255)
    contact_email = forms.EmailField(label='Contact Email')
    
    # New reverse proxy fields
    origin_url = forms.URLField(
        label='Origin Server URL',
        required=False,
        help_text='Backend URL to forward allowed traffic (e.g., https://app.yoursite.com)',
        widget=forms.URLInput(attrs={'placeholder': 'https://app.yoursite.com'})
    )
    waf_host = forms.CharField(
        label='WAF Subdomain',
        required=False,
        max_length=255,
        help_text='Subdomain on the WAF (e.g., yourcompany.waf-app.site)',
        widget=forms.TextInput(attrs={'placeholder': 'yourcompany.waf-app.site'})
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('name', 'domain', 'contact_email', 'origin_url', 'waf_host')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    @transaction.atomic
    def save(self, commit=True):
        # Create the user first
        user = super().save(commit=False)
        user.role = 'user'  # Set default role to 'user' (pending approval)
        
        # Create the tenant and link it to the user
        tenant = Tenant.objects.create(
            name=self.cleaned_data['name'],
            domain=self.cleaned_data['domain'],
            contact_email=self.cleaned_data['contact_email'],
            contact_name=user.username,
            origin_url=self.cleaned_data.get('origin_url', ''),
            waf_host=self.cleaned_data.get('waf_host', ''),
        )
        user.tenant = tenant
        user.save()
        return user
    
    def clean_waf_host(self):
        """Validate that waf_host is unique if provided"""
        waf_host = self.cleaned_data.get('waf_host')
        if waf_host:
            # Check if waf_host already exists
            if Tenant.objects.filter(waf_host=waf_host).exists():
                raise forms.ValidationError('This WAF subdomain is already taken. Please choose another.')
        return waf_host
    
    def clean(self):
        """Additional validation for origin_url and waf_host"""
        cleaned_data = super().clean()
        origin_url = cleaned_data.get('origin_url')
        waf_host = cleaned_data.get('waf_host')
        
        # If origin_url is provided, waf_host should also be provided
        if origin_url and not waf_host:
            raise forms.ValidationError(
                'If you provide an Origin Server URL, you must also specify a WAF Subdomain.'
            )
        
        return cleaned_data
