from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.db import transaction
from .models import User, Tenant

class TenantRegistrationForm(UserCreationForm):
    name = forms.CharField(label='Organization Name', max_length=200)
    domain = forms.CharField(label='Protected Domain', max_length=255)
    contact_email = forms.EmailField(label='Contact Email')

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('name', 'domain', 'contact_email')

    @transaction.atomic
    def save(self, commit=True):
        # Create the user first
        user = super().save(commit=False)
        
        # Create the tenant and link it to the user
        tenant = Tenant.objects.create(
            name=self.cleaned_data['name'],
            domain=self.cleaned_data['domain'],
            contact_email=self.cleaned_data['contact_email'],
            contact_name=user.username,
        )
        user.tenant = tenant
        user.save()
        return user