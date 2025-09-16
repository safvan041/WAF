# waf_core/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect


urlpatterns = [

    path('', lambda request: redirect('login')),

    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Authentication
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='waf_core/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
]