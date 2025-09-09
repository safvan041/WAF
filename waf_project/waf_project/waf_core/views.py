# waf_core/views.py
from django.shortcuts import render
from django.http import HttpResponse

def home_view(request):
    return HttpResponse("Welcome to the WAF protected homepage!")