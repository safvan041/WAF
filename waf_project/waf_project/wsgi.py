"""
WSGI config for waf_project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

# waf_project/wsgi.py

import os
from django.core.wsgi import get_wsgi_application

# Corrected settings module path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf_project.settings')

application = get_wsgi_application()
