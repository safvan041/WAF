# waf_engine/middleware.py

import re
from django.shortcuts import render
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from waf_project.waf_engine.models import WAFRule

class WAFMiddleware(MiddlewareMixin):

    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.waf_rules = self.load_waf_rules()

    def load_waf_rules(self):
        """Loads all active WAF rules from the database."""
        # This can be cached for better performance in a production environment.
        return list(WAFRule.objects.filter(is_active=True))

    def process_request(self, request):
        """
        Processes an incoming request.
        """
        # We only apply the WAF logic to non-admin requests.
        # This prevents accidental blocking of the admin site itself.
        if not request.path.startswith('/admin/') and not request.path.startswith('/static/'):
            if self.check_request(request):
                return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your request has been blocked by the WAF.</p>")

        return None # Return None to continue to the next middleware

    def check_request(self, request):
        """Checks the request for patterns defined in the WAF rules."""
        # Check URL
        if self.match_pattern(request.path, 'URL'):
            return True

        # Check query parameters
        for key, value in request.GET.items():
            if self.match_pattern(value, f'Query Parameter: {key}'):
                return True

        # Check POST data
        if request.method == 'POST':
            # This is a basic check and can be expanded for different content types.
            try:
                # Check JSON body
                if 'application/json' in request.content_type:
                    import json
                    body = json.loads(request.body)
                    for key, value in body.items():
                        if self.match_pattern(value, f'JSON Body: {key}'):
                            return True
                # Check form data
                elif 'application/x-www-form-urlencoded' in request.content_type:
                    for key, value in request.POST.items():
                        if self.match_pattern(value, f'Form Data: {key}'):
                            return True
            except Exception as e:
                # Handle cases where the request body can't be parsed
                print(f"Error parsing request body: {e}")
                pass

        # Check headers
        for key, value in request.headers.items():
            if self.match_pattern(value, f'Header: {key}'):
                return True

        return False

    def match_pattern(self, data, source_field):
        """Matches data against all loaded WAF rules."""
        for rule in self.waf_rules:
            try:
                if re.search(rule.pattern, str(data), re.IGNORECASE):
                    # In a real WAF, you would also log this event to the database.
                    print(f"WAF Alert: Rule '{rule.name}' matched in {source_field} with data: {data}")
                    if rule.action == 'BLOCK':
                        return True
            except re.error as e:
                print(f"Regex error for rule '{rule.name}': {e}")
        return False