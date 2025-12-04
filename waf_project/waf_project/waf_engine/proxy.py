"""
Reverse Proxy Module for WAF

This module handles forwarding allowed requests to the origin server
after they pass through WAF inspection.
"""

import requests
import logging
from django.http import HttpResponse, StreamingHttpResponse
from urllib.parse import urljoin, urlparse

logger = logging.getLogger('waf_engine')


def proxy_request(request, origin_url):
    """
    Forward the Django request to the origin server and return its response.
    
    Args:
        request: Django HttpRequest object
        origin_url: Base URL of the origin server (e.g., "https://app.example.com")
    
    Returns:
        HttpResponse or StreamingHttpResponse with the origin server's response
    """
    # Build the target URL
    target_url = build_target_url(origin_url, request)
    
    # Prepare headers to forward
    headers = prepare_headers(request)
    
    # Get request method and body
    method = request.method
    body = request.body if method in ['POST', 'PUT', 'PATCH'] else None
    
    logger.info(f"Proxying {method} {target_url} to origin server")
    
    try:
        # Make the request to origin server
        # allow_redirects=True: Follow redirects from origin (e.g., HTTP->HTTPS)
        # stream=True: Handle large responses efficiently
        response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=body,
            params=request.GET.dict(),
            allow_redirects=True,  # Follow redirects from origin
            stream=True,
            timeout=30  # 30 second timeout
        )
        
        # Return the response (Location headers and HTML content will be rewritten)
        return create_django_response(response, request, origin_url)
        
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while proxying to {target_url}")
        return HttpResponse(
            "<h1>504 Gateway Timeout</h1><p>The origin server did not respond in time.</p>",
            status=504
        )
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error while proxying to {target_url}")
        return HttpResponse(
            "<h1>502 Bad Gateway</h1><p>Could not connect to the origin server.</p>",
            status=502
        )
    except Exception as e:
        logger.error(f"Error proxying request: {str(e)}")
        return HttpResponse(
            "<h1>500 Internal Server Error</h1><p>An error occurred while processing your request.</p>",
            status=500
        )


def build_target_url(origin_url, request):
    """
    Build the complete target URL by combining origin_url with the request path.
    
    Args:
        origin_url: Base URL of origin (e.g., "https://app.example.com")
        request: Django HttpRequest
    
    Returns:
        Complete URL string
    """
    # Ensure origin_url doesn't end with /
    origin_url = origin_url.rstrip('/')
    
    # Get the full path including query string
    full_path = request.get_full_path()
    
    # Combine them
    target_url = origin_url + full_path
    
    return target_url


def prepare_headers(request):
    """
    Prepare headers to forward to the origin server.
    
    Args:
        request: Django HttpRequest
    
    Returns:
        Dictionary of headers
    """
    # Headers to exclude (these are hop-by-hop headers)
    excluded_headers = {
        'host',  # Will be set by requests library
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailers',
        'transfer-encoding',
        'upgrade',
        'content-length',  # Will be set automatically by requests
    }
    
    headers = {}
    
    # Copy headers from the original request
    for key, value in request.META.items():
        # Django prefixes HTTP headers with HTTP_
        if key.startswith('HTTP_'):
            # Remove HTTP_ prefix and convert to proper header format
            header_name = key[5:].replace('_', '-').title()
            
            # Skip excluded headers
            if header_name.lower() not in excluded_headers:
                headers[header_name] = value
        
        # Also include CONTENT_TYPE and CONTENT_LENGTH if present
        elif key == 'CONTENT_TYPE':
            headers['Content-Type'] = value
    
    # Add X-Forwarded headers for transparency
    headers['X-Forwarded-For'] = get_client_ip(request)
    headers['X-Forwarded-Proto'] = 'https' if request.is_secure() else 'http'
    headers['X-Forwarded-Host'] = request.get_host()
    
    # Add custom header to identify WAF
    headers['X-WAF-Protected'] = 'true'
    
    return headers


def get_client_ip(request):
    """
    Get the real client IP address, considering proxies.
    
    Args:
        request: Django HttpRequest
    
    Returns:
        IP address string
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP in the chain
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def create_django_response(requests_response, request=None, origin_url=None):
    """
    Convert a requests.Response object to a Django HttpResponse.
    
    Args:
        requests_response: requests.Response object
        request: Django HttpRequest (optional, needed for Location rewriting)
        origin_url: Origin URL (optional, needed for content rewriting)
    
    Returns:
        HttpResponse or StreamingHttpResponse
    """
    # Headers to exclude from the response
    excluded_response_headers = {
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailers',
        'transfer-encoding',
        'upgrade',
        'content-encoding',
        'content-length',
    }
    
    # Check if we should stream the response
    # Stream for large responses or specific content types
    content_type = requests_response.headers.get('Content-Type', '')
    should_stream = (
        'text/event-stream' in content_type or
        'application/octet-stream' in content_type or
        int(requests_response.headers.get('Content-Length', 0)) > 1024 * 1024  # > 1MB
    )
    
    # Check if we should rewrite HTML content
    should_rewrite_html = (
        not should_stream and
        request and
        origin_url and
        'text/html' in content_type
    )
    
    # Check if we should rewrite CSS/JS content
    should_rewrite_css_js = (
        not should_stream and
        request and
        origin_url and
        ('text/css' in content_type or 'javascript' in content_type)
    )
    
    if should_stream:
        # Create streaming response (no content rewriting for streams)
        response = StreamingHttpResponse(
            streaming_content=requests_response.iter_content(chunk_size=8192),
            status=requests_response.status_code
        )
    else:
        # Get content
        content = requests_response.content
        
        # Rewrite HTML content if needed
        if should_rewrite_html:
            try:
                content = rewrite_html_content(content, origin_url, request)
            except Exception as e:
                logger.warning(f"Failed to rewrite HTML content: {e}")
                # Continue with original content if rewriting fails
        
        # Rewrite CSS/JS content if needed
        elif should_rewrite_css_js:
            try:
                content = rewrite_css_js_content(content, origin_url, request)
            except Exception as e:
                logger.warning(f"Failed to rewrite CSS/JS content: {e}")
                # Continue with original content if rewriting fails
        
        # Create regular response
        response = HttpResponse(
            content=content,
            status=requests_response.status_code
        )
    
    # Copy headers from origin response
    for key, value in requests_response.headers.items():
        if key.lower() not in excluded_response_headers:
            # Rewrite Location header to preserve tenant URL
            if key.lower() == 'location' and request:
                value = rewrite_location_header(value, request)
            # Rewrite CSP header to allow resources from tenant domain
            elif key.lower() == 'content-security-policy' and request and origin_url:
                value = rewrite_csp_header(value, origin_url, request)
            response[key] = value
    
    return response


def rewrite_css_js_content(content, origin_url, request):
    """
    Rewrite CSS/JS content to replace origin domain with tenant domain.
    
    Args:
        content: CSS/JS content bytes
        origin_url: Origin URL (e.g., "http://www.tenupsoft.com")
        request: Django HttpRequest
    
    Returns:
        Rewritten content bytes
    """
    from urllib.parse import urlparse
    
    try:
        # Decode content
        text = content.decode('utf-8')
        
        # Get origin domain
        origin_parsed = urlparse(origin_url)
        origin_domain = origin_parsed.netloc
        
        # Get tenant domain
        tenant_host = request.get_host()
        tenant_scheme = 'https' if request.is_secure() else 'http'
        
        # Replace all occurrences of origin domain with tenant domain
        replacements = [
            (f'https://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'http://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'//{origin_domain}', f'//{tenant_host}'),
        ]
        
        # Handle www variations
        if origin_domain.startswith('www.'):
            base_domain = origin_domain[4:]
            replacements.extend([
                (f'https://{base_domain}', f'{tenant_scheme}://{tenant_host}'),
                (f'http://{base_domain}', f'{tenant_scheme}://{tenant_host}'),
                (f'//{base_domain}', f'//{tenant_host}'),
            ])
        else:
            www_domain = f'www.{origin_domain}'
            replacements.extend([
                (f'https://{www_domain}', f'{tenant_scheme}://{tenant_host}'),
                (f'http://{www_domain}', f'{tenant_scheme}://{tenant_host}'),
                (f'//{www_domain}', f'//{tenant_host}'),
            ])
        
        for old, new in replacements:
            text = text.replace(old, new)
        
        logger.info(f"Rewrote CSS/JS content: replaced {origin_domain} with {tenant_host}")
        
        return text.encode('utf-8')
        
    except UnicodeDecodeError:
        logger.warning("Failed to decode CSS/JS content as UTF-8")
        return content


def rewrite_csp_header(csp_value, origin_url, request):
    """
    Rewrite Content-Security-Policy header to allow resources from tenant domain.
    
    Args:
        csp_value: Original CSP header value
        origin_url: Origin URL
        request: Django HttpRequest
    
    Returns:
        Rewritten CSP header value
    """
    from urllib.parse import urlparse
    
    # Get origin domain
    origin_parsed = urlparse(origin_url)
    origin_domain = origin_parsed.netloc
    
    # Get tenant domain
    tenant_host = request.get_host()
    tenant_scheme = 'https' if request.is_secure() else 'http'
    
    # Replace origin domain with tenant domain in CSP
    csp_rewritten = csp_value
    
    replacements = [
        (f'https://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
        (f'http://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
    ]
    
    # Handle www variations
    if origin_domain.startswith('www.'):
        base_domain = origin_domain[4:]
        replacements.extend([
            (f'https://{base_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'http://{base_domain}', f'{tenant_scheme}://{tenant_host}'),
        ])
    else:
        www_domain = f'www.{origin_domain}'
        replacements.extend([
            (f'https://{www_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'http://{www_domain}', f'{tenant_scheme}://{tenant_host}'),
        ])
    
    for old, new in replacements:
        csp_rewritten = csp_rewritten.replace(old, new)
    
    logger.info(f"Rewrote CSP header")
    
    return csp_rewritten


def rewrite_html_content(content, origin_url, request):
    """
    Rewrite HTML content to replace origin domain with tenant domain.
    This prevents JavaScript redirects and meta refresh tags from changing the URL.
    
    Args:
        content: HTML content bytes
        origin_url: Origin URL (e.g., "http://www.tenupsoft.com")
        request: Django HttpRequest
    
    Returns:
        Rewritten content bytes
    """
    from urllib.parse import urlparse
    
    try:
        # Decode content
        html = content.decode('utf-8')
        
        # Get origin domain
        origin_parsed = urlparse(origin_url)
        origin_domain = origin_parsed.netloc
        origin_scheme = origin_parsed.scheme
        
        # Get tenant domain
        tenant_host = request.get_host()
        tenant_scheme = 'https' if request.is_secure() else 'http'
        
        # Replace all occurrences of origin domain with tenant domain
        # Handle both HTTP and HTTPS
        replacements = [
            (f'https://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'http://{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'https://www.{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'http://www.{origin_domain}', f'{tenant_scheme}://{tenant_host}'),
            (f'//{origin_domain}', f'//{tenant_host}'),  # Protocol-relative URLs
        ]
        
        for old, new in replacements:
            html = html.replace(old, new)
        
        # Also handle www prefix variations
        if origin_domain.startswith('www.'):
            base_domain = origin_domain[4:]
            html = html.replace(f'https://{base_domain}', f'{tenant_scheme}://{tenant_host}')
            html = html.replace(f'http://{base_domain}', f'{tenant_scheme}://{tenant_host}')
            html = html.replace(f'//{base_domain}', f'//{tenant_host}')
        else:
            www_domain = f'www.{origin_domain}'
            html = html.replace(f'https://{www_domain}', f'{tenant_scheme}://{tenant_host}')
            html = html.replace(f'http://{www_domain}', f'{tenant_scheme}://{tenant_host}')
            html = html.replace(f'//{www_domain}', f'//{tenant_host}')
        
        logger.info(f"Rewrote HTML content: replaced {origin_domain} with {tenant_host}")
        
        # Encode back to bytes
        return html.encode('utf-8')
        
    except UnicodeDecodeError:
        # If we can't decode as UTF-8, return original content
        logger.warning("Failed to decode HTML content as UTF-8")
        return content


def rewrite_location_header(location, request):
    """
    Rewrite Location header to use the tenant's domain instead of origin domain.
    
    Args:
        location: Original Location header value
        request: Django HttpRequest
    
    Returns:
        Rewritten Location header
    """
    from urllib.parse import urlparse, urlunparse
    
    # If it's a relative URL, keep it as is
    if not location.startswith(('http://', 'https://')):
        return location
    
    # Parse the location URL
    parsed = urlparse(location)
    
    # Get the tenant's host
    tenant_host = request.get_host()
    tenant_scheme = 'https' if request.is_secure() else 'http'
    
    # Rewrite to use tenant's domain
    rewritten = urlunparse((
        tenant_scheme,  # Use tenant's scheme
        tenant_host,    # Use tenant's host
        parsed.path,    # Keep original path
        parsed.params,  # Keep params
        parsed.query,   # Keep query
        parsed.fragment # Keep fragment
    ))
    
    logger.info(f"Rewrote Location header: {location} -> {rewritten}")
    return rewritten
