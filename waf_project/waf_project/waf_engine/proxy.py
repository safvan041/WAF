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
        # stream=True allows us to handle large responses efficiently
        response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=body,
            params=request.GET.dict(),
            allow_redirects=False,  # Let the client handle redirects
            stream=True,
            timeout=30  # 30 second timeout
        )
        
        # Return the response
        return create_django_response(response)
        
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


def create_django_response(requests_response):
    """
    Convert a requests.Response object to a Django HttpResponse.
    
    Args:
        requests_response: requests.Response object
    
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
    }
    
    # Check if we should stream the response
    # Stream for large responses or specific content types
    content_type = requests_response.headers.get('Content-Type', '')
    should_stream = (
        'text/event-stream' in content_type or
        'application/octet-stream' in content_type or
        int(requests_response.headers.get('Content-Length', 0)) > 1024 * 1024  # > 1MB
    )
    
    if should_stream:
        # Create streaming response
        response = StreamingHttpResponse(
            streaming_content=requests_response.iter_content(chunk_size=8192),
            status=requests_response.status_code
        )
    else:
        # Create regular response
        response = HttpResponse(
            content=requests_response.content,
            status=requests_response.status_code
        )
    
    # Copy headers from origin response
    for key, value in requests_response.headers.items():
        if key.lower() not in excluded_response_headers:
            response[key] = value
    
    return response
