"""
Simple health check view for container health monitoring.
"""
from django.http import JsonResponse
from django.db import connection
from django.core.cache import cache


def health_check(request):
    """
    Health check endpoint for load balancer and container orchestration.
    Returns 200 OK if the application is healthy.
    """
    health_status = {
        "status": "healthy",
        "database": "unknown",
        "cache": "unknown"
    }
    
    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        health_status["database"] = "connected"
    except Exception as e:
        health_status["database"] = f"error: {str(e)}"
        health_status["status"] = "unhealthy"
    
    # Check cache connection
    try:
        cache.set("health_check", "ok", 10)
        if cache.get("health_check") == "ok":
            health_status["cache"] = "connected"
        else:
            health_status["cache"] = "error"
    except Exception as e:
        health_status["cache"] = f"error: {str(e)}"
        # Cache is optional, don't mark as unhealthy
    
    status_code = 200 if health_status["status"] == "healthy" else 503
    return JsonResponse(health_status, status=status_code)
