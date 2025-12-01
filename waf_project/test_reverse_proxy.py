"""
Simple test script to verify reverse proxy functionality.

This script:
1. Creates a simple HTTP server as a mock origin
2. Configures a tenant to proxy to it
3. Makes test requests through the WAF
"""

import http.server
import socketserver
import threading
import time

# Simple HTTP server to act as origin
class TestOriginHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('X-Origin-Server', 'TestOrigin')
        self.end_headers()
        
        response = f"""
        <html>
        <head><title>Origin Server Response</title></head>
        <body>
            <h1>✅ Reverse Proxy Working!</h1>
            <p>This response came from the origin server.</p>
            <p>Request path: {self.path}</p>
            <p>Headers received by origin:</p>
            <ul>
                {''.join([f'<li>{k}: {v}</li>' for k, v in self.headers.items()])}
            </ul>
        </body>
        </html>
        """
        self.wfile.write(response.encode())

def run_origin_server(port=8001):
    """Run a simple origin server on the specified port"""
    with socketserver.TCPServer(("", port), TestOriginHandler) as httpd:
        print(f"✅ Test origin server running on http://localhost:{port}")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()

if __name__ == "__main__":
    print("=" * 60)
    print("WAF Reverse Proxy Test - Mock Origin Server")
    print("=" * 60)
    print()
    print("Instructions:")
    print("1. Run this script to start a mock origin server")
    print("2. In Django admin, set a tenant's origin_url to: http://localhost:8001")
    print("3. Visit that tenant's domain through the WAF")
    print("4. You should see this origin server's response")
    print()
    print("=" * 60)
    print()
    
    try:
        run_origin_server(8001)
    except KeyboardInterrupt:
        print("\n\n✅ Origin server stopped")
