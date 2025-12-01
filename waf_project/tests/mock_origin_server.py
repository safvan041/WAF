"""
Mock Origin Server for Testing Reverse Proxy

This script creates a simple HTTP server that acts as an origin server
for testing the WAF's reverse proxy functionality.

Usage:
    python -m tests.mock_origin_server

The server will run on http://localhost:8001
"""

import http.server
import socketserver
import json
from datetime import datetime


class MockOriginHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for mock origin server requests"""
    
    def log_message(self, format, *args):
        """Custom logging"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Origin-Server', 'MockOrigin')
        self.send_header('X-Request-Path', self.path)
        self.end_headers()
        
        response = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Mock Origin Server</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .success {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .info {{
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
            padding: 15px;
            border-radius: 5px;
        }}
        h1 {{ color: #28a745; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ padding: 5px 0; border-bottom: 1px solid #ddd; }}
        code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="success">
        <h1>✅ Reverse Proxy Working!</h1>
        <p>This response came from the <strong>mock origin server</strong>.</p>
    </div>
    
    <div class="info">
        <h2>Request Details</h2>
        <p><strong>Path:</strong> <code>{self.path}</code></p>
        <p><strong>Method:</strong> <code>{self.command}</code></p>
        <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h3>Headers Received by Origin:</h3>
        <ul>
            {''.join([f'<li><strong>{k}:</strong> {v}</li>' for k, v in self.headers.items()])}
        </ul>
    </div>
</body>
</html>
        """
        self.wfile.write(response.encode('utf-8'))
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Origin-Server', 'MockOrigin')
        self.end_headers()
        
        response = {
            'status': 'success',
            'message': 'POST request received by origin server',
            'path': self.path,
            'data_received': post_data,
            'timestamp': datetime.now().isoformat()
        }
        
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))


def run_mock_origin(port=8001):
    """Run the mock origin server"""
    handler = MockOriginHandler
    
    with socketserver.TCPServer(("", port), handler) as httpd:
        print("=" * 70)
        print("🚀 Mock Origin Server Started")
        print("=" * 70)
        print(f"\n📍 Server running at: http://localhost:{port}")
        print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n📝 Instructions:")
        print("   1. Configure a tenant's origin_url to: http://localhost:8001")
        print("   2. Make requests through the WAF to that tenant's domain")
        print("   3. You should see this origin server's response")
        print("\n⚠️  Press Ctrl+C to stop the server")
        print("=" * 70)
        print()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n✅ Mock origin server stopped")


if __name__ == "__main__":
    run_mock_origin(8001)
