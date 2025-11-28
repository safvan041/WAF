"""
Quick Demo Script for Testing ML Features

This script demonstrates the ML features by:
1. Generating legitimate traffic
2. Training an ML model
3. Testing anomaly detection
4. Generating attack patterns
5. Suggesting adaptive rules

Usage:
    python demo_ml_features.py --tenant yourdomain.com
"""

import requests
import time
import sys
import argparse
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

BASE_URL = "http://localhost:8000"

def print_step(step_num, description):
    """Print a step header"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Step {step_num}: {description}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

def print_success(message):
    """Print success message"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message"""
    print(f"{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

def generate_legitimate_traffic(count=150):
    """Generate legitimate traffic for training"""
    print_step(1, "Generating Legitimate Traffic")
    print_info(f"Sending {count} legitimate requests...")
    
    success_count = 0
    for i in range(1, count + 1):
        try:
            response = requests.get(f"{BASE_URL}/api/users", params={'page': i}, timeout=5)
            if response.status_code in [200, 404]:  # 404 is ok, endpoint might not exist
                success_count += 1
            
            if i % 25 == 0:
                print(f"  Progress: {i}/{count} requests sent")
            
            time.sleep(0.05)  # Small delay to avoid overwhelming server
        except Exception as e:
            print_error(f"Request {i} failed: {e}")
    
    print_success(f"Generated {success_count}/{count} legitimate requests")
    return success_count >= 100

def test_anomaly_detection():
    """Test anomaly detection with normal and malicious requests"""
    print_step(2, "Testing Anomaly Detection")
    
    # Test normal request
    print_info("Testing normal request...")
    try:
        response = requests.get(f"{BASE_URL}/api/users", params={'page': 1}, timeout=5)
        if response.status_code in [200, 404]:
            print_success("Normal request processed successfully")
        else:
            print_error(f"Unexpected status code: {response.status_code}")
    except Exception as e:
        print_error(f"Normal request failed: {e}")
    
    time.sleep(1)
    
    # Test SQL injection
    print_info("Testing SQL injection attack...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/users",
            params={'id': "1' UNION SELECT password FROM users--"},
            timeout=5
        )
        if response.status_code == 403:
            print_success("SQL injection blocked! (403 Forbidden)")
        elif response.status_code in [200, 404]:
            print_info("Request allowed (model may not be trained yet)")
        else:
            print_info(f"Status code: {response.status_code}")
    except Exception as e:
        print_error(f"Attack test failed: {e}")
    
    time.sleep(1)
    
    # Test XSS
    print_info("Testing XSS attack...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/search",
            params={'q': "<script>alert('XSS')</script>"},
            timeout=5
        )
        if response.status_code == 403:
            print_success("XSS attack blocked! (403 Forbidden)")
        elif response.status_code in [200, 404]:
            print_info("Request allowed (model may not be trained yet)")
        else:
            print_info(f"Status code: {response.status_code}")
    except Exception as e:
        print_error(f"XSS test failed: {e}")

def generate_attack_patterns(count=10):
    """Generate similar attack patterns for rule suggestion"""
    print_step(3, "Generating Attack Patterns")
    print_info(f"Sending {count} similar SQL injection attempts...")
    
    blocked_count = 0
    for i in range(1, count + 1):
        try:
            response = requests.get(
                f"{BASE_URL}/api/users",
                params={'id': f"{i} UNION SELECT password FROM users"},
                timeout=5
            )
            if response.status_code == 403:
                blocked_count += 1
            
            if i % 5 == 0:
                print(f"  Progress: {i}/{count} attacks sent ({blocked_count} blocked)")
            
            time.sleep(0.1)
        except Exception as e:
            print_error(f"Attack {i} failed: {e}")
    
    print_success(f"Sent {count} attack patterns ({blocked_count} blocked)")
    return blocked_count

def main():
    parser = argparse.ArgumentParser(description='Demo ML features for WAF')
    parser.add_argument('--tenant', type=str, default='test.com',
                      help='Tenant domain (default: test.com)')
    parser.add_argument('--skip-traffic', action='store_true',
                      help='Skip generating legitimate traffic')
    parser.add_argument('--skip-attacks', action='store_true',
                      help='Skip generating attack patterns')
    
    args = parser.parse_args()
    
    print(f"{Fore.MAGENTA}")
    print("="*60)
    print("  WAF ML Features Demo")
    print("="*60)
    print(f"{Style.RESET_ALL}")
    print(f"Tenant: {args.tenant}")
    print(f"Base URL: {BASE_URL}")
    print()
    
    # Check if server is running
    print_info("Checking if server is running...")
    try:
        response = requests.get(f"{BASE_URL}/health/", timeout=5)
        print_success("Server is running!")
    except Exception as e:
        print_error(f"Server is not running: {e}")
        print_info("Please start the server with: python manage.py runserver")
        sys.exit(1)
    
    # Generate legitimate traffic
    if not args.skip_traffic:
        if not generate_legitimate_traffic(150):
            print_error("Failed to generate enough legitimate traffic")
            print_info("You need at least 100 successful requests to train a model")
            sys.exit(1)
        
        print()
        print_info("Now train the model with:")
        print(f"  {Fore.CYAN}python manage.py train_ml_models --tenant {args.tenant}{Style.RESET_ALL}")
        print()
        input("Press Enter after training the model...")
    
    # Test anomaly detection
    test_anomaly_detection()
    
    # Generate attack patterns
    if not args.skip_attacks:
        blocked = generate_attack_patterns(10)
        
        if blocked > 0:
            print()
            print_info("Now suggest adaptive rules with:")
            print(f"  {Fore.CYAN}python manage.py suggest_rules --tenant {args.tenant}{Style.RESET_ALL}")
    
    # Summary
    print_step(4, "Demo Complete!")
    print_success("ML features demonstration completed")
    print()
    print("Next steps:")
    print("  1. Check Django admin for:")
    print("     - Anomaly Scores")
    print("     - ML Models")
    print("     - Adaptive Rules (if attacks were blocked)")
    print()
    print("  2. Test the API:")
    print(f"     curl {BASE_URL}/api/ml/insights/")
    print()
    print("  3. Review the LOCAL_TESTING_GUIDE.md for more details")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Demo interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
