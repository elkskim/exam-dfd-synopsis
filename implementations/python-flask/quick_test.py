"""Quick test to verify Python Flask implementations work"""
import requests
import json
import sys

def test_server(port, name):
    base_url = f"http://localhost:{port}"
    print(f"\n{'='*60}")
    print(f"Testing {name} (port {port})")
    print('='*60)
    
    # Test health
    try:
        response = requests.get(f"{base_url}/api/health", timeout=2)
        print(f"✅ Health check: {response.json()}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False
    
    # Test SQL injection attack
    print(f"\n🔴 Testing SQL Injection Attack:")
    payload = {"username": "admin' OR '1'='1'--", "password": "anything"}
    try:
        response = requests.post(f"{base_url}/api/login", json=payload, timeout=2)
        result = response.json()
        if result.get('success'):
            print(f"🚨 VULNERABLE - Auth bypass successful!")
            print(f"   Logged in as: {result['user']['username']}")
        else:
            print(f"✅ SECURE - Attack blocked")
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    # Test normal login
    print(f"\n🟢 Testing Normal Login:")
    payload = {"username": "alice", "password": "password123"}
    try:
        response = requests.post(f"{base_url}/api/login", json=payload, timeout=2)
        result = response.json()
        if result.get('success'):
            print(f"✅ Normal login successful for {result['user']['username']}")
        else:
            print(f"❌ Normal login failed")
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    return True

if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        name = "Vulnerable App" if port == 5001 else "Secure App"
        test_server(port, name)
    else:
        print("Usage: python quick_test.py <port>")
        print("Example: python quick_test.py 5001")

